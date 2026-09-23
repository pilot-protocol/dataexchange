// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_dataexchange
// +build !no_dataexchange

package dataexchange

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Inbox capacity accounting.
//
// Two caps bound the inbox: a file count (InboxMaxFiles) and a byte total
// (InboxMaxBytes, 256 MiB by default). Oldest messages are evicted first.
//
// The byte cap is enforced before every write without listing the
// directory: the service keeps a running total, seeded by one scan and
// reconciled by the periodic eviction pass. Other processes also delete
// inbox files (`pilotctl inbox --clear`, retention sweeps), so the running
// total can only drift upward between scans; the directory is re-read before
// anything is evicted, and eviction decisions always come from that fresh
// scan, never from the running total alone.
//
// When the byte cap forces an eviction, the oldest files are removed until
// the inbox plus the incoming message fits in inboxLowWaterPercent of the
// cap, so one eviction pass makes room for many following messages instead
// of running again on every write.
//
// A write is in flight from its reservation until inboxWriteDone. Its bytes
// are counted in pending the whole time, but its file can already be on
// disk, fully or partly written, when another writer rescans. Rescans
// therefore leave in-flight files out: their bytes are not added to onDisk
// a second time, and eviction never deletes a message that has been
// admitted and is about to be acknowledged.

// inboxLowWaterPercent is the fill level, as a percentage of the byte cap,
// that a byte-cap eviction trims the inbox down to.
const inboxLowWaterPercent = 90

// defaultInboxMaxFiles is the file-count cap when InboxMaxFiles is not set.
const defaultInboxMaxFiles = 10000

// inboxBudget is the running byte total for the inbox directory.
type inboxBudget struct {
	mu  sync.Mutex
	dir string
	// known is false until the first scan of dir.
	known bool
	// onDisk is the byte total of the settled inbox files (all but the
	// in-flight ones) as of the last scan, plus files this service wrote
	// since, minus files it removed since.
	onDisk int64
	// pending is bytes admitted for writes that have not finished yet.
	pending int64
	// inflight holds the destination path of every write counted in
	// pending. rescanLocked skips these files.
	inflight map[string]struct{}
	// scans counts directory listings, so tests can check that the byte cap
	// is not paid for with a full scan per message.
	scans int
}

// inboxFile is one regular file in the inbox directory.
type inboxFile struct {
	name string
	mod  time.Time
	size int64
}

// scanInbox lists the regular files in dir (subdirectories hold no inbox
// messages and are skipped) with their total size.
func scanInbox(dir string) ([]inboxFile, int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	files := make([]inboxFile, 0, len(entries))
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, inboxFile{name: e.Name(), mod: info.ModTime(), size: info.Size()})
		total += info.Size()
	}
	return files, total, nil
}

// inboxLowWater returns the byte level a byte-cap eviction trims to:
// inboxLowWaterPercent of maxBytes, rounded down, without overflowing.
func inboxLowWater(maxBytes int64) int64 {
	return maxBytes/100*inboxLowWaterPercent + maxBytes%100*inboxLowWaterPercent/100
}

// removeOldestInbox deletes files from dir, oldest first, until total is at
// or below limit. files must be the result of a fresh scan. It returns the
// new total and the number of files removed; files that cannot be removed
// are skipped and still counted.
func removeOldestInbox(dir string, files []inboxFile, total, limit int64) (int64, int) {
	if total <= limit {
		return total, 0
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
	evicted := 0
	for i := 0; i < len(files) && total > limit; i++ {
		if err := os.Remove(filepath.Join(dir, files[i].name)); err != nil {
			continue
		}
		total -= files[i].size
		evicted++
	}
	return total, evicted
}

// rescanLocked re-reads dir and resets the running total. Files of writes
// still in flight are left out of both the returned list and the total:
// their bytes are already in pending, and they must not be evicted. b.mu
// must be held.
func (b *inboxBudget) rescanLocked(dir string) ([]inboxFile, error) {
	b.scans++
	files, total, err := scanInbox(dir)
	if err != nil {
		return nil, err
	}
	if len(b.inflight) > 0 {
		settled := files[:0]
		for _, f := range files {
			if _, busy := b.inflight[filepath.Join(dir, f.name)]; busy {
				total -= f.size
				continue
			}
			settled = append(settled, f)
		}
		files = settled
	}
	b.dir, b.known, b.onDisk = dir, true, total
	return files, nil
}

// admitLocked records a reservation of size bytes for the file at path.
// b.mu must be held.
func (b *inboxBudget) admitLocked(path string, size int64) {
	b.pending += size
	if b.inflight == nil {
		b.inflight = make(map[string]struct{})
	}
	b.inflight[path] = struct{}{}
}

// reserveInbox admits a message of size bytes, to be written to path inside
// dir, under the byte cap maxBytes (> 0), evicting the oldest messages when
// needed. On success the caller must report the write's outcome with
// inboxWriteDone(path, ...).
func (s *Service) reserveInbox(dir, path string, size, maxBytes int64) error {
	b := &s.inbox
	b.mu.Lock()
	defer b.mu.Unlock()
	if size > maxBytes {
		return fmt.Errorf("inbox byte budget exceeded: a %d-byte message is larger than the %d-byte cap", size, maxBytes)
	}
	if size+b.pending > maxBytes {
		// Even an empty inbox could not hold this message next to the writes
		// already in progress; evicting would destroy messages for nothing.
		return fmt.Errorf("inbox byte budget exceeded: %d bytes being written + %d > %d", b.pending, size, maxBytes)
	}
	if !b.known || b.dir != dir {
		if _, err := b.rescanLocked(dir); err != nil {
			// Best-effort, as before: an unlistable inbox does not block
			// delivery; the write itself reports any real I/O problem.
			slog.Warn("inbox byte budget: cannot list inbox; admitting message unchecked", "dir", dir, "err", err)
			b.admitLocked(path, size)
			return nil
		}
	}
	if b.onDisk+b.pending+size > maxBytes {
		// The running total may be stale (files deleted by other processes),
		// so decide from a fresh listing.
		files, err := b.rescanLocked(dir)
		if err != nil {
			slog.Warn("inbox byte budget: cannot list inbox; admitting message unchecked", "dir", dir, "err", err)
			b.admitLocked(path, size)
			return nil
		}
		if b.onDisk+b.pending+size > maxBytes {
			target := inboxLowWater(maxBytes)
			if size+b.pending > target {
				target = maxBytes
			}
			before := b.onDisk
			var evicted int
			b.onDisk, evicted = removeOldestInbox(dir, files, b.onDisk, target-size-b.pending)
			slog.Info("inbox eviction (bytes)", "dir", dir, "evicted", evicted,
				"bytes_before", before, "bytes_after", b.onDisk, "max_bytes", maxBytes)
		}
		if b.onDisk+b.pending+size > maxBytes {
			return fmt.Errorf("inbox byte budget exceeded: %d + %d > %d", b.onDisk+b.pending, size, maxBytes)
		}
	}
	b.admitLocked(path, size)
	return nil
}

// inboxWriteDone settles the reservation reserveInbox made for path. From
// then on the file counts in onDisk (if it was written) and can be evicted.
func (s *Service) inboxWriteDone(path string, size int64, written bool) {
	b := &s.inbox
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.inflight, path)
	b.pending -= size
	if b.pending < 0 {
		b.pending = 0
	}
	if written {
		b.onDisk += size
	}
}

// inboxFileRemoved accounts for this service deleting an inbox file it wrote.
func (s *Service) inboxFileRemoved(size int64) {
	b := &s.inbox
	b.mu.Lock()
	defer b.mu.Unlock()
	b.onDisk -= size
	if b.onDisk < 0 {
		b.onDisk = 0
	}
}

// evictInboxOverflow enforces both inbox caps from a fresh listing: the file
// count (InboxMaxFiles, default 10000) and the byte total
// (effectiveInboxMaxBytes, trimmed to the low-water mark when exceeded). It
// also re-seeds the running byte total. Files of writes still in flight are
// never evicted (see rescanLocked). Best-effort: I/O errors are logged and
// skipped. Called periodically from saveInboxMessage.
func (s *Service) evictInboxOverflow(dir string) {
	b := &s.inbox
	b.mu.Lock()
	defer b.mu.Unlock()
	files, err := b.rescanLocked(dir)
	if err != nil {
		slog.Debug("inbox evict: readdir", "dir", dir, "err", err)
		return
	}
	maxFiles := s.cfg.InboxMaxFiles
	if maxFiles <= 0 {
		maxFiles = defaultInboxMaxFiles
	}
	if len(files) > maxFiles {
		// Oldest first.
		sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
		toEvict := len(files) - maxFiles
		evicted := 0
		for i := 0; i < toEvict; i++ {
			if err := os.Remove(filepath.Join(dir, files[i].name)); err != nil {
				continue
			}
			b.onDisk -= files[i].size
			evicted++
		}
		files = files[toEvict:]
		slog.Info("inbox eviction", "dir", dir, "evicted", evicted, "remaining", len(files))
	}
	if maxBytes := s.effectiveInboxMaxBytes(); maxBytes > 0 && b.onDisk+b.pending > maxBytes {
		// Writes still in flight were admitted under the cap and are not
		// candidates, so trim the settled files until they fit next to them:
		// down to the low-water mark, or to the cap when the in-flight
		// writes alone are above the low-water mark (as in reserveInbox).
		target := inboxLowWater(maxBytes)
		if b.pending > target {
			target = maxBytes
		}
		before := b.onDisk
		var evicted int
		b.onDisk, evicted = removeOldestInbox(dir, files, b.onDisk, target-b.pending)
		slog.Info("inbox eviction (bytes)", "dir", dir, "evicted", evicted,
			"bytes_before", before, "bytes_after", b.onDisk, "max_bytes", maxBytes)
	}
}

// inboxTotalBytes sums the on-disk size of all regular files in dir.
func inboxTotalBytes(dir string) (int64, error) {
	_, total, err := scanInbox(dir)
	return total, err
}
