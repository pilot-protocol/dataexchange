// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_dataexchange
// +build !no_dataexchange

package dataexchange

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// seedSparseInbox writes n files of size bytes each into dir with mtimes an
// hour or more in the past (oldest first). The files are sparse, so a test
// can exceed the 256 MiB default cap without using real disk space.
func seedSparseInbox(t *testing.T, dir string, n int, size int64) {
	t.Helper()
	base := time.Now().Add(-time.Hour)
	for i := 0; i < n; i++ {
		p := filepath.Join(dir, fmt.Sprintf("OLD-%05d.json", i))
		f, err := os.Create(p)
		if err != nil {
			t.Fatalf("create %s: %v", p, err)
		}
		if err := f.Truncate(size); err != nil {
			t.Fatalf("truncate %s: %v", p, err)
		}
		_ = f.Close()
		mt := base.Add(time.Duration(i) * time.Second)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatalf("chtimes %s: %v", p, err)
		}
	}
}

func countPrefix(t *testing.T, dir, prefix string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			n++
		}
	}
	return n
}

// TestInboxByteCap_DefaultConfigEvictsOldestNotEverything is the regression
// test for the sweep finding (HYG-01): with the DEFAULT config
// (InboxMaxBytes == 0 ⇒ 256 MiB) the byte-cap evictor compared against the
// raw config value 0 and deleted every inbox file, including the replies a
// `send-message --wait` was about to read.
func TestInboxByteCap_DefaultConfigEvictsOldestNotEverything(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	s := NewService(ServiceConfig{InboxDir: tmp}) // default caps
	if got := s.effectiveInboxMaxBytes(); got != DefaultInboxMaxBytes {
		t.Fatalf("effective cap = %d, want the default %d", got, DefaultInboxMaxBytes)
	}

	// The sweep's reproduction: 257 MiB of old messages (already past the
	// 256 MiB default), five recent replies, then one incoming message.
	const mib = int64(1 << 20)
	seedSparseInbox(t, tmp, 257, mib)
	for i := 0; i < 5; i++ {
		p := filepath.Join(tmp, fmt.Sprintf("RECENT-%d.json", i))
		if err := os.WriteFile(p, []byte(fmt.Sprintf(`{"data":"recent reply %d"}`, i)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	from := protocol.Addr{Network: 1, Node: 0x2}
	if err := s.saveInboxMessage(&Frame{Type: TypeText, Payload: []byte("newest")}, from); err != nil {
		t.Fatalf("save that trips the cap: %v", err)
	}

	if got := countPrefix(t, tmp, "RECENT-"); got != 5 {
		t.Fatalf("recent replies surviving eviction = %d/5 (the old evictor left 0/5)", got)
	}
	if got := countPrefix(t, tmp, "TEXT-"); got != 1 {
		t.Fatalf("the incoming message was not stored (TEXT files = %d)", got)
	}
	old := countPrefix(t, tmp, "OLD-")
	if old == 0 {
		t.Fatal("the default byte cap wiped every old message; it must only evict the oldest overflow")
	}
	total, err := inboxTotalBytes(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if total > DefaultInboxMaxBytes {
		t.Fatalf("inbox holds %d bytes, over the %d default cap", total, DefaultInboxMaxBytes)
	}
	// One pass trims to the low-water mark (90%), not just under the cap.
	if total > inboxLowWater(DefaultInboxMaxBytes) {
		t.Fatalf("inbox holds %d bytes after eviction, want <= low-water %d", total, inboxLowWater(DefaultInboxMaxBytes))
	}
	// ...and no further than that: roughly 10% of the cap plus the 1 MiB of
	// overshoot is evicted, not the whole inbox.
	if evicted := 257 - old; evicted > 30 {
		t.Fatalf("evicted %d of 257 old messages, want only the ~27 needed to reach the low-water mark", evicted)
	}
}

// TestEvictInboxOverflow_DefaultConfigAppliesByteCap covers the periodic
// eviction pass with the default config: it used to skip the byte cap
// entirely whenever InboxMaxBytes was 0.
func TestEvictInboxOverflow_DefaultConfigAppliesByteCap(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	s := NewService(ServiceConfig{InboxDir: tmp})
	seedSparseInbox(t, tmp, 300, 1<<20) // 300 MiB, under the 10k file cap

	s.evictInboxOverflow(tmp)

	total, err := inboxTotalBytes(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if total > inboxLowWater(DefaultInboxMaxBytes) {
		t.Fatalf("after the periodic pass the inbox holds %d bytes, want <= %d", total, inboxLowWater(DefaultInboxMaxBytes))
	}
	remaining := countPrefix(t, tmp, "OLD-")
	if remaining == 0 {
		t.Fatal("periodic eviction wiped the inbox")
	}
	// The newest file must be among the survivors.
	if _, err := os.Stat(filepath.Join(tmp, "OLD-00299.json")); err != nil {
		t.Fatalf("newest message was evicted: %v", err)
	}
	if s.inbox.onDisk != total {
		t.Fatalf("running total %d not re-seeded from disk (%d)", s.inbox.onDisk, total)
	}
}

// TestInboxByteCap_NoDirectoryScanPerMessage checks the running byte
// counter: under the cap, saves never list the inbox directory after the
// first one (the old code listed and stat'ed every file on every message).
func TestInboxByteCap_NoDirectoryScanPerMessage(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	seedSparseInbox(t, tmp, 50, 1024)
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxBytes: 1 << 30})
	from := protocol.Addr{Node: 7}
	// Stay below inboxEvictCheckEvery so the periodic pass does not run.
	for i := 0; i < inboxEvictCheckEvery-1; i++ {
		if err := s.saveInboxMessage(&Frame{Type: TypeText, Payload: []byte("x")}, from); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	if s.inbox.scans != 1 {
		t.Fatalf("inbox directory scanned %d times for %d saves, want 1 (seed only)", s.inbox.scans, inboxEvictCheckEvery-1)
	}
	total, _ := inboxTotalBytes(tmp)
	if s.inbox.onDisk != total || s.inbox.pending != 0 {
		t.Fatalf("running total = %d (pending %d), disk = %d", s.inbox.onDisk, s.inbox.pending, total)
	}
}

// TestInboxByteCap_StaleCounterRescansBeforeEvicting: other processes delete
// inbox files (pilotctl inbox --clear). The running total then overstates
// usage; the service must re-read the directory instead of evicting the
// messages that remain.
func TestInboxByteCap_StaleCounterRescansBeforeEvicting(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxBytes: 4096})
	from := protocol.Addr{Node: 8}
	payload := []byte(strings.Repeat("p", 200))
	for i := 0; i < 12; i++ {
		if err := s.saveInboxMessage(&Frame{Type: TypeText, Payload: payload}, from); err != nil {
			t.Fatalf("fill %d: %v", i, err)
		}
	}
	// Another process clears the inbox behind the service's back.
	entries, _ := os.ReadDir(tmp)
	for _, e := range entries {
		_ = os.Remove(filepath.Join(tmp, e.Name()))
	}
	// These writes would overflow the stale counter; a fresh scan shows an
	// empty inbox, so none of them may evict another.
	for i := 0; i < 5; i++ {
		if err := s.saveInboxMessage(&Frame{Type: TypeText, Payload: payload}, from); err != nil {
			t.Fatalf("post-clear save %d: %v", i, err)
		}
		if got := countPrefix(t, tmp, "TEXT-"); got != i+1 {
			t.Fatalf("after post-clear save %d the inbox has %d files, want %d (nothing evicted)", i, got, i+1)
		}
	}
}

// TestInboxByteCap_LowWaterHysteresis: an eviction frees ~10% of the cap, so
// the following writes do not each pay for another eviction pass.
func TestInboxByteCap_LowWaterHysteresis(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	const capBytes = 20000
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxBytes: capBytes})
	from := protocol.Addr{Node: 9}
	payload := []byte(strings.Repeat("h", 100))

	var afterEviction int
	for i := 0; i < 500; i++ {
		before := countPrefix(t, tmp, "TEXT-")
		if err := s.saveInboxMessage(&Frame{Type: TypeText, Payload: payload}, from); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
		if countPrefix(t, tmp, "TEXT-") < before+1 {
			afterEviction = i
			break
		}
	}
	if afterEviction == 0 {
		t.Fatal("the byte cap never evicted")
	}
	total, _ := inboxTotalBytes(tmp)
	if total > inboxLowWater(capBytes) {
		t.Fatalf("after eviction the inbox holds %d bytes, want <= low-water %d", total, inboxLowWater(capBytes))
	}
	// The next several writes fit without another eviction.
	for i := 0; i < 5; i++ {
		before := countPrefix(t, tmp, "TEXT-")
		if err := s.saveInboxMessage(&Frame{Type: TypeText, Payload: payload}, from); err != nil {
			t.Fatalf("post-eviction save %d: %v", i, err)
		}
		if got := countPrefix(t, tmp, "TEXT-"); got != before+1 {
			t.Fatalf("post-eviction save %d evicted again (%d -> %d files)", i, before, got)
		}
	}
}

// TestInboxByteCap_ConcurrentWritersHoldCap runs saves from many goroutines
// (one per connection in production) and checks the cap and the running
// total stay consistent. Run with -race.
func TestInboxByteCap_ConcurrentWritersHoldCap(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	const capBytes = 16384
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxBytes: capBytes})
	payload := []byte(strings.Repeat("c", 300))

	var wg sync.WaitGroup
	errs := make(chan error, 8*25)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			from := protocol.Addr{Node: uint32(100 + w)}
			for i := 0; i < 25; i++ {
				if err := s.saveInboxMessage(&Frame{Type: TypeText, Payload: payload}, from); err != nil {
					errs <- err
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent save failed: %v", err)
	}
	total, _ := inboxTotalBytes(tmp)
	if total > capBytes {
		t.Fatalf("inbox holds %d bytes, over the %d cap", total, capBytes)
	}
	if s.inbox.pending != 0 {
		t.Fatalf("pending = %d after all writes finished, want 0", s.inbox.pending)
	}
	if s.inbox.onDisk < total {
		t.Fatalf("running total %d understates disk usage %d", s.inbox.onDisk, total)
	}
}

// TestInboxByteCap_RollbackReleasesBytes: a governed delivery that is
// rolled back (receipt failure) must hand its bytes back to the budget.
func TestInboxByteCap_RollbackReleasesBytes(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxBytes: 1 << 20})
	delivery, err := s.prepareInboxMessage(&Frame{Type: TypeText, Payload: []byte("to be rolled back")}, protocol.Addr{Node: 3}, nil)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if s.inbox.onDisk == 0 {
		t.Fatal("running total did not count the staged message")
	}
	if err := delivery.rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if s.inbox.onDisk != 0 || s.inbox.pending != 0 {
		t.Fatalf("after rollback onDisk=%d pending=%d, want 0/0", s.inbox.onDisk, s.inbox.pending)
	}
}

// TestInboxByteCap_DisabledSkipsAccounting: a negative InboxMaxBytes turns
// the byte cap off, and with it every scan and counter update.
func TestInboxByteCap_DisabledSkipsAccounting(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxBytes: -1})
	for i := 0; i < 10; i++ {
		if err := s.saveInboxMessage(&Frame{Type: TypeText, Payload: []byte(strings.Repeat("d", 1000))}, protocol.Addr{Node: 4}); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	if s.inbox.scans != 0 || s.inbox.onDisk != 0 {
		t.Fatalf("disabled byte cap still accounted: scans=%d onDisk=%d", s.inbox.scans, s.inbox.onDisk)
	}
	if got := countPrefix(t, tmp, "TEXT-"); got != 10 {
		t.Fatalf("files = %d, want 10", got)
	}
}

func TestInboxLowWater(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ max, want int64 }{
		{100, 90},
		{200, 180},
		{1000, 900},
		{DefaultInboxMaxBytes, 241591910},
		{1<<62 + 7, 4150517416584649119}, // no overflow near the int64 limit
	} {
		if got := inboxLowWater(tc.max); got != tc.want {
			t.Errorf("inboxLowWater(%d) = %d, want %d", tc.max, got, tc.want)
		}
	}
}

// TestInboxByteCap_UnlistableInboxIsBestEffort keeps the historical
// behaviour: failing to list the inbox does not block delivery.
func TestInboxByteCap_UnlistableInboxIsBestEffort(t *testing.T) {
	t.Parallel()
	s := NewService(ServiceConfig{InboxMaxBytes: 1 << 20})
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	path := filepath.Join(missing, "TEXT-x.json")
	if err := s.reserveInbox(missing, path, 100, 1<<20); err != nil {
		t.Fatalf("reserve with an unlistable inbox: %v", err)
	}
	if s.inbox.pending != 100 {
		t.Fatalf("pending = %d, want 100", s.inbox.pending)
	}
	s.inboxWriteDone(path, 100, false)
	if s.inbox.pending != 0 || s.inbox.onDisk != 0 || len(s.inbox.inflight) != 0 {
		t.Fatalf("after a failed write pending=%d onDisk=%d inflight=%d, want 0/0/0", s.inbox.pending, s.inbox.onDisk, len(s.inbox.inflight))
	}
}

// fileWithMarker reports whether some file in dir contains marker.
func fileWithMarker(t *testing.T, dir, marker string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err == nil && strings.Contains(string(raw), marker) {
			return true
		}
	}
	return false
}

// TestInboxByteCap_InflightWriteNotEvicted is the regression test for review
// finding DX-REV-2. Writer A is admitted and its file is fully written, but
// its reservation is not settled yet (the window between os.WriteFile and
// the deferred inboxWriteDone). Writer B then needs an eviction. B used to
// count A's bytes twice (in the fresh scan and in pending), evict down past
// the old file and delete A's file too, although A had been admitted and
// was about to be ACKed, and A + B fit under the cap.
func TestInboxByteCap_InflightWriteNotEvicted(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	const capBytes = 1000
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxBytes: capBytes})
	oldPath := filepath.Join(tmp, "OLD.json")
	if err := os.WriteFile(oldPath, []byte(strings.Repeat("o", 300)), 0600); err != nil {
		t.Fatal(err)
	}
	mt := time.Now().Add(-time.Hour)
	if err := os.Chtimes(oldPath, mt, mt); err != nil {
		t.Fatal(err)
	}

	// Hold writer A right after its file is on disk.
	aWritten := make(chan string, 1)
	releaseA := make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseA) })
	defer release()
	var writes atomic.Int32
	s.afterInboxWrite = func(path string) {
		if writes.Add(1) == 1 { // writer A only
			aWritten <- path
			<-releaseA
		}
	}
	from := protocol.Addr{Network: 1, Node: 0x2}
	errA := make(chan error, 1)
	go func() {
		errA <- s.saveInboxMessage(&Frame{Type: TypeText, Payload: []byte("MARKER-A" + strings.Repeat("a", 292))}, from)
	}()
	aPath := <-aWritten

	if err := s.saveInboxMessage(&Frame{Type: TypeText, Payload: []byte("MARKER-B" + strings.Repeat("b", 292))}, from); err != nil {
		t.Fatalf("save B: %v", err)
	}
	if _, err := os.Stat(aPath); err != nil {
		t.Fatalf("B's eviction deleted A's file, which was admitted and fully written: %v", err)
	}
	release()
	if err := <-errA; err != nil {
		t.Fatalf("save A: %v", err)
	}

	aInfo, err := os.Stat(aPath)
	if err != nil {
		t.Fatalf("A's file is gone after A was acknowledged: %v", err)
	}
	total, err := inboxTotalBytes(tmp)
	if err != nil {
		t.Fatal(err)
	}
	bSize := total - aInfo.Size()
	if _, err := os.Stat(oldPath); err == nil {
		bSize -= 300
	}
	// The premise: OLD + A + B does not fit, A + B fits under the low-water
	// mark, so exactly OLD has to go.
	if 300+aInfo.Size()+bSize <= capBytes || aInfo.Size()+bSize > inboxLowWater(capBytes) {
		t.Fatalf("test premise broken: A=%d B=%d bytes", aInfo.Size(), bSize)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("the oldest message was not evicted to make room (stat err %v)", err)
	}
	if !fileWithMarker(t, tmp, "MARKER-A") || !fileWithMarker(t, tmp, "MARKER-B") {
		t.Fatal("A or B missing from the inbox")
	}
	if total > capBytes {
		t.Fatalf("inbox holds %d bytes, over the %d cap", total, capBytes)
	}
	// The running total counts each file once.
	if s.inbox.pending != 0 || s.inbox.onDisk != total || len(s.inbox.inflight) != 0 {
		t.Fatalf("budget pending=%d onDisk=%d inflight=%d, want 0/%d/0", s.inbox.pending, s.inbox.onDisk, len(s.inbox.inflight), total)
	}
}

// TestInboxByteCap_RescanDoesNotDoubleCountInflight: a rescan while a write
// is in flight must not add the in-flight file to onDisk, or the running
// total overstates the inbox once the write settles.
func TestInboxByteCap_RescanDoesNotDoubleCountInflight(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxBytes: 1 << 20})
	path := filepath.Join(tmp, "TEXT-inflight.json")
	if err := s.reserveInbox(tmp, path, 400, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, 400), 0600); err != nil {
		t.Fatal(err)
	}
	s.evictInboxOverflow(tmp) // rescans while the write is in flight
	if s.inbox.onDisk != 0 {
		t.Fatalf("onDisk = %d while the only file is in flight, want 0", s.inbox.onDisk)
	}
	s.inboxWriteDone(path, 400, true)
	if s.inbox.onDisk != 400 || s.inbox.pending != 0 {
		t.Fatalf("after settling onDisk=%d pending=%d, want 400/0", s.inbox.onDisk, s.inbox.pending)
	}
}

// TestEvictInboxOverflow_SkipsInflightWrite: the periodic pass must not
// delete a file whose write is in flight either. It trims the settled files
// so that they fit next to the in-flight bytes.
func TestEvictInboxOverflow_SkipsInflightWrite(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	const capBytes = 1000
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxBytes: capBytes})
	path := filepath.Join(tmp, "TEXT-inflight.json")
	if err := s.reserveInbox(tmp, path, 950, capBytes); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, 950), 0600); err != nil {
		t.Fatal(err)
	}
	// Another process drops a file in while the write is in flight, and the
	// in-flight file is (for this test) older than it.
	other := filepath.Join(tmp, "OTHER.json")
	if err := os.WriteFile(other, make([]byte, 100), 0600); err != nil {
		t.Fatal(err)
	}
	older := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, older, older); err != nil {
		t.Fatal(err)
	}

	s.evictInboxOverflow(tmp)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("periodic eviction deleted an in-flight write: %v", err)
	}
	if _, err := os.Stat(other); !os.IsNotExist(err) {
		t.Fatalf("settled file not trimmed although settled + in-flight is over the cap (stat err %v)", err)
	}
	s.inboxWriteDone(path, 950, true)
	if total, _ := inboxTotalBytes(tmp); s.inbox.onDisk != total || total > capBytes {
		t.Fatalf("onDisk=%d disk=%d cap=%d", s.inbox.onDisk, total, capBytes)
	}
}
