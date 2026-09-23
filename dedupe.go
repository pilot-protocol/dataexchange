// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_dataexchange
// +build !no_dataexchange

package dataexchange

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// Receiver-side duplicate suppression.
//
// A delivery is identified by a SHA-256 over the sender address, the frame
// type, filename, MessageID, ReplyTo and the exact payload bytes. When a
// second delivery with the same key arrives inside the window after the
// first one was stored, the service acknowledges it (with the original ACK
// plus " (duplicate)") and does not store it again. Frames with a MessageID
// are checked by default; frames without one are only checked when
// ServiceConfig.DedupeContentWindow is set, because two identical legacy
// messages from one sender can be deliberate.

// DefaultDedupeWindow is how long a stored frame that carried a MessageID is
// remembered for duplicate suppression when ServiceConfig.DedupeWindow is 0.
const DefaultDedupeWindow = 10 * time.Minute

// dedupeMaxEntries bounds each dedupe cache. When it is full the oldest
// remembered delivery is forgotten early, so a burst of traffic shortens the
// effective window instead of growing memory (about 100 bytes per entry).
const dedupeMaxEntries = 8192

type dedupeKey [sha256.Size]byte

// deliveryDedupe remembers recently stored deliveries. Entries are created
// "in flight" when a frame starts processing, so a concurrent identical
// delivery (the same reply arriving over two paths microseconds apart) waits
// for the first instead of racing it; a failed first attempt is forgotten so
// the waiting copy is processed normally.
type deliveryDedupe struct {
	window time.Duration
	max    int
	now    func() time.Time

	mu      sync.Mutex
	entries map[dedupeKey]*dedupeEntry
	// order holds stored entries oldest first. Every entry in a cache has
	// the same window, so this is also expiry order.
	order []dedupeOrder
	head  int
}

type dedupeEntry struct {
	done    chan struct{} // closed once the first delivery finished
	ack     string        // the first delivery's ACK text (set before done closes)
	expires time.Time
}

type dedupeOrder struct {
	key   dedupeKey
	entry *dedupeEntry
}

func newDeliveryDedupe(window time.Duration, maxEntries int) *deliveryDedupe {
	return &deliveryDedupe{
		window:  window,
		max:     maxEntries,
		now:     time.Now,
		entries: make(map[dedupeKey]*dedupeEntry),
	}
}

// dedupeClaim is the right (and duty) to process one delivery. The zero
// value is an inert claim.
type dedupeClaim struct {
	cache *deliveryDedupe
	key   dedupeKey
	entry *dedupeEntry
}

// finish records the outcome of the claimed delivery: a stored delivery is
// remembered for the window (ack is replayed to duplicates), a failed one is
// forgotten so a retry is processed normally. Safe to call on a zero or
// already-finished claim.
func (c *dedupeClaim) finish(stored bool, ack string) {
	if c.cache == nil {
		return
	}
	c.cache.finish(c.key, c.entry, stored, ack)
	*c = dedupeClaim{}
}

// claim returns (claim, "", true) when the caller should process the
// delivery, or (zero, ack, true) when it duplicates a stored one, where ack
// is the first delivery's ACK text. While an identical delivery is still in
// flight it waits for that one to finish. ok is false only when ctx ends
// while waiting.
func (d *deliveryDedupe) claim(ctx context.Context, key dedupeKey) (claim dedupeClaim, duplicateOf string, ok bool) {
	for {
		entry, fresh := d.begin(key)
		if fresh {
			return dedupeClaim{cache: d, key: key, entry: entry}, "", true
		}
		select {
		case <-entry.done:
		case <-ctx.Done():
			return dedupeClaim{}, "", false
		}
		d.mu.Lock()
		current := d.entries[key]
		d.mu.Unlock()
		if current == entry {
			return dedupeClaim{}, entry.ack, true
		}
		// The first attempt failed (or its memory expired): try again.
	}
}

func (d *deliveryDedupe) begin(key dedupeKey) (*dedupeEntry, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expireLocked(d.now())
	if entry, exists := d.entries[key]; exists {
		return entry, false
	}
	entry := &dedupeEntry{done: make(chan struct{})}
	d.entries[key] = entry
	return entry, true
}

func (d *deliveryDedupe) finish(key dedupeKey, entry *dedupeEntry, stored bool, ack string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if stored {
		entry.ack = ack
		entry.expires = d.now().Add(d.window)
		d.order = append(d.order, dedupeOrder{key: key, entry: entry})
		for len(d.order)-d.head > d.max {
			d.popLocked()
		}
	} else if d.entries[key] == entry {
		delete(d.entries, key)
	}
	close(entry.done)
}

func (d *deliveryDedupe) expireLocked(now time.Time) {
	for d.head < len(d.order) && !now.Before(d.order[d.head].entry.expires) {
		d.popLocked()
	}
}

func (d *deliveryDedupe) popLocked() {
	oldest := d.order[d.head]
	d.order[d.head] = dedupeOrder{}
	d.head++
	if d.entries[oldest.key] == oldest.entry {
		delete(d.entries, oldest.key)
	}
	// Compact once the consumed prefix dominates, keeping the slice bounded.
	if d.head > 64 && d.head*2 > len(d.order) {
		d.order = append(d.order[:0], d.order[d.head:]...)
		d.head = 0
	}
}

// len reports how many deliveries (stored or in flight) are remembered.
func (d *deliveryDedupe) len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.entries)
}

// dedupeEligible reports whether frames of this (already unwrapped) type are
// stored as a single unit and therefore subject to duplicate suppression.
// Streams have their own resume protocol and trace frames are diagnostics.
func dedupeEligible(frameType uint32) bool {
	switch frameType {
	case TypeText, TypeJSON, TypeBinary, TypeFile, TypeGoverned:
		return true
	default:
		return false
	}
}

// deliveryKeyFor hashes everything that makes two deliveries identical.
// Variable-length fields are length-prefixed so field boundaries cannot be
// shifted to forge a collision.
func deliveryKeyFor(from protocol.Addr, f *Frame) dedupeKey {
	h := sha256.New()
	var n [8]byte
	writeField := func(b []byte) {
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	writeField([]byte(from.String()))
	binary.BigEndian.PutUint32(n[:4], f.Type)
	h.Write(n[:4])
	writeField([]byte(f.Filename))
	writeField([]byte(f.MessageID))
	writeField([]byte(f.ReplyTo))
	writeField(f.Payload)
	var key dedupeKey
	copy(key[:], h.Sum(nil))
	return key
}

// dedupeCacheFor picks the cache that governs f, or nil when f is not
// subject to duplicate suppression.
func (s *Service) dedupeCacheFor(f *Frame) *deliveryDedupe {
	if !dedupeEligible(f.Type) {
		return nil
	}
	if f.MessageID != "" {
		return s.dedupeByID
	}
	return s.dedupeByContent
}

func (s *Service) effectiveDedupeWindow() time.Duration {
	switch {
	case s.cfg.DedupeWindow < 0:
		return 0
	case s.cfg.DedupeWindow == 0:
		return DefaultDedupeWindow
	default:
		return s.cfg.DedupeWindow
	}
}
