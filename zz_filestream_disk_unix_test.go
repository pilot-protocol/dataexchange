// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux || darwin || freebsd

package dataexchange

import "testing"

// FreeBSD's Statfs_t.Bavail is signed and goes negative once root's reserved
// blocks are in use. That is no space, not 2^64 blocks of it.
func TestBlocksAvailable_NegativeIsNone(t *testing.T) {
	if got := blocksAvailable(int64(-3)); got != 0 {
		t.Errorf("blocksAvailable(-3) = %d, want 0", got)
	}
	if got := blocksAvailable(int64(7)); got != 7 {
		t.Errorf("blocksAvailable(int64 7) = %d, want 7", got)
	}
	if got := blocksAvailable(uint64(7)); got != 7 {
		t.Errorf("blocksAvailable(uint64 7) = %d, want 7", got)
	}
}
