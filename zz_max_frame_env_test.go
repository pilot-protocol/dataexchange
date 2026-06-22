// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import "testing"

// TestMaxFrameSize_DefaultAndConstants pins the default cap so a future
// bump is forced to update tests + CHANGELOG alongside the code.
//
// The env-driven override (PILOT_DATAEXCHANGE_MAX_FRAME) is evaluated at
// package init; testing it after the fact would require restarting the
// process, which `go test` can't do cleanly. Instead we verify the
// init-time invariants here and trust the override path through code
// review.
func TestMaxFrameSize_DefaultAndConstants(t *testing.T) {
	t.Parallel()
	if DefaultMaxFrameSize != 64<<20 {
		t.Errorf("DefaultMaxFrameSize = %d; want %d (64 MiB)", DefaultMaxFrameSize, 64<<20)
	}
	// When PILOT_DATAEXCHANGE_MAX_FRAME is unset (as it is in CI),
	// MaxFrameSize must equal the default. A non-default value here
	// means the test environment is overriding the cap and the rest of
	// the suite may behave unexpectedly — fail loudly so the operator
	// sees it.
	if MaxFrameSize != DefaultMaxFrameSize {
		t.Errorf("MaxFrameSize = %d; want %d (default) — is PILOT_DATAEXCHANGE_MAX_FRAME set?",
			MaxFrameSize, DefaultMaxFrameSize)
	}
}
