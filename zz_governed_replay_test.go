// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/decision"
)

// TestGovernedReplayGuard pins SECURITY_REVIEW_v1.14 finding M5: a verified
// governed intent may be delivered at most once; a replay within the intent's
// validity window is rejected, and the cache drains after expiry.
func TestGovernedReplayGuard(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	clock := base
	g := newGovernedReplayGuard()
	g.now = func() time.Time { return clock }

	intent := decision.Intent{ID: "int-1", TenantID: "t", AgentID: "a", ExpiresAt: base.Add(5 * time.Minute).Unix()}

	if err := g.admit(intent); err != nil {
		t.Fatalf("first delivery rejected: %v", err)
	}
	if err := g.admit(intent); err == nil {
		t.Fatal("replay within TTL was ACCEPTED")
	}
	// A distinct intent from the same agent is fine (fresh nonce/id).
	if err := g.admit(decision.Intent{ID: "int-2", TenantID: "t", AgentID: "a", ExpiresAt: clock.Add(5 * time.Minute).Unix()}); err != nil {
		t.Fatalf("distinct intent rejected: %v", err)
	}
	// After the intent expires the entry is pruned; the same id no longer
	// collides (and upstream freshness would reject the stale intent anyway).
	clock = base.Add(6 * time.Minute)
	if err := g.admit(decision.Intent{ID: "int-1", TenantID: "t", AgentID: "a", ExpiresAt: clock.Add(5 * time.Minute).Unix()}); err != nil {
		t.Fatalf("post-expiry re-use rejected: %v", err)
	}
}
