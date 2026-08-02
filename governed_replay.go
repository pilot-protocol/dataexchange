// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"fmt"
	"sync"
	"time"

	"github.com/pilot-protocol/common/decision"
)

// maxGovernedReplayEntries bounds the receiver-side replay cache. Entries are
// keyed on the signed intent and expire at the intent's own ExpiresAt (<= the
// 5-minute MaxIntentTTL), so under legitimate signed traffic the cache drains
// continuously. The cap is a backstop against pathological retention; on
// overflow a new transfer is refused (fail closed) rather than admitted
// un-deduplicated.
const maxGovernedReplayEntries = 1 << 20

// governedReplayGuard rejects a second delivery of the same signed governed
// intent. A verified governed envelope is otherwise a bearer capability: any
// peer that observed one could re-send the exact bytes within the intent TTL,
// producing duplicate authorized deliveries and re-charging the signing
// agent's quota. Dedup is keyed on (tenant, agent, intent id) — all
// signature-authenticated fields — so a replay cannot dodge it by presenting a
// different transport peer. A legitimate retry must carry a fresh intent
// (fresh nonce/id); reusing a signed intent IS the replay pattern.
type governedReplayGuard struct {
	mu   sync.Mutex
	seen map[string]int64 // key -> intent ExpiresAt (unix seconds)
	now  func() time.Time
}

func newGovernedReplayGuard() *governedReplayGuard {
	return &governedReplayGuard{seen: make(map[string]int64), now: time.Now}
}

func governedReplayKey(intent decision.Intent) string {
	return intent.TenantID + "\x1f" + intent.AgentID + "\x1f" + intent.ID
}

// admit records the intent as delivered and returns an error if it was already
// delivered (replay) or if the cache is saturated. A blank intent ID is a
// no-op (upstream freshness/nonce checks still apply).
func (g *governedReplayGuard) admit(intent decision.Intent) error {
	if intent.ID == "" {
		return nil
	}
	now := g.now().Unix()
	key := governedReplayKey(intent)
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, exp := range g.seen {
		if exp <= now {
			delete(g.seen, k)
		}
	}
	if exp, ok := g.seen[key]; ok && exp > now {
		return fmt.Errorf("governed intent already delivered (replay rejected)")
	}
	if len(g.seen) >= maxGovernedReplayEntries {
		return fmt.Errorf("governed replay cache saturated")
	}
	expiresAt := intent.ExpiresAt
	if expiresAt <= now {
		expiresAt = now + int64(decision.MaxIntentTTL/time.Second)
	}
	g.seen[key] = expiresAt
	return nil
}
