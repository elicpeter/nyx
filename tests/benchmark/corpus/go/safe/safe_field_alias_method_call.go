// Pointer-analysis Phase 2 fixture (gated on `NYX_POINTER_ANALYSIS=1`).
//
// The textual chain decomposition in `state/transfer.rs` already
// handles `c.mu.Lock()` by routing through `chain_proxies`, but the
// SSA-aliased shape below — `m := c.mu; m.Lock(); m.Unlock()` —
// previously fell through to the SymbolId proxy path because the
// receiver of the call is a single bare identifier (`m`), not a chain.
//
// With pointer analysis enabled the per-body PointsToFacts identify
// `m` as `Field(SelfParam, mu)` (PtrProxyHint::FieldOnly) and the
// state engine routes the acquire/release pair into chain_proxies
// instead of marking `m` as a leakable resource.  No
// `state-resource-leak` / `state-resource-leak-possible` finding
// should fire here.
package main

import "sync"

type Container struct {
	mu sync.Mutex
}

func (c *Container) Update() {
	m := c.mu
	m.Lock()
	defer m.Unlock()
	// mutation guarded by the field-aliased mutex
}
