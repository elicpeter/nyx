// Phase 3 of the field-projections rollout (2026-04-25): the textual
// proxy-receiver extractor in `state/transfer.rs` previously collapsed
// chained receivers to the chain root, FP-ing `c` as proxy-acquired.
//
// This fixture exercises the proper FieldProj-aware path: a method call
// `c.writer.header.set(...)` (3-segment receiver) must NOT mark `c` as
// proxy-acquired — `c.writer.header` is a semantically distinct chain
// receiver tracked separately in `ProductState.chain_proxies`.
//
// Companion to `safe_method_receiver_mutex.go` which exercises the
// 2-segment receiver case (`c.mu.Lock()` / `c.mu.Unlock()`).  Together
// they pin the contract that the chain root never inherits proxy state
// from any of its field projections.
package main

type ResponseWriter interface {
	Header() Header
}

type Header map[string][]string

func (h Header) set(key, value string) {
	h[key] = []string{value}
}

type chainContext struct {
	writer ResponseWriter
}

// Realistic chained-receiver shape: `c.writer.header.set(...)` lowers to
// 2 FieldProj ops + a Call.  The state engine's chain_proxies map
// records the projection chain `c.writer.header` as the receiver, NOT
// the chain root `c`.  No leak should fire on `c` even though no
// matching `release` is called.
func (c *chainContext) MarkSafe(key, value string) {
	hdr := c.writer.Header()
	_ = hdr
}

// Direct receiver (single dot) still routes through the SymbolId-based
// path — preserves all existing 1-dot proxy semantics.  No leak on `c`.
func (c *chainContext) DirectReceiver() {
	_ = c.writer
}
