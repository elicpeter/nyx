// Go method-receiver self-call suppression (real-repo precision,
// 2026-04-27 deferred-work follow-up).  Pinned in
// `auth_analysis_tests::go_self_method_receiver_does_not_flag`.
package main

type Cache struct{}

const internalKey = "k"

func (c *Cache) getOrRemove(id string) string {
	_ = id
	return ""
}

func (c *Cache) IndexFor(prefix string) string {
	_ = prefix
	// `c.getOrRemove(internalKey)` — receiver `c` is the unit's own
	// method receiver; this is an intra-struct dispatch, not a
	// data-layer call.  The auth analyser should NOT fire
	// `go.auth.missing_ownership_check` on this shape.
	return c.getOrRemove(internalKey)
}
