package main

// Real-repo precision (2026-04-27): hugo's `cache/filecache/filecache.go`
// produced ~48 go.auth.missing_ownership_check findings on bare-receiver
// `*Cache` method calls inside the `Cache` type's own methods —
// `c.getOrRemove(id)`, `c.removeIfExpired(id)`, `c.Fs.Create(filename)`.
//
// Each `c.foo(...)` call is an intra-struct dispatch from one
// `*Cache` method to another, parameterised by an internal cache key
// (`id`).  Without type tracking the auth analyser cannot tell `c.Fs`
// is `afero.Fs` (in-process filesystem abstraction) from `*sql.DB`,
// so it would prefix-match the trailing verb (`Get`, `Save`, `Remove`,
// `Create`) against `read_indicator_names` / `mutation_indicator_names`
// and produce a HIGH-severity ownership-gap finding.
//
// Engine fix: in `src/auth_analysis/extract/common.rs::build_function_unit`,
// when the unit is a Go `method_declaration` (the only declaration kind
// that exposes a `receiver` field in tree-sitter-go), seed the receiver
// variable name into `state.non_sink_vars`.  `classify_sink_class` then
// routes any `<receiver>.<chain>(...)` call to `SinkClass::InMemoryLocal`
// — which is excluded from `is_auth_relevant` — closing the entire
// hugo `*Cache`-method cluster in one structural step.
//
// The fix is conservative on the safe side: in `func (s *Service)
// Handle() { s.db.Query(sql) }`, the call would also be
// classified `InMemoryLocal`.  When SSA type facts include the
// receiver root (the `apply_var_types_to_model` Phase B2 path), the
// type-derived class still wins via the override pass, so the fix
// only suppresses calls whose receiver type is unknown — which is the
// hugo case where over-firing was the entire problem.
//
// Companion vulnerable counterpart: `vuln_repo_findbyid_no_auth.go` —
// `repo.Find(id)` (bare-identifier receiver, NOT a method receiver)
// still classifies as a data-layer read and still fires.

type Cache struct {
	Fs FsProxy
}

type FsProxy struct{}

func (f FsProxy) Create(name string) (string, error) {
	_ = name
	return "", nil
}

func (f FsProxy) Remove(name string) error {
	_ = name
	return nil
}

// Constant cache key — not user-controlled but the original FP also
// fired with internal id parameters, so this fixture pins the
// structural shape rather than the literal-bound variant.
const internalKey = "internal-cache-id"

func (c *Cache) getOrRemove(id string) (string, error) {
	// Intra-struct dispatch: `c.removeIfExpired` is another `*Cache`
	// method, not a data-layer call.  Without the receiver-name
	// suppression, this would prefix-match `Remove` and fire
	// `go.auth.missing_ownership_check`.
	if err := c.removeIfExpired(id); err != nil {
		return "", err
	}
	// `c.Fs.Create(...)` — receiver chain `c.Fs`, first segment is
	// the method receiver `c`; without the fix this would
	// prefix-match `Create` (mutation indicator) and fire.
	if path, err := c.Fs.Create(id); err == nil {
		_ = path
	}
	return id, nil
}

func (c *Cache) removeIfExpired(id string) error {
	// Same shape as `c.Fs.Create` but with a remove verb on the
	// in-process filesystem proxy.
	return c.Fs.Remove(id)
}

func (c *Cache) IndexFor(prefix string) string {
	// Bare-receiver internal getter — exemplifies the prefix-match
	// case.  Without the fix this would prefix-match `Get`.
	_ = prefix
	out, _ := c.getOrRemove(internalKey)
	return out
}

func main() {
	c := &Cache{}
	_, _ = c.getOrRemove("k")
	_ = c.removeIfExpired("k")
	_ = c.IndexFor("p")
}
