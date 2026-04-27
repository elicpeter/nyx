package main

// Real-repo precision (2026-04-27): companion vulnerable counterpart to
// `safe/safe_chained_call_response_header.go`.
//
// The chained-call suppression added in
// `src/auth_analysis/config.rs::classify_sink_class` only gates the
// verb-name fallback on shapes whose receiver is itself a call result
// (`w.Header().Get(..)`).  Bare-identifier receivers like `repo.Find`
// remain canonical data-layer sinks and must continue to fire
// `go.auth.missing_ownership_check` when invoked with a scoped
// identifier (`id` parameter) without a preceding ownership check.

type Repo struct{}

func (r *Repo) Find(id string) interface{} { return nil }
func (r *Repo) Save(id string, val string) {}

// `repo.Find(id)` — bare-identifier receiver, name matches the `Find`
// read indicator.  Still classifies as `DbCrossTenantRead` and still
// fires the ownership check because no auth check precedes it.
func GetByID(ctx interface{}, repo *Repo, id string) interface{} {
	return repo.Find(id)
}

// `repo.Save(id, ..)` — bare-identifier receiver, mutation indicator.
func UpdateByID(ctx interface{}, repo *Repo, id string, val string) {
	repo.Save(id, val)
}
