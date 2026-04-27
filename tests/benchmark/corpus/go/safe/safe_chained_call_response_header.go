package main

import (
	"net/http"
)

const (
	AmzRequestID    = "x-amz-request-id"
	AmzRequestHosts = "x-amz-host-id"
)

// Real-repo precision (2026-04-27): minio's `cmd/api-response.go` and
// `cmd/admin-handlers.go` produced 70+ go.auth.missing_ownership_check
// findings on the chained-call shape `w.Header().Get(constName)`.
//
// `w.Header()` returns an `http.Header` (a `map[string][]string`) from
// the response writer's *outgoing* headers — reading a value back by a
// constant key is never auth-relevant.  But the auth-analysis sink
// classifier saw the callee text `w.Header().Get`, matched `Get`
// against the `read_indicator_names` list (which prefix-matches), and
// classified the operation as `DbCrossTenantRead`.  With the helper's
// `(ctx, w, ...)` parameter shape passing `unit_has_user_input_evidence`
// (the `ctx` name signals a request-context handler), a high-severity
// finding fired on the constant header lookup.
//
// Engine fix: in `src/auth_analysis/config.rs::classify_sink_class`,
// suppress the loose verb-name fallback (`is_read` / `is_mutation`)
// when the receiver chain itself contains a call expression
// (`w.Header().Get`, `r.URL.Query().Get`, `db.Tx(opts).Query`).  The
// receiver of the final method is the return value of an earlier
// call — opaque to the analyser — and the bare verb match cannot
// safely conclude a data-layer sink without type tracking.
//
// Companion vulnerable counterpart: `vuln_repo_findbyid_no_auth.go` —
// `repo.Find(id)` (bare-identifier receiver) still classifies as a
// data-layer read and still fires.

func writeErrorResponse(ctx interface{}, w http.ResponseWriter, errCode int) {
	// Reading from the response writer's outgoing headers using a
	// constant key.  Chained-call receiver `w.Header()` returns an
	// in-process map; `.Get(...)` on it is in-memory bookkeeping, not
	// a data-layer or network sink.
	requestID := w.Header().Get(AmzRequestID)
	hostID := w.Header().Get(AmzRequestHosts)
	_ = requestID
	_ = hostID
	_ = errCode
}

func parseQueryFlag(r *http.Request) string {
	// Same shape on the request side: `r.URL.Query()` returns
	// `url.Values` (a map); `.Get(name)` is a constant-keyed lookup.
	return r.URL.Query().Get("flag")
}
