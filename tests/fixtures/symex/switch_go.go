// Fixture: Go switch with integer-literal cases that exercise per-case
// path-constraint forking in the symex executor.
//
// The scrutinee `code` is a primitive integer, so `code == 200` /
// `code == 500` lower to ConstValue::Int comparisons that the constraint
// solver can refine. Findings on the safe arm should not be emitted
// because the path constraint forks the symbolic state and the safe arm
// sanitizes before the sink.

package main

import (
	"database/sql"
	"net/http"
	"strconv"
)

var db *sql.DB

func sanitize(s string) string {
	return strconv.Quote(s)
}

func dispatch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	code := 200
	if r.URL.Query().Get("mode") == "raw" {
		code = 500
	}

	switch code {
	case 500:
		// Raw path: tainted q flows into a SQL sink.
		_, _ = db.Query("SELECT * FROM users WHERE name = '" + q + "'")
	case 200:
		// Safe path: q is sanitized first.
		safe := sanitize(q)
		_, _ = db.Query("SELECT * FROM users WHERE name = '" + safe + "'")
	default:
		_, _ = w.Write([]byte("unknown"))
	}
}
