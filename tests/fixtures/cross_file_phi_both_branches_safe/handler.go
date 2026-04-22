package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

// searchItems handles GET /search?q=<user-supplied>
//
// SAFE: the raw query parameter flows through safeOnBothBranches (defined
// in validator.go) which sanitises on every return path.  With CF-4 the
// per-return-path decomposition records both branches as carrying the
// same sanitising transform, so the caller observes a clean flow on
// every call regardless of which branch ran.
func searchItems(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("q")
	clean, err := safeOnBothBranches(raw, true)
	if err != nil {
		http.Error(w, "bad query", http.StatusBadRequest)
		return
	}
	db.QueryRow("SELECT id FROM items WHERE name = ?", clean) //nolint — sanitised both branches
}
