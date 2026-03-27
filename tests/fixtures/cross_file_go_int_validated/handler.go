package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

// lookupRecord handles GET /record?id=<user-supplied>
//
// SAFE: the raw HTTP parameter is passed through validateID() (defined in
// validation.go) which calls strconv.Atoi — a Cap::all() sanitiser.
// The sanitised integer is then used in a db.Query call.
// No taint-unsanitised-flow should be reported.
func lookupRecord(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("id")           // taint source
	id, err := validateID(raw)         // cross-file int sanitiser
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	db.QueryRow("SELECT name FROM records WHERE id = ?", id) //nolint — sanitised
}
