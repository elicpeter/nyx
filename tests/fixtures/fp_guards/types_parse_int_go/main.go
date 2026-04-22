// FP GUARD — type-driven suppression (strconv.Atoi int).
//
// The tainted query string is parsed with strconv.Atoi — a sanitiser
// that covers Cap::all for the resulting int.  Passing the int to a
// SQL placeholder (or even naïve concat, as below) cannot carry a
// SQL-injection payload.
//
// Expected: NO taint-unsanitised-flow finding.
package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
)

func Handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	raw := r.FormValue("id")       // tainted web source
	id, err := strconv.Atoi(raw)   // strconv.Atoi → Cap::all sanitiser
	if err != nil {
		http.Error(w, "bad id", 400)
		return
	}
	rows, _ := db.Query(fmt.Sprintf("SELECT name FROM users WHERE id = %d", id))
	defer rows.Close()
}
