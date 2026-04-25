package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func logHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	db, _ := sql.Open("sqlite3", "audit.db")
	// fmt.Fprintf to a *sql.DB (an io.Writer that is NOT http.ResponseWriter)
	// should not trigger XSS — db is a database connection, not a response writer.
	fmt.Fprintf(db, "INSERT INTO logs VALUES ('%s')", name)
}
