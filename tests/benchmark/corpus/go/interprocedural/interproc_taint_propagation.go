package main

import (
	"database/sql"
	"net/http"
)

func buildQuery(filter string) string {
	return "SELECT * FROM logs WHERE msg LIKE '%" + filter + "%'"
}

func handler(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	query := buildQuery(filter)
	var db *sql.DB
	db.Query(query)
}
