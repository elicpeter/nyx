package main

import (
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/lib/pq"
)

func getUserUnsafe(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT name FROM users WHERE id = '%s'", userId)
	rows, _ := db.Query(query)
	defer rows.Close()
	for rows.Next() {
		var name string
		rows.Scan(&name)
		fmt.Fprintf(w, "%s\n", name)
	}
}

func getUserSafe(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("id")
	rows, _ := db.Query("SELECT name FROM users WHERE id = $1", userId)
	defer rows.Close()
	for rows.Next() {
		var name string
		rows.Scan(&name)
		fmt.Fprintf(w, "%s\n", name)
	}
}
