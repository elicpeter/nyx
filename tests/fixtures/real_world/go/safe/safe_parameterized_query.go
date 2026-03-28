package main

import (
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/lib/pq"
)

// Safe: $1 positional parameter with db.Query
func getUser(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("id")
	rows, _ := db.Query("SELECT name FROM users WHERE id = $1", userId)
	defer rows.Close()
	for rows.Next() {
		var name string
		rows.Scan(&name)
		fmt.Fprintf(w, "%s\n", name)
	}
}

// Safe: ? placeholder with db.Exec (MySQL-style)
func deleteUser(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("id")
	db.Exec("DELETE FROM users WHERE id = ?", userId)
	fmt.Fprintf(w, "deleted")
}

// Safe: multiple $1/$2 placeholders with db.Query
func searchUsers(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	age := r.URL.Query().Get("age")
	rows, _ := db.Query("SELECT * FROM users WHERE name = $1 AND age = $2", name, age)
	defer rows.Close()
	for rows.Next() {
		var n string
		rows.Scan(&n)
		fmt.Fprintf(w, "%s\n", n)
	}
}
