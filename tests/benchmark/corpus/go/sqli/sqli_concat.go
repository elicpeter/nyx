package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	db, _ := sql.Open("sqlite3", "app.db")
	db.Query("SELECT * FROM users WHERE id = " + id)
}
