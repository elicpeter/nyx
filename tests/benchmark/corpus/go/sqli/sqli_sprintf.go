package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	db, _ := sql.Open("sqlite3", "app.db")
	db.Exec(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
}
