package main

import (
	"database/sql"
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("id")
	_, err := strconv.Atoi(input)
	if err != nil {
		http.Error(w, "bad input", 400)
		return
	}
	db, _ := sql.Open("sqlite3", "app.db")
	defer db.Close()
	db.Query("SELECT * FROM users WHERE id = " + input)
}
