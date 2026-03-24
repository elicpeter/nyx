package main

import "database/sql"

func querySafe(dsn string) {
	db, _ := sql.Open("postgres", dsn)
	defer db.Close()
	db.Query("SELECT 1")
}
