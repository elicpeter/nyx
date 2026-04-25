package main

import "database/sql"

func queryUnsafe(dsn string) {
	db, _ := sql.Open("postgres", dsn)
	db.Query("SELECT 1")
	// db never closed — leak
}
