// Counterpart to safe_error_log_only_function.go.  The vulnerable
// shape is `if err != nil { log(...) } sink(tainted)` — the error is
// logged but execution falls through to a real sink that uses
// user-controlled input.  This must still fire `cfg-error-fallthrough`
// after the False-edge-only walk fix.
package main

import (
	"database/sql"
	"fmt"
)

func handle(db *sql.DB, err error, name string) {
	if err != nil {
		fmt.Println("warn:", err)
	}
	db.Exec("UPDATE u SET n=" + name)
}
