package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

// Phase 12.6 fixture: a Go switch with 6+ cases, each dispatching to a
// different sink. Designed to exercise multi-case taint propagation — we
// assert the engine reports findings across distinct cases regardless of
// whether the SSA terminator uses the classic cascade or the
// Terminator::Switch variant introduced in Phase 12.3.
//
// The user input `r.URL.Query().Get("q")` taints `action` and then flows
// into a different dangerous sink per switch case. Cases are mutually
// exclusive (Go switch has no implicit fall-through) so the Switch
// terminator is a natural fit.

var db *sql.DB

func dispatch(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("q")

	switch action {
	case "login":
		// SQL injection — action flows into a raw query.
		db.Query("SELECT * FROM users WHERE name = '" + action + "'")
	case "ping":
		// Command injection via exec.
		exec.Command("sh", "-c", "ping "+action).Run()
	case "render":
		// XSS: reflected back to response writer.
		fmt.Fprintf(w, "<div>%s</div>", action)
	case "read":
		// Path traversal: open an attacker-controlled file.
		os.Open(action)
	case "env":
		// Environment tampering.
		os.Setenv(action, "1")
	case "log":
		// Log injection via %s echo of tainted input.
		fmt.Fprintf(os.Stderr, "%s", action)
	case "stream":
		// Additional SSRF-shaped HTTP fetch.
		http.Get(action)
	default:
		fmt.Fprint(w, "unknown")
	}
}

func main() {
	http.HandleFunc("/", dispatch)
	http.ListenAndServe(":8080", nil)
}
