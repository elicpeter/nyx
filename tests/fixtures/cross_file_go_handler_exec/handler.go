package main

import (
	"fmt"
	"net/http"
)

// handleRun is an HTTP handler that takes a user-supplied command and executes
// it via a helper function defined in executor.go.
//
// VULN: r.FormValue("cmd") is a taint source (user-controlled).  The tainted
// value crosses a file boundary into runCommand(), which passes it verbatim to
// exec.Command.  No sanitisation occurs anywhere in the call chain.
func handleRun(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd") // taint source: user input from HTTP form
	runCommand(cmd)            // tainted value crosses file boundary → exec.Command
	fmt.Fprintln(w, "done")
}
