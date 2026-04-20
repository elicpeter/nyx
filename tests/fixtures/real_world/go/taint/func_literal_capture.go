package main

import (
	"net/http"
	"os/exec"
)

// Go func literal captures tainted req.URL.Query().Get("q") then calls sink.
func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	run := func() {
		exec.Command("sh", "-c", q).Run()  // sink on captured source
	}
	run()
}
