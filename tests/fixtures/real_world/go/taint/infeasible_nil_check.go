package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	if cmd == "safe" {
		if cmd == "rm" {
			// Infeasible: cmd == "safe" AND cmd == "rm"
			exec.Command(cmd).Run()
		}
	}
	exec.Command(cmd).Run()
}
