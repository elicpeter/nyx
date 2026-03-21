package main

import (
	"net/http"
	"os/exec"
)

var allowed = map[string]bool{"ls": true, "pwd": true}

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	if !allowed[cmd] {
		http.Error(w, "denied", 403)
		return
	}
	exec.Command(cmd).Run()
}
