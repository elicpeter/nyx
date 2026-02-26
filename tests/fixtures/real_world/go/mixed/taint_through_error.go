package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		// Error is not properly handled
		http.Error(w, err.Error(), 500)
	}
	w.Write(out)
}
