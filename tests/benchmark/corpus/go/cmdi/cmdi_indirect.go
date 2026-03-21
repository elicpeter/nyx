package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := "ping -c 1 " + host
	exec.Command("sh", "-c", cmd).Run()
}
