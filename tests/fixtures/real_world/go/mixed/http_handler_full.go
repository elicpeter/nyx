package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

func adminHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	// No auth check
	out, _ := exec.Command("sh", "-c", cmd).Output()
	fmt.Fprintf(w, "%s", out)
}

func readHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	f, _ := os.Open(path)
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	w.Write(buf[:n])
	// f leaked + path traversal
}
