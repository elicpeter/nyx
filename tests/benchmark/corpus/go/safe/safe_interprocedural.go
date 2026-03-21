package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func sanitizePath(p string) string {
	return filepath.Clean(p)
}

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	data, _ := os.ReadFile(sanitizePath(path))
	w.Write(data)
}
