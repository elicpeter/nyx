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
	if !is_authenticated(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	path := r.URL.Query().Get("path")
	data, _ := os.ReadFile(sanitizePath(path))
	w.Write(data)
}

func is_authenticated(r *http.Request) bool {
	return r.Header.Get("Authorization") != ""
}
