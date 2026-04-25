package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	if !is_authenticated(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	path := r.URL.Query().Get("path")
	clean := filepath.Clean(path)
	data, _ := os.ReadFile(clean)
	w.Write(data)
}

func is_authenticated(r *http.Request) bool {
	return r.Header.Get("Authorization") != ""
}
