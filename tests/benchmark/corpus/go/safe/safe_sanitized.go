package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	clean := filepath.Clean(path)
	data, _ := os.ReadFile(clean)
	w.Write(data)
}
