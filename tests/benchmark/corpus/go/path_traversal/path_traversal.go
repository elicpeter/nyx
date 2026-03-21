package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	data, _ := os.ReadFile(path)
	w.Write(data)
}
