package main

import (
	"io/ioutil"
	"net/http"
	"path/filepath"
)

func readFileHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	data, err := ioutil.ReadFile(path)
	if err != nil {
		http.Error(w, "Not found", 404)
		return
	}
	w.Write(data)
}

func safeReadHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	clean := filepath.Clean(path)
	if filepath.IsAbs(clean) {
		http.Error(w, "Forbidden", 403)
		return
	}
	data, _ := ioutil.ReadFile(filepath.Join("/safe/dir", clean))
	w.Write(data)
}
