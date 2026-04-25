package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	http.Get(url)
}
