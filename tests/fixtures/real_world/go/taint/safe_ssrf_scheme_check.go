package main

import (
	"net/http"
	"net/url"
	"strings"
)

func handler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	parsed, err := url.Parse(target)
	if err != nil || !strings.HasPrefix(parsed.Scheme, "https") {
		http.Error(w, "invalid", 400)
		return
	}
	http.Get(target)
}
