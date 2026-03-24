package main

import (
	"html"
	"net/http"
)

func sanitizeInput(s string) string {
	return html.EscapeString(s)
}

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	safe := sanitizeInput(name)
	w.Write([]byte("<h1>" + safe + "</h1>"))
}
