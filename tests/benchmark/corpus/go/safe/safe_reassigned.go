package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	name = "Guest"
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}
