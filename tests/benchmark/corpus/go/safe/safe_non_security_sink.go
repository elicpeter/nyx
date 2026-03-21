package main

import (
	"fmt"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	log.Printf("User requested: %s", name)
	fmt.Fprintf(w, "%d", len(name))
}
