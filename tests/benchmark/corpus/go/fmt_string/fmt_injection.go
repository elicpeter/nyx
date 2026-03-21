package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	fmt.Fprintf(w, msg)
}
