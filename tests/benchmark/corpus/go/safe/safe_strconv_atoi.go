package main

import (
	"fmt"
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("count")
	count, err := strconv.Atoi(raw)
	if err != nil {
		http.Error(w, "bad input", 400)
		return
	}
	fmt.Fprintf(w, "Count: %d", count)
}
