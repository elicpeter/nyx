package main

import (
	"fmt"
	"net/http"
)

// Vulnerable counterpart to safe/safe_fprintf_io_writer_param.go.  The render
// helper declares its writer explicitly as `http.ResponseWriter`, so the
// formatted bytes DO reach the HTTP client — a real reflected XSS.  Proves the
// Go writer-type recogniser suppresses generic `io.Writer` helpers without
// silencing response-writer-typed helpers.
func render(w http.ResponseWriter, name string) {
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	render(w, name)
}
