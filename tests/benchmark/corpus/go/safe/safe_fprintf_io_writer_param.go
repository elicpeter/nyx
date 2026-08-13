package main

import (
	"fmt"
	"io"
	"net/http"
)

// A generic doc / serializer helper that formats attacker-influenced data
// into a caller-supplied `io.Writer`.  The bytes never reach an HTTP client
// (the writer is a buffer / file / pipe / stdout at every call site), so
// `fmt.Fprintf` here is NOT a reflected-XSS vector.  A real XSS handler
// declares its writer as `http.ResponseWriter` (see go/xss/xss_fprintf.go).
//
// Distilled from prometheus util/documentcli/documentcli.go:
// `func GenerateMarkdown(model *kingpin.ApplicationModel, writer io.Writer)`.
func writeRow(w io.Writer, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "row %s\n", name)
}
