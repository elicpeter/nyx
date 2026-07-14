package main

import (
	"bytes"
	"fmt"
	"net/http"
)

// Formats attacker-influenced data into an in-memory `*bytes.Buffer` that is
// later streamed to a subprocess (git-index input), not to an HTTP response.
// `fmt.Fprintf` into a buffer is not a reflected-XSS vector.
//
// Distilled from gitea services/repository/files/temp_repo.go:
// `stdIn := new(bytes.Buffer); fmt.Fprintf(stdIn, "0 %s\t%s\x00", ...)`.
func buildIndexInput(r *http.Request) []byte {
	name := r.URL.Query().Get("name")
	buf := bytes.NewBuffer(nil)
	fmt.Fprintf(buf, "0 %s\t%s\x00", name, "blob")
	return buf.Bytes()
}
