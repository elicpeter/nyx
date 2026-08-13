package main

import (
	"bytes"
	"fmt"
	"net/http"
)

// Formats attacker-influenced data into a `*bytes.Buffer` allocated with the
// `new(bytes.Buffer)` builtin, later streamed to a subprocess (git-index
// input), not to an HTTP response.  `fmt.Fprintf` into a buffer is not a
// reflected-XSS vector.  Unlike `bytes.NewBuffer(nil)`, the `new(T)` form
// drops its type argument from the CFG, so the writer type must be recovered
// from the binding constructor (`extract_decl_type_go`).
//
// Distilled from gitea services/repository/files/temp_repo.go:152:
// `stdIn := new(bytes.Buffer); fmt.Fprintf(stdIn, "0 %s\t%s\x00", ...)`.
func buildIndexInput(r *http.Request) []byte {
	name := r.URL.Query().Get("name")
	stdIn := new(bytes.Buffer)
	fmt.Fprintf(stdIn, "0 %s\t%s\x00", name, "blob")
	return stdIn.Bytes()
}
