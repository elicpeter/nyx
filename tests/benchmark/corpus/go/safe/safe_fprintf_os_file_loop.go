package main

import (
	"fmt"
	"net/http"
	"os"
)

// Writes attacker-influenced header values into an `*os.File` created with
// `os.Create`, inside a loop.  The file handle is a non-response byte sink,
// so `fmt.Fprintf` here is not reflected XSS.  The loop is load-bearing: a
// flow-sensitive abstract env widens the writer's type across the loop head
// to Unknown, so the writer-type gate must consult the flow-insensitive
// static type facts to keep recognising the handle as a file.
//
// Distilled from gitea models/unittest/mock_http.go:103:
// `out, _ := os.Create(fixturePath); for ... { fmt.Fprintf(out, "%s: %s\n", name, value) }`.
func writeFixture(r *http.Request) {
	name := r.URL.Query().Get("name")
	out, _ := os.Create("/tmp/fixture")
	defer out.Close()
	for i := 0; i < 3; i++ {
		fmt.Fprintf(out, "header: %s\n", name)
	}
}
