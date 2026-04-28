// CVE Hunt Session 2 regression — Go path traversal via `os.Remove`.
// Real-world Go path-traversal CVEs (Owncast CVE-2024-31450 emoji delete)
// sink into mutating filesystem helpers — `os.Remove`, `os.WriteFile`,
// `os.RemoveAll` — not the read-side `os.Open` / `os.ReadFile` family the
// Go ruleset previously covered. Joining a directory base to an HTTP-
// supplied filename and forwarding to `os.Remove` is a generic pattern
// across Go HTTP CRUD APIs.
package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	target := filepath.Join("data/uploads", name)
	os.Remove(target)
	_ = w
}
