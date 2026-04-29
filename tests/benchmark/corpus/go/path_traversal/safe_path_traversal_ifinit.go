// CVE Hunt Session 4 regression — Go if-init taint, sanitized counterpart.
// Same shape as `path_traversal_ifinit.go` but the user-supplied filename
// is cleansed via `filepath.Base` (which is in the Go sanitizer set with
// `Cap::FILE_IO`) before being joined into the target path. The handler
// also runs an auth check so the unrelated `state-unauthed-access` rule
// does not fire — keeps this fixture as a clean negative for path-trav.
package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	if !is_authenticated(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	if name := r.URL.Query().Get("name"); name != "" {
		safe := filepath.Base(name)
		target := filepath.Join("data/uploads", safe)
		os.Remove(target)
	}
	_ = w
}

func is_authenticated(r *http.Request) bool {
	return r.Header.Get("Authorization") != ""
}
