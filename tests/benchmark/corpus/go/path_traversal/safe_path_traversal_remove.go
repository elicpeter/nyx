// CVE Hunt Session 2 regression — negative pair to path_traversal_remove.go.
// `filepath.Base` strips any traversal segments before the join, so the
// resolved `target` is a child of `data/uploads`. Pin so the FILE_IO sink
// matcher additions don't start firing on properly-cleansed flows.
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
	name := filepath.Base(r.URL.Query().Get("name"))
	target := filepath.Join("data/uploads", name)
	os.Remove(target)
	_ = w
}

func is_authenticated(r *http.Request) bool {
	return r.Header.Get("Authorization") != ""
}
