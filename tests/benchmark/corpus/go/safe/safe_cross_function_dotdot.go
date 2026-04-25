// go-safe-016: cross-function bool-returning validator with rejection.
package main

import (
	"io/ioutil"
	"net/http"
	"strings"
)

func validateNoDotdot(s string) bool {
	return !strings.Contains(s, "..") && !strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "\\")
}

func handler(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("path")
	if !validateNoDotdot(raw) {
		return
	}
	_, _ = ioutil.ReadFile(raw)
}
