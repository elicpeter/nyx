// go-safe-014: direct-return path sanitiser using strings.Contains/HasPrefix.
package main

import (
	"io/ioutil"
	"net/http"
	"strings"
)

func sanitizePath(s string) string {
	if strings.Contains(s, "..") || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "\\") {
		return ""
	}
	return s
}

func handler(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("path")
	safe := sanitizePath(raw)
	_, _ = ioutil.ReadFile(safe)
}
