// go-safe-015: Go-natural `(string, error)` tuple-returning sanitiser.
package main

import (
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
)

func sanitizePath(s string) (string, error) {
	if strings.Contains(s, "..") || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "\\") {
		return "", errors.New("invalid path")
	}
	return s, nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("path")
	safe, err := sanitizePath(raw)
	if err != nil {
		return
	}
	_, _ = ioutil.ReadFile(safe)
}
