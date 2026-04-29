// CVE Hunt Session 2 regression — negative pair to ssrf_default_client_get.go.
// Hard-coded URL handed to `http.DefaultClient.Get`; no taint reaches the
// sink. Pin so a future overshoot of the new SSRF matcher (`http.DefaultClient.*`)
// can't quietly start firing on safe constant-URL helper code.
package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	if !is_authenticated(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	http.DefaultClient.Get("https://api.internal.example.com/health")
	_ = w
}

func is_authenticated(r *http.Request) bool {
	return r.Header.Get("Authorization") != ""
}
