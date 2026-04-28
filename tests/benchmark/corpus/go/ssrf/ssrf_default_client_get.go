// CVE Hunt Session 2 regression — Go SSRF via `http.DefaultClient.Get`.
// Real-world Go SSRF (Owncast CVE-2023-3188) uses the package-level
// shared client rather than the bare `http.Get` helper. A previous label
// rule that only included `http.Get` missed every CVE in this shape.
package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	http.DefaultClient.Get(url)
}
