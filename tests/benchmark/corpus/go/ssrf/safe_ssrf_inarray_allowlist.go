// Synthetic precision guard (CVE-2026-21859 shape).
//
// An outbound request whose URL is confined to a fixed allowlist via a
// value-first membership function `InArray(uri, links)` is safe, even when the
// URL reaches the sink through a base64/split-derived copy (`uri := parts[1]`,
// an elided container index). Pins two invariants:
//   1. camelCase `InArray(value, list)` is recognised as an allowlist guard;
//   2. the allowlist narrowing is copy-alias-aware, so the value surfacing
//      under the copy-source name (`parts`) is still treated as validated.
package main

import (
	"encoding/base64"
	"net/http"
	"strings"
)

var stored = map[string][]string{}

func getAssets(id string) ([]string, error) { return stored[id], nil }

func InArray(k string, arr []string) bool {
	for _, v := range arr {
		if strings.EqualFold(v, k) {
			return true
		}
	}
	return false
}

func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	encoded := r.URL.Query().Get("data")
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	parts := strings.SplitN(string(decoded), ":", 2)
	id := parts[0]
	uri := parts[1]
	links, _ := getAssets(id)
	if !InArray(uri, links) {
		return
	}
	resp, _ := http.Get(uri)
	_ = resp
}
