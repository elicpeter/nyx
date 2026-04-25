// URL encoding at SQL sink — wrong-type sanitizer (Go).
//
// url.QueryEscape is registered as Sanitizer(URL_ENCODE) in the Go label
// rules, but db.Query is a Sink(SQL_QUERY). URL encoding does NOT
// neutralise SQL injection, so the engine still emits a finding.
//
// Symex should classify url.QueryEscape as TransformKind::UrlEncode and
// produce a renderable witness that names the transform — confirming the
// new Go transform classifier is wired through to witness rendering.

package main

import (
	"database/sql"
	"net/http"
	"net/url"
)

func handler(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("q")
	encoded := url.QueryEscape(userInput)
	db, _ := sql.Open("sqlite3", "test.db")
	db.Query("SELECT * FROM items WHERE name = '" + encoded + "'")
}
