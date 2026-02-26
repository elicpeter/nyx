package main

import (
	"fmt"
	"html/template"
	"net/http"
)

func unsafeHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}

func safeHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	tmpl := template.Must(template.New("hello").Parse("<h1>Hello {{.}}</h1>"))
	tmpl.Execute(w, name)
}
