package main

import (
	"html/template"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("input")
	tmpl := template.Must(template.New("t").Parse("<div>{{.}}</div>"))
	tmpl.Execute(w, template.HTML(input))
}
