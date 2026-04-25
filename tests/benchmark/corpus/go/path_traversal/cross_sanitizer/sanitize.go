package main

import "html"

func SanitizeHTML(s string) string {
	return html.EscapeString(s)
}
