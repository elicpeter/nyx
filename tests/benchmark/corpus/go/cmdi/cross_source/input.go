package main

import "net/http"

func GetUserInput(r *http.Request) string {
	return r.URL.Query().Get("cmd")
}
