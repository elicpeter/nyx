package main

import "net/http"

func main() {
	http.Get("https://api.example.com/health")
}
