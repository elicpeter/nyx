package main

import (
	"net/http"
	"os"
)

func main() {
	url := os.Getenv("TARGET_URL")
	http.Get(url)
}
