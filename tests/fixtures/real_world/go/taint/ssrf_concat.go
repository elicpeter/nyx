package main

import (
    "net/http"
    "os"
)

func main() {
    host := os.Getenv("TARGET_HOST")
    url := "http://" + host + "/api/data"
    http.Get(url)
}
