package main

import (
	"context"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	http.DefaultClient.Do(req)
}
