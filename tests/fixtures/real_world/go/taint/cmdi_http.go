package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("ping", "-c", "1", host)
	output, _ := cmd.Output()
	fmt.Fprintf(w, "%s", output)
}

func unsafePing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	output, _ := cmd.Output()
	fmt.Fprintf(w, "%s", output)
}

func main() {
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/unsafe-ping", unsafePing)
	http.ListenAndServe(":8080", nil)
}
