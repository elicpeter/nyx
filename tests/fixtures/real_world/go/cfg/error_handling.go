package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
)

func handleRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Command string `json:"command"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		fmt.Println("bad request")
		// falls through!
	}

	cmd := exec.Command("sh", "-c", req.Command)
	cmd.Run()
}

func handleRequestSafe(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Command string `json:"command"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Bad request", 400)
		return
	}

	cmd := exec.Command("sh", "-c", req.Command)
	cmd.Run()
}
