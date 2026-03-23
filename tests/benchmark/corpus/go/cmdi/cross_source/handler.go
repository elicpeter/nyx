package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := GetUserInput(r)
	exec.Command("sh", "-c", cmd).Run()
}
