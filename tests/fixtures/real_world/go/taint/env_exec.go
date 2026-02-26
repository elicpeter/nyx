package main

import (
	"os"
	"os/exec"
)

func main() {
	cmd := os.Getenv("USER_CMD")
	exec.Command("sh", "-c", cmd).Run()
}
