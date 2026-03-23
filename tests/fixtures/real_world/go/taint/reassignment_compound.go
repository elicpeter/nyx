package main

import (
	"os"
	"os/exec"
)

func main() {
	cmd := os.Getenv("CMD")
	cmd = cmd + " suffix"
	exec.Command("sh", "-c", cmd)
}
