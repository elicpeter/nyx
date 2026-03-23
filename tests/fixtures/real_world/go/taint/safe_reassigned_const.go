package main

import (
	"os"
	"os/exec"
)

func main() {
	cmd := os.Getenv("CMD")
	cmd = "safe"
	exec.Command("sh", "-c", cmd)
}
