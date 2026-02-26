package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

func runWithTimeout(command string, timeout time.Duration) (string, error) {
	cmd := exec.Command("sh", "-c", command)

	done := make(chan string)
	go func() {
		output, _ := cmd.Output()
		done <- string(output)
	}()

	select {
	case result := <-done:
		return result, nil
	case <-time.After(timeout):
		cmd.Process.Kill()
		return "", fmt.Errorf("timeout")
	}
}

func main() {
	cmd := os.Getenv("CMD")
	result, _ := runWithTimeout(cmd, 5*time.Second)
	fmt.Println(result)
}
