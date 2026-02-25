package main

import (
	"fmt"
	"os"
	"os/exec"
	"html"
)

func getEnv() string {
	return os.Getenv("APP_SECRET")
}

func sanitizeHTML(input string) string {
	return html.EscapeString(input)
}

func runCommand(cmd string) {
	exec.Command("sh", "-c", cmd).Run()
}

func safeFlow() {
	val := getEnv()
	clean := sanitizeHTML(val)
	fmt.Println(clean)
}

func unsafeFlow() {
	val := getEnv()
	runCommand(val)
}

func main() {
	safeFlow()
	unsafeFlow()
}
