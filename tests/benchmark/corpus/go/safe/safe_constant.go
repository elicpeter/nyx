package main

import "os/exec"

func main() {
	exec.Command("echo", "health-ok").Run()
}
