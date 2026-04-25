package main

import "os/exec"

// runCommand executes an arbitrary shell command supplied by the caller.
//
// SINK: exec.Command with a user-controlled first argument.
// This function is called from handler.go with an unsanitised HTTP parameter.
func runCommand(cmd string) {
	exec.Command("sh", "-c", cmd).Run() //nolint
}
