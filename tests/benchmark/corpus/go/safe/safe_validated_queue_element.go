package main

import (
	"net/http"
	"os/exec"
	"strings"
)

// validate strips shell metacharacters; the returned string is safe
// to pass to exec.Command.  Modeled as a sanitiser by the engine.
func validate(s string) string {
	return strings.ReplaceAll(s, ";", "")
}

func handler(w http.ResponseWriter, r *http.Request) {
	cmds := []string{}
	cmds = append(cmds, validate(r.URL.Query().Get("cmd")))
	// Index-read on a slice that only ever received validated values.
	// Exercises the W4 cell-shape change: validated_must on `cmds`'s
	// ELEM cell must AND-propagate through the W5 `__index_get__`
	// synth so the sink sees a sanitised value.
	_ = exec.Command(cmds[0]).Run()
}
