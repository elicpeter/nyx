package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmds := []string{}
	// No validate() call — tainted user input flows directly into the
	// container's ELEM cell, then back out via the W5 `__index_get__`
	// synth into exec.Command.
	cmds = append(cmds, r.URL.Query().Get("cmd"))
	_ = exec.Command(cmds[0]).Run()
}
