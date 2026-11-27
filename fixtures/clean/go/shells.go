package main

import (
	"net/http"
	"os/exec"
)

func build(w http.ResponseWriter, r *http.Request, target string) {
	exec.CommandContext(r.Context(), "make", "--", target).Run()
	exec.Command("bash", "-lc", "make all").Run()
}
