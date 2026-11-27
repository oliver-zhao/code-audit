package main

import (
	"net/http"
	"os"
	"os/exec"
)

func build(w http.ResponseWriter, r *http.Request, target string) {
	exec.CommandContext(r.Context(), "sh", "-c", "make "+target).Run()
	exec.Command("bash", "-lc", makeLine(target)).Run()
	exec.Command("/usr/bin/env", "bash", "-c", target).Run()
	exec.Command(os.Getenv("SHELL"), "-c", target).Run()
	exec.CommandContext(r.Context(), "git", "fetch", r.FormValue("remote")).Run()
}

func makeLine(t string) string { return "make " + t }
