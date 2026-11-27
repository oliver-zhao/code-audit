package main

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
)

func ping(w http.ResponseWriter, r *http.Request) {
	out, _ := exec.Command("ping", "-c", "1", r.URL.Query().Get("host")).Output()
	w.Write(out)
}

func archive(ctx context.Context, dir string) {
	exec.CommandContext(ctx, "bash", "-c", fmt.Sprintf("tar czf /backup/out.tgz %s", dir)).Run()
	exec.Command("cmd", "/C", "dir "+dir).Run()
}

func runHook(script string) {
	exec.Command("/bin/sh", "-c", script).Run()
}

func runTool(tool string, args []string) {
	exec.Command(tool, args...).Run()
}
