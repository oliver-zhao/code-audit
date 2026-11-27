package main

import (
	"context"
	"net"
	"net/http"
	"os/exec"
)

func ping(w http.ResponseWriter, r *http.Request) {
	ip := net.ParseIP(r.URL.Query().Get("host"))
	if ip == nil {
		http.Error(w, "bad host", http.StatusBadRequest)
		return
	}
	out, _ := exec.Command("ping", "-c", "1", "--", ip.String()).Output()
	w.Write(out)
}

func archive(ctx context.Context, dir string) {
	exec.CommandContext(ctx, "tar", "czf", "/backup/out.tgz", "--", dir).Run()
	exec.Command("sh", "-c", "ls -l /backup").Run()
}
