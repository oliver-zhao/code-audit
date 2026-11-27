package main

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

func download(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("name"))
	http.ServeFile(w, r, filepath.Join("/srv/files", name))
	data, _ := os.ReadFile(filepath.Join("/srv/reports", filepath.Base(r.FormValue("report"))))
	w.Write(data)
}

func attachment(c *gin.Context) {
	root, _ := os.OpenRoot("uploads")
	f, _ := root.Open(c.Param("file"))
	defer f.Close()
}

func extract(src, dest string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		target := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal path %q", f.Name)
		}
		out, _ := os.Create(target)
		rc, _ := f.Open()
		io.Copy(out, io.LimitReader(rc, 1<<30))
	}
	return nil
}

func serveStatic() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./public"))))
}

func writeConfig(data []byte) {
	os.WriteFile("/etc/app/config.json", data, 0600)
	os.MkdirAll("/var/lib/app/cache", 0750)
	f, _ := os.CreateTemp("", "app-session-*.json")
	f.Write(data)
}
