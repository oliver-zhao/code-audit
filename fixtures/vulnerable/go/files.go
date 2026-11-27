package main

import (
	"archive/zip"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func download(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join("/srv/files", r.URL.Query().Get("name")))
	data, _ := os.ReadFile("/srv/reports/" + r.FormValue("report"))
	w.Write(data)
}

func attachment(c *gin.Context) {
	c.File(filepath.Join("uploads", c.Param("file")))
}

func extract(src, dest string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		target := filepath.Join(dest, f.Name)
		out, _ := os.Create(target)
		rc, _ := f.Open()
		io.Copy(out, rc)
	}
	return nil
}

func exposeRoot() {
	http.Handle("/", http.FileServer(http.Dir("/")))
}

func writeConfig(data []byte) {
	os.WriteFile("/etc/app/config.json", data, 0777)
	os.Chmod("/var/lib/app/state.db", 0666)
	os.MkdirAll("/var/lib/app/cache", 0777)
	os.WriteFile("/tmp/app-session.json", data, 0600)
}

func openUserFile(base, name string) {
	os.Open(base + "/" + name)
}
