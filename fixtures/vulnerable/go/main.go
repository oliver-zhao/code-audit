package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	name := r.URL.Query().Get("name")
	db.Query("SELECT * FROM users WHERE name = '" + r.URL.Query().Get("name") + "'")
	exec.Command("sh", "-c", "ls "+name)
	os.Open("/data/" + r.URL.Query().Get("file"))
	_ = md5.New()
	resetToken := rand.Intn(1000000); _ = resetToken
	http.Get(name)
	_ = &tls.Config{InsecureSkipVerify: true}
}
