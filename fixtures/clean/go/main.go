package main

import (
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"net/http"
	"os"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	name := r.URL.Query().Get("name")
	db.Query("SELECT * FROM users WHERE name = $1", name)
	exec.Command("ls", "-l")
	os.Open("/data/static.txt")
	_ = sha256.New()
	_, _ = crand.Read(make([]byte, 16))
	http.Get("https://example.invalid/api")
	_ = &tls.Config{InsecureSkipVerify: false}
}
