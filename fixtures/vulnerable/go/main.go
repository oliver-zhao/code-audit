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
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	exec.Command("sh", "-c", "ls "+name)
	os.Open("/data/" + name)
	_ = md5.New()
	_ = rand.Intn(100)
	http.Get(name)
	_ = &tls.Config{InsecureSkipVerify: true}
}
