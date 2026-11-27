package main

import (
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var allowedHosts = map[string]bool{"api.example.invalid": true}

func proxy(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.Query().Get("url"))
	if err != nil || !allowedHosts[u.Hostname()] {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	resp, _ := http.Get("https://api.example.invalid/v1/status")
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func login(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/home", http.StatusFound)
}

func tlsConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: false}
}

func sshConfig() (*ssh.ClientConfig, error) {
	cb, err := knownhosts.New("/etc/ssh/ssh_known_hosts")
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{User: "deploy", HostKeyCallback: cb}, nil
}

type Job struct{ Name string }

func submit(w http.ResponseWriter, r *http.Request) {
	var job Job
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&job)
	n, _ := strconv.ParseInt(r.FormValue("n"), 10, 32)
	var small int32 = int32(n)
	_ = small
}

func unpack(src *os.File, dst *os.File) {
	gz, _ := gzip.NewReader(src)
	io.Copy(dst, io.LimitReader(gz, 1<<30))
}

func serve() {
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy", proxy)
	srv := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	srv.ListenAndServe()
}
