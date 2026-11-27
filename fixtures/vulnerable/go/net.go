package main

import (
	"compress/gzip"
	"crypto/tls"
	"encoding/gob"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"

	"golang.org/x/crypto/ssh"
)

func proxy(w http.ResponseWriter, r *http.Request) {
	resp, _ := http.Get(r.URL.Query().Get("url"))
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func fetch(target string) {
	req, _ := http.NewRequest("GET", target, nil)
	http.DefaultClient.Do(req)
}

func login(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.FormValue("next"), http.StatusFound)
}

func tlsConfigs() []*tls.Config {
	return []*tls.Config{
		{MinVersion: tls.VersionTLS10},
		{CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}},
	}
}

func sshConfig() *ssh.ClientConfig {
	return &ssh.ClientConfig{User: "deploy", HostKeyCallback: ssh.InsecureIgnoreHostKey()}
}

type Job struct{ Name string }

func submit(w http.ResponseWriter, r *http.Request) {
	var job Job
	gob.NewDecoder(r.Body).Decode(&job)
	n, _ := strconv.Atoi(r.FormValue("n"))
	var small int32 = int32(n)
	_ = small
}

func unpack(src *os.File, dst *os.File) {
	gz, _ := gzip.NewReader(src)
	io.Copy(dst, gz)
}

func main() {
	http.HandleFunc("/proxy", proxy)
	http.ListenAndServe(":8080", nil)
}
