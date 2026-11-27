package main

import (
	"fmt"
	"net/http"
)

func webhook(w http.ResponseWriter, r *http.Request) {
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, r.FormValue("callback"), nil)
	http.DefaultClient.Do(req)
	http.Get(fmt.Sprintf("http://%s/health", r.FormValue("host")))
}

func status(host string) {
	http.Get("http://" + host + "/status")
	http.Get(fmt.Sprintf("https://%s/metrics", host))
}

func echoBack(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(r.URL.Query().Get("msg")))
	fmt.Fprintf(w, "<p>Hello %s</p>", r.FormValue("name"))
}
