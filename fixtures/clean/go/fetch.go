package main

import (
	"bytes"
	"fmt"
	"html"
	"net/http"
	"strings"

	"github.com/bradfitz/gomemcache/memcache"
)

func webhook(w http.ResponseWriter, r *http.Request, mc *memcache.Client) {
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://hooks.example.invalid/in", bytes.NewReader([]byte(r.FormValue("payload"))))
	http.DefaultClient.Do(req)
	http.Post("https://api.example.invalid/notes", "text/plain", strings.NewReader(r.FormValue("note")))
	mc.Get(r.URL.Query().Get("key"))
}

func echoBack(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(html.EscapeString(r.URL.Query().Get("msg"))))
	fmt.Fprintf(w, "<p>Hello %s</p>", html.EscapeString(r.FormValue("name")))
}
