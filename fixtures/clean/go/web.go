package main

import (
	"html/template"
	"net/http"

	"github.com/rs/cors"
)

var page = template.Must(template.New("page").Parse("<p>{{.}}</p>"))

func greet(w http.ResponseWriter, r *http.Request) {
	page.Execute(w, r.URL.Query().Get("msg"))
	_ = template.HTML("<b>static</b>")
}

func corsHandler(h http.Handler) http.Handler {
	return cors.New(cors.Options{
		AllowedOrigins:   []string{"https://app.example.invalid"},
		AllowCredentials: true,
	}).Handler(h)
}

var trustedOrigins = map[string]bool{"https://app.example.invalid": true}

func withCORS(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); trustedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
}

func setSession(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    value,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
