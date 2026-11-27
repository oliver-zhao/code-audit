package main

import (
	"html/template"
	"net/http"

	"github.com/rs/cors"
)

func greet(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("page").Parse("<p>{{.}}</p>"))
	tmpl.Execute(w, template.HTML(r.URL.Query().Get("msg")))
}

func corsHandler(h http.Handler) http.Handler {
	return cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
	}).Handler(h)
}

func withCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func setSession(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    value,
		Secure:   false,
		HttpOnly: false,
		SameSite: http.SameSiteNoneMode,
	})
}
