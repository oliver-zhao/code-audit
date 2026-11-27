package main

import (
	"net/http"
	"text/template"
)

func render(w http.ResponseWriter, r *http.Request) {
	t, _ := template.New("x").Parse(r.FormValue("tpl"))
	t.Execute(w, nil)
}
