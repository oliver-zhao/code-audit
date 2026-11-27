package main

import (
	"net/http"
	"strings"
	"text/template"
)

func preview(w http.ResponseWriter, r *http.Request) {
	t, _ := template.New("p").Funcs(template.FuncMap{"upper": strings.ToUpper}).Parse(r.FormValue("body"))
	t.Execute(w, nil)
}
