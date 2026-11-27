package main

import (
	"html/template"
	"net/http"
	"strings"
)

const previewPage = "<p>{{upper .}}</p>"

func preview(w http.ResponseWriter, r *http.Request) {
	t, _ := template.New("p").Funcs(template.FuncMap{"upper": strings.ToUpper}).Parse(previewPage)
	t.Execute(w, r.FormValue("body"))
}
