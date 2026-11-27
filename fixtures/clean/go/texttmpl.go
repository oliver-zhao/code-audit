package main

import (
	"os"
	"text/template"
)

func renderConfig(values map[string]string) {
	t := template.Must(template.New("cfg").Parse("listen = {{.addr}}\n"))
	t.Execute(os.Stdout, values)
}
