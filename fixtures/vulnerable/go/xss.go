package main

import "html/template"

// The fixture lacked a template.HTML sink; this seed gives the Go template rule
// a real line to match. Marking request data as safe HTML enables XSS.
func renderTemplate(name string) template.HTML {
	return template.HTML(name)
}