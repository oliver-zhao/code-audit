package main

import "github.com/rs/cors"

var trusted = map[string]bool{"https://app.example.invalid": true}

var apiCORS = cors.New(cors.Options{
	AllowOriginFunc:  func(origin string) bool { return trusted[origin] },
	AllowCredentials: true,
})
