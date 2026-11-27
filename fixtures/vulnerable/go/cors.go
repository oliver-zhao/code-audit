package main

import "github.com/rs/cors"

var apiCORS = cors.New(cors.Options{
	AllowOriginFunc:  func(origin string) bool { return true },
	AllowCredentials: true,
})
