package main

import (
	"net/http"
	_ "net/http/pprof"
)

func debugServer() {
	go http.ListenAndServe("localhost:6060", nil)
}
