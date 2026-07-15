package main

import "net/http"

// A registered endpoint. Vulnerability modules call register() from their
// init() functions, so main.go auto-discovers them with no central wiring to
// edit — the Go analogue of the Flask/Express/Spring auto-registration used by
// the other apps in this lab.
type route struct {
	pattern string // Go 1.22 ServeMux pattern, e.g. "GET /injection/sql/login"
	desc    string
	handler http.HandlerFunc
}

var routes []route

func register(pattern, desc string, h http.HandlerFunc) {
	routes = append(routes, route{pattern, desc, h})
}
