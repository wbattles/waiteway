package main

import _ "embed"

//go:embed templates/admin.html
var adminTemplate string

//go:embed templates/login.html
var loginTemplate string
