package main

import _ "embed"

//go:embed templates/admin.html
var adminTemplate string

//go:embed templates/login.html
var loginTemplate string

//go:embed templates/admin_users.html
var usersAdminTemplate string

//go:embed templates/settings.html
var settingsTemplate string
