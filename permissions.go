package main

import (
	"database/sql"
	"net/http"
)

func (g *Gateway) requestUser(r *http.Request) (User, bool) {
	key := requestAPIKey(r)
	if key == "" {
		return User{}, false
	}
	user, err := g.store.FindUserByAPIKey(key)
	if err != nil && err != sql.ErrNoRows {
		return User{}, false
	}
	return user, err == nil
}
