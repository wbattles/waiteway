package main

import (
	"database/sql"
	"net/http"
	"strconv"
)

func teamIDsFromForm(r *http.Request, key string) []int {
	values := r.Form[key]
	ids := []int{}
	seen := map[int]struct{}{}
	for _, value := range values {
		id, err := strconv.Atoi(value)
		if err != nil || id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids
}

func (g *Gateway) userMatchesTeamIDs(user User, teamIDs []int) bool {
	if len(teamIDs) == 0 {
		return true
	}
	ok, err := g.store.UserInAnyTeam(user.ID, teamIDs)
	return err == nil && ok
}

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
