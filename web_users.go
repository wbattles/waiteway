package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type appPageData struct {
	CurrentUser User
	IsAdmin     bool
}

type userCreateRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"is_admin"`
}

type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type adminPasswordChangeRequest struct {
	NewPassword string `json:"new_password"`
}

type teamRequest struct {
	Name    string `json:"name"`
	Acronym string `json:"acronym"`
	UserIDs []int  `json:"user_ids"`
}

type teamUpdateRequest struct {
	Name    *string `json:"name"`
	Acronym *string `json:"acronym"`
	UserIDs []int   `json:"user_ids"`
}

func (g *Gateway) handleUsersAdminPage(w http.ResponseWriter, r *http.Request) {
	user, ok := g.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !user.IsAdmin {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := g.usersTmpl.Execute(w, appPageData{CurrentUser: user, IsAdmin: user.IsAdmin}); err != nil {
		http.Error(w, "page render failed", http.StatusInternalServerError)
	}
}

func (g *Gateway) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	user, ok := g.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := g.settingsTmpl.Execute(w, appPageData{CurrentUser: user, IsAdmin: user.IsAdmin}); err != nil {
		http.Error(w, "page render failed", http.StatusInternalServerError)
	}
}

func (g *Gateway) handleAPI(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/api/current-user":
		g.handleAPICurrentUser(w, r)
	case path == "/api/users":
		g.handleAPIUsers(w, r)
	case path == "/api/me/password":
		g.handleAPIMyPassword(w, r)
	case path == "/api/me/api-keys":
		g.handleAPIMyAPIKeys(w, r)
	case strings.HasPrefix(path, "/api/me/api-keys/"):
		g.handleAPIMyAPIKeyByID(w, r)
	case path == "/api/admin/users":
		g.handleAPIAdminUsers(w, r)
	case strings.HasPrefix(path, "/api/admin/users/"):
		g.handleAPIAdminUserByID(w, r)
	case path == "/api/admin/teams":
		g.handleAPIAdminTeams(w, r)
	case strings.HasPrefix(path, "/api/admin/teams/"):
		g.handleAPIAdminTeamByID(w, r)
	case path == "/api/teams":
		g.handleAPITeams(w, r)
	case strings.HasPrefix(path, "/api/teams/") && strings.HasSuffix(path, "/users"):
		g.handleAPITeamUsers(w, r)
	case path == "/api/me/teams":
		g.handleAPIMyTeams(w, r)
	case strings.HasPrefix(path, "/api/me/teams/"):
		g.handleAPIMyTeamByID(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (g *Gateway) requireUser(w http.ResponseWriter, r *http.Request) (User, bool) {
	user, ok := g.currentUser(r)
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, "login required")
		return User{}, false
	}
	return user, true
}

func (g *Gateway) requireAdmin(w http.ResponseWriter, r *http.Request) (User, bool) {
	user, ok := g.requireUser(w, r)
	if !ok {
		return User{}, false
	}
	if !user.IsAdmin {
		writeAPIError(w, http.StatusForbidden, "admin access required")
		return User{}, false
	}
	return user, true
}

func (g *Gateway) handleAPICurrentUser(w http.ResponseWriter, r *http.Request) {
	user, ok := g.requireUser(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": user.ID, "username": user.Username, "is_admin": user.IsAdmin})
}

func (g *Gateway) handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := g.requireUser(w, r); !ok {
		return
	}
	users, err := g.store.ListUsers()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to load users")
		return
	}
	items := make([]map[string]any, 0, len(users))
	for _, user := range users {
		items = append(items, map[string]any{"id": user.ID, "username": user.Username, "is_admin": user.IsAdmin})
	}
	writeJSON(w, http.StatusOK, items)
}

func (g *Gateway) handleAPIMyPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := g.requireUser(w, r)
	if !ok {
		return
	}
	var req passwordChangeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !checkPassword(req.CurrentPassword, user.PasswordHash) {
		writeAPIError(w, http.StatusBadRequest, "current password is incorrect")
		return
	}
	if strings.TrimSpace(req.NewPassword) == "" {
		writeAPIError(w, http.StatusBadRequest, "new password is required")
		return
	}
	if err := g.store.UpdateUserPassword(user.ID, req.NewPassword); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to update password")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "password updated"})
}

func (g *Gateway) handleAPIMyAPIKeys(w http.ResponseWriter, r *http.Request) {
	user, ok := g.requireUser(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		keys, err := g.store.ListAPIKeysByUser(user.ID)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "failed to load api keys")
			return
		}
		items := make([]map[string]any, 0, len(keys))
		for _, key := range keys {
			masked := key.KeyPrefix
			if masked != "" {
				masked += "..."
			}
			items = append(items, map[string]any{"id": key.ID, "key": masked, "created_at": key.CreatedAt.Format(time.RFC3339)})
		}
		writeJSON(w, http.StatusOK, items)
	case http.MethodPost:
		rawKey, err := randomHex(32)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "failed to create api key")
			return
		}
		key, err := g.store.CreateAPIKey(user.ID, rawKey)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "failed to create api key")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": key.ID, "key": rawKey})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (g *Gateway) handleAPIMyAPIKeyByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := g.requireUser(w, r)
	if !ok {
		return
	}
	keyID, ok := parseTrailingID(w, r.URL.Path, "/api/me/api-keys/")
	if !ok {
		return
	}
	if err := g.store.DeleteAPIKeyForUser(keyID, user.ID); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to delete api key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "api key deleted"})
}

func (g *Gateway) handleAPIAdminUsers(w http.ResponseWriter, r *http.Request) {
	admin, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		users, err := g.store.ListUsers()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "failed to load users")
			return
		}
		items := make([]map[string]any, 0, len(users))
		for _, user := range users {
			items = append(items, map[string]any{
				"id": user.ID, "username": user.Username, "is_admin": user.IsAdmin, "created_at": user.CreatedAt.Format(time.RFC3339),
			})
		}
		writeJSON(w, http.StatusOK, items)
	case http.MethodPost:
		var req userCreateRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if len(strings.TrimSpace(req.Username)) > 15 {
			writeAPIError(w, http.StatusBadRequest, "username must be 15 characters or less")
			return
		}
		user, err := g.store.CreateUser(req.Username, req.Password, req.IsAdmin)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "failed to create user")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": user.ID, "username": user.Username, "is_admin": user.IsAdmin, "created_at": user.CreatedAt.Format(time.RFC3339), "created_by": admin.ID})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (g *Gateway) handleAPIAdminUserByID(w http.ResponseWriter, r *http.Request) {
	admin, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/users/")
	if strings.HasSuffix(path, "/password") {
		userID, err := strconv.Atoi(strings.TrimSuffix(path, "/password"))
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid user id")
			return
		}
		if r.Method != http.MethodPatch {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req adminPasswordChangeRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if strings.TrimSpace(req.NewPassword) == "" {
			writeAPIError(w, http.StatusBadRequest, "new password is required")
			return
		}
		targetUser, err := g.store.GetUserByID(userID)
		if err != nil {
			writeAPIError(w, http.StatusNotFound, "user not found")
			return
		}
		if targetUser.IsAdmin && targetUser.ID != admin.ID {
			writeAPIError(w, http.StatusForbidden, "cannot change another admin's password")
			return
		}
		if err := g.store.UpdateUserPassword(userID, req.NewPassword); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "failed to update password")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "password updated"})
		return
	}
	userID, err := strconv.Atoi(path)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if userID == admin.ID {
		writeAPIError(w, http.StatusBadRequest, "cannot delete yourself")
		return
	}
	if err := g.store.DeleteUser(userID); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to delete user")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "user deleted"})
}

func (g *Gateway) handleAPIAdminTeams(w http.ResponseWriter, r *http.Request) {
	admin, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		teams, err := g.store.ListTeamsForUser(admin)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "failed to load teams")
			return
		}
		writeJSON(w, http.StatusOK, serializeTeams(teams))
	case http.MethodPost:
		var req teamRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		team, err := g.store.CreateTeam(req.Name, req.Acronym, admin.ID, req.UserIDs)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, serializeTeam(team))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (g *Gateway) handleAPIAdminTeamByID(w http.ResponseWriter, r *http.Request) {
	admin, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	teamID, ok := parseTrailingID(w, r.URL.Path, "/api/admin/teams/")
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var req teamUpdateRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		team, err := g.store.UpdateTeam(teamID, req.Name, req.Acronym, req.UserIDs, req.UserIDs != nil, admin.ID)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, serializeTeam(team))
	case http.MethodDelete:
		if err := g.store.DeleteTeam(teamID); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "failed to delete team")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "team deleted"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (g *Gateway) handleAPITeams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := g.requireUser(w, r)
	if !ok {
		return
	}
	teams, err := g.store.ListTeamsForUser(user)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to load teams")
		return
	}
	writeJSON(w, http.StatusOK, serializeTeams(teams))
}

func (g *Gateway) handleAPITeamUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := g.requireUser(w, r)
	if !ok {
		return
	}
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/teams/")
	teamID, err := strconv.Atoi(strings.TrimSuffix(trimmed, "/users"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid team id")
		return
	}
	if !g.canManageTeam(user, teamID) {
		writeAPIError(w, http.StatusForbidden, "access denied")
		return
	}
	users, err := g.store.ListTeamUsers(teamID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to load team users")
		return
	}
	items := make([]map[string]any, 0, len(users))
	for _, member := range users {
		items = append(items, map[string]any{"id": member.ID, "username": member.Username})
	}
	writeJSON(w, http.StatusOK, items)
}

func (g *Gateway) handleAPIMyTeams(w http.ResponseWriter, r *http.Request) {
	user, ok := g.requireUser(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodPost:
		if !user.IsAdmin {
			writeAPIError(w, http.StatusForbidden, "admin access required")
			return
		}
		var req teamRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		team, err := g.store.CreateTeam(req.Name, req.Acronym, user.ID, req.UserIDs)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, serializeTeam(team))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (g *Gateway) handleAPIMyTeamByID(w http.ResponseWriter, r *http.Request) {
	user, ok := g.requireUser(w, r)
	if !ok {
		return
	}
	teamID, ok := parseTrailingID(w, r.URL.Path, "/api/me/teams/")
	if !ok {
		return
	}
	if !g.canManageTeam(user, teamID) {
		writeAPIError(w, http.StatusForbidden, "access denied")
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var req teamUpdateRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		team, err := g.store.UpdateTeam(teamID, req.Name, req.Acronym, req.UserIDs, req.UserIDs != nil, user.ID)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, serializeTeam(team))
	case http.MethodDelete:
		if err := g.store.DeleteTeam(teamID); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "failed to delete team")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "team deleted"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (g *Gateway) canManageTeam(user User, teamID int) bool {
	if user.IsAdmin {
		return true
	}
	team, err := g.store.GetTeam(teamID)
	if err != nil {
		return false
	}
	return team.CreatedByID == user.ID
}

func serializeTeams(teams []Team) []map[string]any {
	items := make([]map[string]any, 0, len(teams))
	for _, team := range teams {
		items = append(items, serializeTeam(team))
	}
	return items
}

func serializeTeam(team Team) map[string]any {
	users := make([]map[string]any, 0, len(team.Users))
	for _, user := range team.Users {
		users = append(users, map[string]any{"id": user.ID, "username": user.Username})
	}
	return map[string]any{
		"id":            team.ID,
		"name":          team.Name,
		"acronym":       team.Acronym,
		"created_by_id": team.CreatedByID,
		"user_count":    team.UserCount,
		"users":         users,
	}
}

func parseTrailingID(w http.ResponseWriter, path, prefix string) (int, bool) {
	value := strings.TrimPrefix(path, prefix)
	id, err := strconv.Atoi(value)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request")
		return false
	}
	return true
}

func writeAPIError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]string{"detail": detail})
}

func randomHex(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
