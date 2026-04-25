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
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := g.requireAdmin(w, r); !ok {
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
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
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
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (g *Gateway) handleAPIMyAPIKeyByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
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
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
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
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
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
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
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
