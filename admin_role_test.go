package main

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSetUserAdminRefusesLastAdminDemotion(t *testing.T) {
	gw, sessionID := testAdminGatewayWithSession(t, true)

	req := httptest.NewRequest(http.MethodPatch, "/api/admin/users/1/admin",
		strings.NewReader(`{"is_admin": false}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "waiteway_session", Value: sessionID})
	rec := httptest.NewRecorder()

	gw.adminHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPromoteAndDemoteUser(t *testing.T) {
	gw, sessionID := testAdminGatewayWithSession(t, true)
	other, err := gw.store.CreateUser("bob", "pw", false)
	if err != nil {
		t.Fatal(err)
	}

	patch := func(body string) int {
		req := httptest.NewRequest(http.MethodPatch,
			"/api/admin/users/"+strconv.Itoa(other.ID)+"/admin",
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "waiteway_session", Value: sessionID})
		rec := httptest.NewRecorder()
		gw.adminHandler().ServeHTTP(rec, req)
		return rec.Code
	}

	if code := patch(`{"is_admin": true}`); code != http.StatusOK {
		t.Fatalf("promote failed: %d", code)
	}
	user, _ := gw.store.GetUserByID(other.ID)
	if !user.IsAdmin {
		t.Fatal("expected user to be admin")
	}
	if code := patch(`{"is_admin": false}`); code != http.StatusOK {
		t.Fatalf("demote failed: %d", code)
	}
	user, _ = gw.store.GetUserByID(other.ID)
	if user.IsAdmin {
		t.Fatal("expected user to be demoted")
	}
}

func TestExpiredSessionIsRejected(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	user, err := store.CreateUser("alice", "pass", false)
	if err != nil {
		t.Fatal(err)
	}

	// Insert an expired session directly so we can drive UserBySessionID.
	old := time.Now().UTC().Add(-2 * sessionMaxAge).Format(time.RFC3339Nano)
	if _, err := store.db.Exec(
		"INSERT INTO sessions (id, created_at, user_id) VALUES (?, ?, ?)",
		"old-session", old, user.ID,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := store.UserBySessionID("old-session"); err == nil {
		t.Fatal("expected expired session to be rejected")
	}
}

func TestCurrentUserPurgesExpiredSessions(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	user, err := store.CreateUser("alice", "pass", false)
	if err != nil {
		t.Fatal(err)
	}

	old := time.Now().UTC().Add(-2 * sessionMaxAge).Format(time.RFC3339Nano)
	if _, err := store.db.Exec(
		"INSERT INTO sessions (id, created_at, user_id) VALUES (?, ?, ?)",
		"old-session", old, user.ID,
	); err != nil {
		t.Fatal(err)
	}

	gw, err := newGateway(store, Config{LogLimit: 10, Routes: []Route{{Name: "test", PathPrefix: "/test", Target: "http://localhost:3000"}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gw.Close)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "waiteway_session", Value: "old-session"})
	if _, ok := gw.currentUser(req); ok {
		t.Fatal("expected expired session to fail")
	}

	var count int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = ?", "old-session").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("expected expired session to be purged")
	}
}

func TestLoginSetsSessionCookieLifetime(t *testing.T) {
	gw, _ := testAdminGatewayWithSession(t, true)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=user&password=pass"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	gw.adminHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie")
	}
	var session *http.Cookie
	for _, c := range cookies {
		if c.Name == "waiteway_session" {
			session = c
			break
		}
	}
	if session == nil {
		t.Fatal("expected waiteway_session cookie")
	}
	if session.MaxAge <= 0 {
		t.Fatal("expected cookie max age")
	}
	if session.Expires.IsZero() {
		t.Fatal("expected cookie expiry")
	}
	if session.Secure {
		t.Fatal("expected non-secure cookie for plain http request")
	}
	if !session.HttpOnly {
		t.Fatal("expected httpOnly cookie")
	}
}

func TestLoginSetsSecureCookieForHTTPS(t *testing.T) {
	gw, _ := testAdminGatewayWithSession(t, true)

	req := httptest.NewRequest(http.MethodPost, "https://example.com/login", strings.NewReader("username=user&password=pass"))
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	gw.adminHandler().ServeHTTP(rec, req)

	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "waiteway_session" {
			session = c
			break
		}
	}
	if session == nil {
		t.Fatal("expected waiteway_session cookie")
	}
	if !session.Secure {
		t.Fatal("expected secure cookie for https request")
	}
}

func TestMyPasswordChangeRevokesSessions(t *testing.T) {
	gw, sessionID := testAdminGatewayWithSession(t, false)

	req := httptest.NewRequest(http.MethodPatch, "/api/me/password", strings.NewReader(`{"current_password":"pass","new_password":"next"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "waiteway_session", Value: sessionID})
	rec := httptest.NewRecorder()

	gw.adminHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := gw.store.UserBySessionID(sessionID); err == nil {
		t.Fatal("expected session to be revoked")
	}
}

func TestAdminPasswordResetRevokesTargetSessions(t *testing.T) {
	gw, adminSession := testAdminGatewayWithSession(t, true)
	target, err := gw.store.CreateUser("jane", "pass", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := gw.store.AddUserSession("target-session", target.ID); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPatch, "/api/admin/users/"+strconv.Itoa(target.ID)+"/password", strings.NewReader(`{"new_password":"next"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "waiteway_session", Value: adminSession})
	rec := httptest.NewRecorder()

	gw.adminHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := gw.store.UserBySessionID("target-session"); err == nil {
		t.Fatal("expected target session to be revoked")
	}
}

func TestCreateAPIKeyRespectsPerUserLimit(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	user, err := store.CreateUser("alice", "pass", false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxAPIKeysPerUser; i++ {
		if _, err := store.CreateAPIKey(user.ID, "key-"+strconv.Itoa(i)); err != nil {
			t.Fatalf("create key %d failed: %v", i, err)
		}
	}
	if _, err := store.CreateAPIKey(user.ID, "overflow"); !errors.Is(err, ErrAPIKeyLimitReached) {
		t.Fatalf("expected ErrAPIKeyLimitReached, got %v", err)
	}
}
