package main

import (
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
