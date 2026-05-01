package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleAdminAllowsNonAdminReadOnlyView(t *testing.T) {
	gw, sessionID := testAdminGatewayWithSession(t, false)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "waiteway_session", Value: sessionID})
	rec := httptest.NewRecorder()

	gw.adminHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestHandleAdminPostRejectsNonAdminWrites(t *testing.T) {
	gw, sessionID := testAdminGatewayWithSession(t, false)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("action=add_policy"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "waiteway_session", Value: sessionID})
	rec := httptest.NewRecorder()

	gw.adminHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func testAdminGatewayWithSession(t *testing.T, isAdmin bool) (*Gateway, string) {
	t.Helper()

	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	config := Config{
		LogLimit: 10,
		Routes: []Route{{
			Name:       "test",
			PathPrefix: "/test",
			Target:     "http://localhost:3000",
		}},
	}

	user, err := store.CreateUser("user", "pass", isAdmin)
	if err != nil {
		t.Fatal(err)
	}

	gw, err := newGateway(store, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gw.Close)

	sessionID := "session-1"
	if err := store.AddUserSession(sessionID, user.ID); err != nil {
		t.Fatal(err)
	}

	return gw, sessionID
}
