package main

import (
	"errors"
	"testing"
)

func TestCreateUserRejectsUsernameWithSpaces(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if _, err := store.CreateUser("bad user", "pass", false); err == nil {
		t.Fatal("expected username with spaces to fail")
	}
}

func TestCreateUserSurfacesDuplicateUsernameError(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if _, err := store.CreateUser("alice", "pass", false); err != nil {
		t.Fatalf("first create failed: %v", err)
	}
	_, err = store.CreateUser("alice", "pass", false)
	if !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("expected ErrUsernameTaken, got %v", err)
	}
}
