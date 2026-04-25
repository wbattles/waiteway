package main

import (
	"strings"
	"testing"
)

func TestCompileConfigRejectsDuplicateRoutePathPrefixes(t *testing.T) {
	_, err := compileConfig(Config{
		Routes: []Route{
			{Name: "first", PathPrefix: "/example", Target: "https://example.com"},
			{Name: "second", PathPrefix: "/example", Target: "https://other-example.com"},
		},
	})
	if err == nil {
		t.Fatal("expected duplicate path prefix error")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected duplicate prefix error, got %v", err)
	}
}

func TestStoreAddRouteRejectsDuplicateRoutePathPrefixes(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if err := store.AddRoute(Route{Name: "first", PathPrefix: "/example", Target: "https://example.com"}); err != nil {
		t.Fatal(err)
	}

	err = store.AddRoute(Route{Name: "second", PathPrefix: "/example", Target: "https://other-example.com"})
	if err == nil {
		t.Fatal("expected duplicate path prefix error")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected duplicate prefix error, got %v", err)
	}
}

func TestStoreUpdateRouteRejectsDuplicateRoutePathPrefixes(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if err := store.AddRoute(Route{Name: "first", PathPrefix: "/example", Target: "https://example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddRoute(Route{Name: "second", PathPrefix: "/other", Target: "https://other-example.com"}); err != nil {
		t.Fatal(err)
	}

	err = store.UpdateRoute(1, Route{Name: "second", PathPrefix: "/example", Target: "https://other-example.com"})
	if err == nil {
		t.Fatal("expected duplicate path prefix error")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected duplicate prefix error, got %v", err)
	}
}

func TestStoreUpdateRouteAllowsSamePrefixOnSameRoute(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if err := store.AddRoute(Route{Name: "first", PathPrefix: "/example", Target: "https://example.com"}); err != nil {
		t.Fatal(err)
	}

	if err := store.UpdateRoute(0, Route{Name: "first-renamed", PathPrefix: "/example", Target: "https://example.com/v2"}); err != nil {
		t.Fatalf("updating route with its own prefix should succeed, got %v", err)
	}
}

func TestNormalizePathPrefixStripsTrailingSlashes(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"/", "/"},
		{"/api", "/api"},
		{"/api/", "/api"},
		{"/api///", "/api"},
		{"api", "/api"},
		{"api/", "/api"},
	}
	for _, tt := range tests {
		got := normalizePathPrefix(tt.input)
		if got != tt.want {
			t.Errorf("normalizePathPrefix(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestStoreUniqueIndexRejectsDuplicatePathPrefix(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if err := store.AddRoute(Route{Name: "first", PathPrefix: "/example", Target: "https://example.com"}); err != nil {
		t.Fatal(err)
	}

	// bypass the app-level check by inserting directly
	_, err = store.db.Exec(
		"INSERT INTO routes (name, path_prefix, target, position) VALUES (?, ?, ?, ?)",
		"sneaky", "/example", "https://sneaky.com", 99,
	)
	if err == nil {
		t.Fatal("expected unique index to reject duplicate path_prefix")
	}
}

func TestCompileConfigNormalizesBeforeDuplicateCheck(t *testing.T) {
	_, err := compileConfig(Config{
		Routes: []Route{
			{Name: "first", PathPrefix: "/example", Target: "https://example.com"},
			{Name: "second", PathPrefix: "/example/", Target: "https://other-example.com"},
		},
	})
	if err == nil {
		t.Fatal("expected trailing-slash duplicate to be caught after normalization")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected duplicate prefix error, got %v", err)
	}
}

func TestValidateRouteTarget(t *testing.T) {
	valid := []string{
		"http://example.com",
		"https://example.com",
		"https://example.com/path",
		"http://localhost:3000",
	}
	for _, target := range valid {
		if err := validateRouteTarget(target); err != nil {
			t.Errorf("expected %q to be valid, got %v", target, err)
		}
	}

	invalid := []string{
		"",               // empty
		"example.com",    // no scheme
		"://example.com", // missing scheme
		"https://",       // no host
		"not a url at all",
		"::::",
	}
	for _, target := range invalid {
		if err := validateRouteTarget(target); err == nil {
			t.Errorf("expected %q to be invalid", target)
		}
	}
}

func TestStoreAddRouteNormalizesBeforeDuplicateCheck(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if err := store.AddRoute(Route{Name: "first", PathPrefix: "/example", Target: "https://example.com"}); err != nil {
		t.Fatal(err)
	}

	err = store.AddRoute(Route{Name: "second", PathPrefix: "/example/", Target: "https://other-example.com"})
	if err == nil {
		t.Fatal("expected trailing-slash duplicate to be caught after normalization")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected duplicate prefix error, got %v", err)
	}
}
