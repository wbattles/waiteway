package main

import (
	"strings"
	"testing"
)

func TestStoreAddPolicyRejectsDuplicateName(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if err := store.AddPolicy(Policy{Name: "shared"}); err != nil {
		t.Fatal(err)
	}

	err = store.AddPolicy(Policy{Name: "shared"})
	if err == nil {
		t.Fatal("expected duplicate policy name error")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected friendly duplicate error, got %v", err)
	}
}

func TestStoreUpdatePolicyRejectsDuplicateName(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if err := store.AddPolicy(Policy{Name: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddPolicy(Policy{Name: "second"}); err != nil {
		t.Fatal(err)
	}

	err = store.UpdatePolicy(1, Policy{Name: "first"})
	if err == nil {
		t.Fatal("expected duplicate policy name error")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected friendly duplicate error, got %v", err)
	}
}

func TestStoreUpdatePolicyAllowsSameNameOnSamePolicy(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if err := store.AddPolicy(Policy{Name: "first"}); err != nil {
		t.Fatal(err)
	}

	if err := store.UpdatePolicy(0, Policy{Name: "first", RetryCount: 3}); err != nil {
		t.Fatalf("updating policy without changing its name should succeed, got %v", err)
	}
}

func TestRouteMatchesPath(t *testing.T) {
	tests := []struct {
		prefix string
		path   string
		want   bool
	}{
		{"/", "/", true},
		{"/", "/anything", true},
		{"/api", "/api", true},
		{"/api", "/api/users", true},
		{"/api", "/apifoo", false}, // segment boundary required
		{"/api", "/other", false},
		{"/api/v1", "/api/v1/users", true},
		{"/api/v1", "/api/v2", false},
	}
	for _, tt := range tests {
		got := routeMatchesPath(tt.prefix, tt.path)
		if got != tt.want {
			t.Errorf("routeMatchesPath(%q, %q) = %v, want %v", tt.prefix, tt.path, got, tt.want)
		}
	}
}

func TestStoreAddPolicyNormalizesRewritePathPrefix(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if err := store.AddPolicy(Policy{Name: "rewrite", RewritePathPrefix: "api/v1/"}); err != nil {
		t.Fatal(err)
	}

	policies, err := store.ListPolicies()
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0].RewritePathPrefix != "/api/v1" {
		t.Errorf("expected normalized rewrite prefix /api/v1, got %q", policies[0].RewritePathPrefix)
	}
}

func TestStoreUpdatePolicyNormalizesRewritePathPrefix(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if err := store.AddPolicy(Policy{Name: "rewrite", RewritePathPrefix: "/api"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdatePolicy(0, Policy{Name: "rewrite", RewritePathPrefix: "/api/v2/"}); err != nil {
		t.Fatal(err)
	}

	policies, err := store.ListPolicies()
	if err != nil {
		t.Fatal(err)
	}
	if policies[0].RewritePathPrefix != "/api/v2" {
		t.Errorf("expected normalized rewrite prefix /api/v2, got %q", policies[0].RewritePathPrefix)
	}
}

func TestCompilePolicyNormalizesRewritePathPrefix(t *testing.T) {
	compiled, err := compilePolicy(Policy{Name: "rewrite", RewritePathPrefix: "api/"})
	if err != nil {
		t.Fatal(err)
	}
	if compiled.RewritePathPrefix != "/api" {
		t.Errorf("expected normalized rewrite prefix /api, got %q", compiled.RewritePathPrefix)
	}
}

func TestStoreDeleteAllSessions(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if err := store.AddSession("one"); err != nil {
		t.Fatal(err)
	}
	if err := store.AddSession("two"); err != nil {
		t.Fatal(err)
	}
	if !store.HasSession("one") || !store.HasSession("two") {
		t.Fatal("expected both sessions to exist before delete")
	}

	if err := store.DeleteAllSessions(); err != nil {
		t.Fatal(err)
	}
	if store.HasSession("one") || store.HasSession("two") {
		t.Fatal("expected all sessions to be gone after DeleteAllSessions")
	}
}
