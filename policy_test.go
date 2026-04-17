package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testGateway(t *testing.T, upstream *httptest.Server, policy Policy) *httptest.Server {
	t.Helper()
	target := upstream.URL

	config := Config{
		Admin:    AdminConfig{Username: "admin", Password: "admin"},
		LogLimit: 10,
		Policies: []Policy{policy},
		Routes: []Route{
			{
				Name:       "test",
				PathPrefix: "/test",
				Target:     target,
				PolicyName: policy.Name,
			},
		},
	}

	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	gw, err := newGateway(store, config)
	if err != nil {
		t.Fatal(err)
	}

	return httptest.NewServer(gw.gatewayHandler())
}

func TestPolicyAPIKeyAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	gw := testGateway(t, upstream, Policy{
		Name:          "auth",
		RequireAPIKey: true,
		APIKeys:       []string{"good-key"},
	})
	defer gw.Close()

	// no key
	resp, _ := http.Get(gw.URL + "/test")
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 without key, got %d", resp.StatusCode)
	}

	// wrong key
	req, _ := http.NewRequest("GET", gw.URL+"/test", nil)
	req.Header.Set("X-API-Key", "bad-key")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 with wrong key, got %d", resp.StatusCode)
	}

	// correct key
	req, _ = http.NewRequest("GET", gw.URL+"/test", nil)
	req.Header.Set("X-API-Key", "good-key")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 with correct key, got %d", resp.StatusCode)
	}
}

func TestPolicyBasicAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	gw := testGateway(t, upstream, Policy{
		Name:              "basic",
		BasicAuthUsername: "user",
		BasicAuthPassword: "pass",
	})
	defer gw.Close()

	// no auth
	resp, _ := http.Get(gw.URL + "/test")
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 without auth, got %d", resp.StatusCode)
	}

	// wrong creds
	req, _ := http.NewRequest("GET", gw.URL+"/test", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:wrong")))
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 with wrong creds, got %d", resp.StatusCode)
	}

	// correct creds
	req, _ = http.NewRequest("GET", gw.URL+"/test", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 with correct creds, got %d", resp.StatusCode)
	}
}

func TestPolicyRateLimiting(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	gw := testGateway(t, upstream, Policy{
		Name:                   "ratelimit",
		RateLimitRequests:      2,
		RateLimitWindowSeconds: 60,
	})
	defer gw.Close()

	// first two should pass
	for i := 0; i < 2; i++ {
		resp, _ := http.Get(gw.URL + "/test")
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: expected 200, got %d", i+1, resp.StatusCode)
		}
	}

	// third should be rate limited
	resp, _ := http.Get(gw.URL + "/test")
	if resp.StatusCode != 429 {
		t.Fatalf("expected 429 on third request, got %d", resp.StatusCode)
	}
}

func TestPolicyMethodAllowList(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	gw := testGateway(t, upstream, Policy{
		Name:           "methods",
		AllowedMethods: []string{"GET"},
	})
	defer gw.Close()

	// GET should work
	resp, _ := http.Get(gw.URL + "/test")
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for GET, got %d", resp.StatusCode)
	}

	// POST should be denied
	resp, _ = http.Post(gw.URL+"/test", "text/plain", strings.NewReader("hi"))
	if resp.StatusCode != 405 {
		t.Fatalf("expected 405 for POST, got %d", resp.StatusCode)
	}
}

func TestPolicyPayloadLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	gw := testGateway(t, upstream, Policy{
		Name:            "payload",
		MaxPayloadBytes: 10,
	})
	defer gw.Close()

	// small body should pass
	resp, _ := http.Post(gw.URL+"/test", "text/plain", strings.NewReader("short"))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for small body, got %d", resp.StatusCode)
	}

	// large body should be rejected
	resp, _ = http.Post(gw.URL+"/test", "text/plain", strings.NewReader("this is way too long for the limit"))
	if resp.StatusCode != 413 {
		t.Fatalf("expected 413 for large body, got %d", resp.StatusCode)
	}
}

func TestPolicyRequestTransform(t *testing.T) {
	var received string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = string(body)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	gw := testGateway(t, upstream, Policy{
		Name:                    "transform",
		RequestTransformFind:    "cat",
		RequestTransformReplace: "dog",
	})
	defer gw.Close()

	http.Post(gw.URL+"/test", "text/plain", strings.NewReader("i have a cat"))
	if received != "i have a dog" {
		t.Fatalf("expected 'i have a dog', got %q", received)
	}
}

func TestPolicyResponseTransform(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	}))
	defer upstream.Close()

	gw := testGateway(t, upstream, Policy{
		Name:                     "restransform",
		ResponseTransformFind:    "hello",
		ResponseTransformReplace: "goodbye",
	})
	defer gw.Close()

	resp, _ := http.Get(gw.URL + "/test")
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "goodbye world" {
		t.Fatalf("expected 'goodbye world', got %q", string(body))
	}
}

func TestPolicyRequestHeaders(t *testing.T) {
	var gotAdd, gotRemove string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAdd = r.Header.Get("X-Custom")
		gotRemove = r.Header.Get("X-Remove-Me")
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	gw := testGateway(t, upstream, Policy{
		Name:                 "reqheaders",
		AddRequestHeaders:    []string{"X-Custom: hello"},
		RemoveRequestHeaders: []string{"X-Remove-Me"},
	})
	defer gw.Close()

	req, _ := http.NewRequest("GET", gw.URL+"/test", nil)
	req.Header.Set("X-Remove-Me", "should-be-gone")
	http.DefaultClient.Do(req)

	if gotAdd != "hello" {
		t.Fatalf("expected X-Custom 'hello', got %q", gotAdd)
	}
	if gotRemove != "" {
		t.Fatalf("expected X-Remove-Me to be removed, got %q", gotRemove)
	}
}

func TestPolicyResponseHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "yes")
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	gw := testGateway(t, upstream, Policy{
		Name:                  "resheaders",
		AddResponseHeaders:    []string{"X-Added: from-waiteway"},
		RemoveResponseHeaders: []string{"X-Upstream"},
	})
	defer gw.Close()

	resp, _ := http.Get(gw.URL + "/test")
	if resp.Header.Get("X-Added") != "from-waiteway" {
		t.Fatalf("expected X-Added 'from-waiteway', got %q", resp.Header.Get("X-Added"))
	}
	if resp.Header.Get("X-Upstream") != "" {
		t.Fatalf("expected X-Upstream removed, got %q", resp.Header.Get("X-Upstream"))
	}
}

func TestPolicyCaching(t *testing.T) {
	callCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Write([]byte(fmt.Sprintf("call %d", callCount)))
	}))
	defer upstream.Close()

	gw := testGateway(t, upstream, Policy{
		Name:            "cache",
		CacheTTLSeconds: 60,
	})
	defer gw.Close()

	// first call
	resp, _ := http.Get(gw.URL + "/test")
	body1, _ := io.ReadAll(resp.Body)

	// second call should be cached
	resp, _ = http.Get(gw.URL + "/test")
	body2, _ := io.ReadAll(resp.Body)

	if string(body1) != "call 1" {
		t.Fatalf("first call: expected 'call 1', got %q", string(body1))
	}
	if string(body2) != "call 1" {
		t.Fatalf("second call should be cached 'call 1', got %q", string(body2))
	}
	if callCount != 1 {
		t.Fatalf("upstream should have been called once, called %d times", callCount)
	}
}

func TestPolicyCORSPreflight(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	gw := testGateway(t, upstream, Policy{
		Name:             "cors",
		CORSAllowOrigins: []string{"*"},
		CORSAllowMethods: []string{"GET", "POST"},
		CORSAllowHeaders: []string{"Content-Type"},
	})
	defer gw.Close()

	// preflight
	req, _ := http.NewRequest("OPTIONS", gw.URL+"/test", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	resp, _ := http.DefaultClient.Do(req)

	if resp.StatusCode != 204 {
		t.Fatalf("expected 204 for preflight, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("expected ACAO *, got %q", resp.Header.Get("Access-Control-Allow-Origin"))
	}
	if resp.Header.Get("Access-Control-Allow-Methods") != "GET, POST" {
		t.Fatalf("expected ACAM 'GET, POST', got %q", resp.Header.Get("Access-Control-Allow-Methods"))
	}

	// normal request should also get CORS headers
	resp, _ = http.Get(gw.URL + "/test")
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("expected ACAO * on normal response, got %q", resp.Header.Get("Access-Control-Allow-Origin"))
	}
}

func TestPolicyIPBlock(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	// block both IPv4 and IPv6 loopback
	gw := testGateway(t, upstream, Policy{
		Name:        "ipblock",
		IPBlockList: []string{"127.0.0.0/8", "::1/128"},
	})
	defer gw.Close()

	resp, _ := http.Get(gw.URL + "/test")
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403 for blocked IP, got %d", resp.StatusCode)
	}
}

func TestPolicyIPAllow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	// allow only 10.0.0.0/8 — localhost should be denied
	gw := testGateway(t, upstream, Policy{
		Name:        "ipallow",
		IPAllowList: []string{"10.0.0.0/8"},
	})
	defer gw.Close()

	resp, _ := http.Get(gw.URL + "/test")
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403 for non-allowed IP, got %d", resp.StatusCode)
	}
}

func TestPolicyResponseSizeLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this is a long response body that exceeds the limit"))
	}))
	defer upstream.Close()

	gw := testGateway(t, upstream, Policy{
		Name:             "reslimit",
		MaxResponseBytes: 10,
	})
	defer gw.Close()

	resp, _ := http.Get(gw.URL + "/test")
	if resp.StatusCode != 502 {
		t.Fatalf("expected 502 for oversized response, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "response too large") {
		t.Fatalf("expected 'response too large' message, got %q", string(body))
	}
}

func TestPolicyCircuitBreaker(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()

	gw := testGateway(t, upstream, Policy{
		Name:                       "breaker",
		CircuitBreakerFailures:     2,
		CircuitBreakerResetSeconds: 60,
	})
	defer gw.Close()

	// trigger failures to open circuit
	for i := 0; i < 2; i++ {
		resp, _ := http.Get(gw.URL + "/test")
		if resp.StatusCode != 500 {
			t.Fatalf("failure %d: expected 500, got %d", i+1, resp.StatusCode)
		}
	}

	// circuit should now be open
	resp, _ := http.Get(gw.URL + "/test")
	if resp.StatusCode != 503 {
		t.Fatalf("expected 503 when circuit open, got %d", resp.StatusCode)
	}
}

func TestPolicyRequestTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	gw := testGateway(t, upstream, Policy{
		Name:                  "timeout",
		RequestTimeoutSeconds: 1,
	})
	defer gw.Close()

	start := time.Now()
	resp, _ := http.Get(gw.URL + "/test")
	elapsed := time.Since(start)

	if resp.StatusCode != 502 {
		t.Fatalf("expected 502 on timeout, got %d", resp.StatusCode)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("timeout should have cut off before 2s, took %s", elapsed)
	}
}

func TestPolicyRetryWithBody(t *testing.T) {
	callCount := 0
	var lastBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		lastBody = string(body)
		callCount++
		if callCount < 3 {
			// close connection to simulate failure
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	gw := testGateway(t, upstream, Policy{
		Name:       "retry",
		RetryCount: 3,
	})
	defer gw.Close()

	resp, err := http.Post(gw.URL+"/test", "text/plain", strings.NewReader("retry-body"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 after retries, got %d", resp.StatusCode)
	}
	if lastBody != "retry-body" {
		t.Fatalf("expected body 'retry-body' on final attempt, got %q", lastBody)
	}
	if callCount != 3 {
		t.Fatalf("expected 3 upstream calls, got %d", callCount)
	}
}

func TestPolicyPathRewrite(t *testing.T) {
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	target := upstream.URL
	config := Config{
		Admin:    AdminConfig{Username: "admin", Password: "admin"},
		LogLimit: 10,
		Policies: []Policy{{
			Name:              "rewrite",
			RewritePathPrefix: "/new",
		}},
		Routes: []Route{{
			Name:       "test",
			PathPrefix: "/old",
			Target:     target,
			PolicyName: "rewrite",
		}},
	}

	store, _ := openStore(":memory:")
	defer store.Close()
	gw, _ := newGateway(store, config)
	srv := httptest.NewServer(gw.gatewayHandler())
	defer srv.Close()

	http.Get(srv.URL + "/old/stuff")
	if receivedPath != "/new/stuff" {
		t.Fatalf("expected /new/stuff, got %q", receivedPath)
	}

	http.Get(srv.URL + "/old")
	if receivedPath != "/new" {
		t.Fatalf("expected /new, got %q", receivedPath)
	}
}

func TestPolicyMultipleFeatures(t *testing.T) {
	var receivedHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Injected")
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	gw := testGateway(t, upstream, Policy{
		Name:              "multi",
		RequireAPIKey:     true,
		APIKeys:           []string{"key1"},
		AllowedMethods:    []string{"GET"},
		AddRequestHeaders: []string{"X-Injected: yes"},
	})
	defer gw.Close()

	// POST with key should fail on method
	req, _ := http.NewRequest("POST", gw.URL+"/test", nil)
	req.Header.Set("X-API-Key", "key1")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 405 {
		t.Fatalf("expected 405 for POST, got %d", resp.StatusCode)
	}

	// GET without key should fail on auth
	resp, _ = http.Get(gw.URL + "/test")
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 without key, got %d", resp.StatusCode)
	}

	// GET with key should pass and inject header
	req, _ = http.NewRequest("GET", gw.URL+"/test", nil)
	req.Header.Set("X-API-Key", "key1")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if receivedHeader != "yes" {
		t.Fatalf("expected X-Injected 'yes', got %q", receivedHeader)
	}
}

// suppress unused import warnings
var _ = net.SplitHostPort
var _ = bytes.NewReader
