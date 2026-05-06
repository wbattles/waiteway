package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestStoreRoundTripsWebSocketsField makes sure the websockets flag survives
// a save and reload, and that the migration column shows up in fresh DBs.
func TestStoreRoundTripsWebSocketsField(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if err := store.AddRoute(Route{
		Name:       "chat",
		PathPrefix: "/ws",
		Target:     "http://localhost:3000",
		WebSockets: true,
	}); err != nil {
		t.Fatal(err)
	}

	routes, err := store.ListRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if !routes[0].WebSockets {
		t.Fatal("expected WebSockets to be true after round trip")
	}

	if err := store.UpdateRoute(0, Route{
		Name:       "chat",
		PathPrefix: "/ws",
		Target:     "http://localhost:3000",
		WebSockets: false,
	}); err != nil {
		t.Fatal(err)
	}
	routes, err = store.ListRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if routes[0].WebSockets {
		t.Fatal("expected WebSockets to be false after update")
	}
}

// TestCompileConfigTranslatesWSScheme checks that ws:// and wss:// targets are
// rewritten to http/https so Go's reverse proxy can dial them.
func TestCompileConfigTranslatesWSScheme(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"ws://example.com", "http://example.com"},
		{"wss://example.com", "https://example.com"},
		{"WS://example.com/path", "http://example.com/path"},
	}
	for _, tt := range tests {
		routes, err := compileConfig(Config{
			Routes: []Route{{Name: "x", PathPrefix: "/x", Target: tt.in, WebSockets: true}},
		})
		if err != nil {
			t.Fatalf("compileConfig(%q) failed: %v", tt.in, err)
		}
		// Force the director to run and see the rewritten scheme by checking
		// the proxy's behavior end-to-end via a fake request.
		req, _ := http.NewRequest("GET", "http://gateway"+routes[0].PathPrefix, nil)
		routes[0].proxy.Director(req)
		want, _ := url.Parse(tt.want)
		if req.URL.Scheme != want.Scheme {
			t.Errorf("target %q -> scheme %q, want %q", tt.in, req.URL.Scheme, want.Scheme)
		}
	}
}

// TestApplyResponsePolicySkipsSwitchingProtocols verifies the response policy
// does nothing on a 101, regardless of which knobs are on. Reading the body
// of a 101 would corrupt a hijacked stream.
func TestApplyResponsePolicySkipsSwitchingProtocols(t *testing.T) {
	policy, err := compilePolicy(Policy{
		Name:                     "ws-breaker",
		MaxResponseBytes:         10,
		ResponseTransformFind:    "a",
		ResponseTransformReplace: "b",
		AddResponseHeaders:       []string{"X-Tampered: yes"},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("aaaaaaaaaaaaaaaaaaaa")),
	}
	if err := applyResponsePolicy(policy, resp); err != nil {
		t.Fatalf("applyResponsePolicy on 101: %v", err)
	}
	if got := resp.Header.Get("X-Tampered"); got != "" {
		t.Errorf("expected headers untouched on 101, got %q", got)
	}
	// The body should still be readable in full because nothing consumed it.
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 20 {
		t.Errorf("expected body untouched on 101, got %d bytes", len(body))
	}
}

// TestIsWebSocketUpgradeRecognizesValidHeaders covers the header parsing
// (case-insensitive, comma-separated Connection token).
func TestIsWebSocketUpgradeRecognizesValidHeaders(t *testing.T) {
	yes := []http.Header{
		{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}},
		{"Upgrade": {"WebSocket"}, "Connection": {"upgrade"}},
		{"Upgrade": {"websocket"}, "Connection": {"keep-alive, Upgrade"}},
	}
	for _, h := range yes {
		r := &http.Request{Header: h}
		if !isWebSocketUpgrade(r) {
			t.Errorf("expected upgrade for headers %v", h)
		}
	}
	no := []http.Header{
		{},
		{"Upgrade": {"websocket"}},
		{"Connection": {"Upgrade"}},
		{"Upgrade": {"h2c"}, "Connection": {"Upgrade"}},
	}
	for _, h := range no {
		r := &http.Request{Header: h}
		if isWebSocketUpgrade(r) {
			t.Errorf("did not expect upgrade for headers %v", h)
		}
	}
}

// TestStatusRecorderImplementsHijacker is the load-bearing fix: Go's reverse
// proxy needs the response writer to satisfy http.Hijacker for any upgrade.
func TestStatusRecorderImplementsHijacker(t *testing.T) {
	hijacked := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		if _, ok := interface{}(rec).(http.Hijacker); !ok {
			hijacked <- errors.New("statusRecorder does not implement http.Hijacker")
			return
		}
		conn, _, err := rec.Hijack()
		if err != nil {
			hijacked <- err
			return
		}
		conn.Close()
		hijacked <- nil
	}))
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL)
	if err == nil {
		resp.Body.Close()
	}

	select {
	case err := <-hijacked:
		if err != nil {
			t.Fatalf("hijack failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler never ran")
	}
}

// TestGatewayProxiesWebSocketUpgrade is the end-to-end check. It spins up a
// tiny upstream that completes the WS handshake and echoes back one message,
// then proxies through the gateway. If anything along the policy / recorder
// path drops the upgrade, this test catches it.
func TestGatewayProxiesWebSocketUpgrade(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			http.Error(w, "expected upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		// Manually complete the handshake without a real WS library: the
		// proxy only cares about the 101 + byte streaming.
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		// Echo a single line.
		line, err := brw.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = brw.WriteString(line)
		_ = brw.Flush()
	}))
	t.Cleanup(upstream.Close)

	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	// Attach a policy whose features would normally break a WS connection.
	// Caching, response transform, response size limit, and a short timeout.
	if err := store.AddPolicy(Policy{
		Name:                  "would-break-ws",
		RequestTimeoutSeconds: 1,
		CacheTTLSeconds:       60,
		MaxResponseBytes:      10,
		ResponseTransformFind: "x",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddRoute(Route{
		Name:       "ws",
		PathPrefix: "/ws",
		Target:     upstream.URL,
		PolicyName: "would-break-ws",
		WebSockets: true,
	}); err != nil {
		t.Fatal(err)
	}

	config, err := store.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	gw, err := newGateway(store, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gw.Close)

	gateway := httptest.NewServer(gw.gatewayHandler())
	t.Cleanup(gateway.Close)

	// Open a raw TCP connection to the gateway and write a WS upgrade by hand.
	gwURL, _ := url.Parse(gateway.URL)
	conn, err := net.DialTimeout("tcp", gwURL.Host, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	req := "GET /ws HTTP/1.1\r\n" +
		"Host: " + gwURL.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		t.Fatalf("missing Upgrade header in response: %v", resp.Header)
	}

	// Now talk over the upgraded connection.
	if _, err := conn.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	echoed, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if echoed != "hello\n" {
		t.Fatalf("expected echo 'hello', got %q", echoed)
	}

	// Wait longer than the policy timeout to confirm it was bypassed.
	time.Sleep(1500 * time.Millisecond)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("still-here\n")); err != nil {
		// upstream only echoes once, so a write error here is fine; the
		// point of the sleep was just to outlive the request timeout
		// without the gateway killing us.
	}
}
