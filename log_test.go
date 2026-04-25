package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestStoreTrimLogsKeepsNewest(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	for i := 0; i < 20; i++ {
		if err := store.AddLog(requestLog{
			Time:   time.Now(),
			Method: "GET",
			Path:   "/test",
			Status: 200,
		}); err != nil {
			t.Fatal(err)
		}
	}

	if err := store.TrimLogs(5); err != nil {
		t.Fatal(err)
	}

	logs, err := store.ListLogs(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 5 {
		t.Errorf("expected 5 logs after trim, got %d", len(logs))
	}
}

func TestGatewayDrainsPendingLogsOnClose(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	gw, err := newGateway(store, Config{
		Admin:    AdminConfig{Username: "admin", Password: "admin"},
		LogLimit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	for i := 0; i < 10; i++ {
		gw.recordRequest(req, req.RemoteAddr, "test", 200, time.Millisecond, time.Now())
	}

	// Close blocks until the drainer has flushed pending entries
	gw.Close()

	logs, err := store.ListLogs(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 10 {
		t.Errorf("expected 10 logs after Close flush, got %d", len(logs))
	}
}

func TestGatewayCloseIsIdempotent(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	gw, err := newGateway(store, Config{
		Admin: AdminConfig{Username: "admin", Password: "admin"},
	})
	if err != nil {
		t.Fatal(err)
	}

	gw.Close()
	gw.Close() // second call must not panic or hang
}

func TestGatewayRecordRequestIsNonBlocking(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	gw, err := newGateway(store, Config{
		Admin: AdminConfig{Username: "admin", Password: "admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gw.Close)

	// Stop the drainer so logCh fills up, then verify recordRequest still
	// returns quickly (the drop-on-full path). Close() is idempotent, so the
	// t.Cleanup above safely becomes a no-op.
	gw.Close()

	req := httptest.NewRequest("GET", "/test", nil)
	done := make(chan struct{})
	go func() {
		// Send enough to overflow the 1024 buffer plus extras.
		for i := 0; i < 2000; i++ {
			gw.recordRequest(req, req.RemoteAddr, "test", 200, 0, time.Now())
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("recordRequest blocked when channel was full")
	}
}

func TestAdminMetricsEndpointReportsCounters(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	gw, err := newGateway(store, Config{
		Admin: AdminConfig{Username: "admin", Password: "admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gw.Close)

	req := httptest.NewRequest("GET", "/test", nil)
	gw.recordRequest(req, req.RemoteAddr, "test", 200, time.Millisecond, time.Now())
	gw.recordRequest(req, req.RemoteAddr, "test", 502, 2*time.Millisecond, time.Now())

	res := httptest.NewRecorder()
	gw.adminHandler().ServeHTTP(res, httptest.NewRequest("GET", "/metrics", nil))

	if res.Code != 200 {
		t.Fatalf("expected 200, got %d", res.Code)
	}

	body, err := io.ReadAll(res.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)

	if !strings.Contains(text, "waiteway_requests_total 2") {
		t.Fatalf("expected requests counter in metrics output, got %q", text)
	}
	if !strings.Contains(text, "waiteway_errors_total 1") {
		t.Fatalf("expected errors counter in metrics output, got %q", text)
	}
}

func TestGatewayLogRequestWritesRawJSONLine(t *testing.T) {
	store, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	gw, err := newGateway(store, Config{
		Admin: AdminConfig{Username: "admin", Password: "admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gw.Close)

	originalStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = originalStdout
	}()

	gw.logRequest(requestLog{
		Time:       time.Date(2026, 4, 18, 22, 21, 29, 0, time.UTC),
		Method:     "GET",
		Path:       "/api/joke",
		Status:     401,
		Route:      "joke",
		RemoteAddr: "72.209.227.37",
		Duration:   0,
	})

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}

	line := strings.TrimSpace(buf.String())
	if strings.Contains(line, "2026/") {
		t.Fatalf("expected raw JSON without Go log prefix, got %q", line)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		t.Fatalf("expected valid JSON line, got %q: %v", line, err)
	}

	if payload["event"] != "request" {
		t.Fatalf("expected request event, got %#v", payload["event"])
	}
	if payload["route"] != "joke" {
		t.Fatalf("expected joke route, got %#v", payload["route"])
	}
}
