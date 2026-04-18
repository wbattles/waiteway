package main

import (
	"net/http/httptest"
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
		gw.recordRequest(req, "test", 200, time.Millisecond)
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
	// returns quickly (the drop-on-full path).
	close(gw.stopCh)
	<-gw.doneCh

	req := httptest.NewRequest("GET", "/test", nil)
	done := make(chan struct{})
	go func() {
		// Send enough to overflow the 1024 buffer plus extras.
		for i := 0; i < 2000; i++ {
			gw.recordRequest(req, "test", 200, 0)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("recordRequest blocked when channel was full")
	}
}
