package main

import (
	"sync"
	"testing"
)

func TestNewTunedTransportUsesDefaultTLSHandling(t *testing.T) {
	resetTransportState()

	transport, err := newTunedTransport()
	if err != nil {
		t.Fatalf("newTunedTransport returned error: %v", err)
	}
	if transport.TLSClientConfig != nil {
		t.Fatal("expected default TLS handling")
	}
}

func resetTransportState() {
	gatewayTransportOnce = sync.Once{}
	gatewayTransport = nil
	gatewayTransportErr = nil
}
