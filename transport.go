package main

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// gatewayTransport is the shared upstream transport.
var (
	gatewayTransportOnce sync.Once
	gatewayTransport     *http.Transport
	gatewayTransportErr  error
)

// sharedTransport returns the process-wide upstream transport.
func sharedTransport() (*http.Transport, error) {
	gatewayTransportOnce.Do(func() {
		gatewayTransport, gatewayTransportErr = newTunedTransport()
	})
	return gatewayTransport, gatewayTransportErr
}

// newTunedTransport builds the shared upstream transport.
func newTunedTransport() (*http.Transport, error) {
	dialer := &net.Dialer{
		// Bound connection setup time.
		Timeout: 5 * time.Second,

		// Keep idle upstream connections healthy.
		KeepAlive: 30 * time.Second,
	}

	return &http.Transport{
		// Honor standard proxy environment variables.
		Proxy: http.ProxyFromEnvironment,

		// Use the tuned dialer above.
		DialContext: dialer.DialContext,

		// Keep a larger shared idle pool for upstream reuse.
		MaxIdleConns: 1024,

		// Avoid reconnect churn for hot upstreams.
		MaxIdleConnsPerHost: 256,

		// Do not impose a transport-level per-host cap.
		MaxConnsPerHost: 0,

		// Close long-idle upstream connections.
		IdleConnTimeout: 90 * time.Second,

		// Bound TLS setup time.
		TLSHandshakeTimeout: 5 * time.Second,

		// Bound time-to-first-response-header from upstream.
		ResponseHeaderTimeout: 30 * time.Second,

		// Bound Expect: 100-continue wait time.
		ExpectContinueTimeout: 1 * time.Second,

		// Use HTTP/2 upstream when available.
		ForceAttemptHTTP2: true,

		// Pass upstream response bodies through as-is.
		DisableCompression: true,

	}, nil
}
