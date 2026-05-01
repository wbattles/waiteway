package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
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

	tlsConfig, err := tlsConfigFromEnvironment()
	if err != nil {
		return nil, err
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

		// Trust system roots plus any extra cert from WAITEWAY_CA_CERT.
		TLSClientConfig: tlsConfig,
	}, nil
}

func tlsConfigFromEnvironment() (*tls.Config, error) {
	path := strings.TrimSpace(os.Getenv("WAITEWAY_CA_CERT"))
	if path == "" {
		return nil, nil
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read WAITEWAY_CA_CERT %q: %w", path, err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("parse WAITEWAY_CA_CERT %q: no PEM certificates found", path)
	}

	return &tls.Config{RootCAs: pool}, nil
}
