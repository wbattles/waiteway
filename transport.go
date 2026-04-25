package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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

		// Allow extra root certificates to be mounted into the container.
		TLSClientConfig: tlsConfig,
	}, nil
}

func tlsConfigFromEnvironment() (*tls.Config, error) {
	certFile := strings.TrimSpace(os.Getenv("WAITEWAY_CA_CERT_FILE"))
	certDir := strings.TrimSpace(os.Getenv("WAITEWAY_CA_CERT_DIR"))
	if certFile == "" && certDir == "" {
		return nil, nil
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	loaded := 0
	if certFile != "" {
		count, err := appendCertFile(pool, certFile)
		if err != nil {
			return nil, err
		}
		loaded += count
	}

	if certDir != "" {
		count, err := appendCertDirectory(pool, certDir)
		if err != nil {
			return nil, err
		}
		loaded += count
	}

	if loaded == 0 {
		return nil, fmt.Errorf("no certificates loaded from WAITEWAY_CA_CERT_FILE or WAITEWAY_CA_CERT_DIR")
	}

	return &tls.Config{RootCAs: pool}, nil
}

func appendCertDirectory(pool *x509.CertPool, dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("read WAITEWAY_CA_CERT_DIR %q: %w", dir, err)
	}

	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !looksLikeCertFile(entry.Name()) {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(files)

	loaded := 0
	for _, file := range files {
		count, err := appendCertFile(pool, file)
		if err != nil {
			return 0, err
		}
		loaded += count
	}

	return loaded, nil
}

func appendCertFile(pool *x509.CertPool, path string) (int, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read certificate file %q: %w", path, err)
	}
	if ok := pool.AppendCertsFromPEM(pemData); !ok {
		return 0, fmt.Errorf("parse certificate file %q: no PEM certificates found", path)
	}
	return 1, nil
}

func looksLikeCertFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".crt" || ext == ".pem" || ext == ".cer"
}
