package main

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// gatewayTransport is the single, shared *http.Transport every reverse proxy
// in the gateway uses to talk to upstreams.
//
// Why share one transport?
//
// http.Transport is the thing that holds the pool of TCP/TLS connections.
// Each transport keeps its own pool, so giving every route its own transport
// would mean every route has to open fresh connections instead of reusing
// existing ones. Sharing one transport lets connections be pooled across
// routes that hit the same upstream.
//
// In Go, http.Transport is safe to use from many goroutines at once, so it's
// fine for every request, on every route, to share the same instance.
var (
	gatewayTransportOnce sync.Once
	gatewayTransport     *http.Transport
)

// sharedTransport returns the lazily-built singleton transport. We use
// sync.Once instead of building it in init() so the constructor runs only if
// something actually asks for it.
func sharedTransport() *http.Transport {
	gatewayTransportOnce.Do(func() {
		gatewayTransport = newTunedTransport()
	})
	return gatewayTransport
}

// newTunedTransport builds an *http.Transport with values tuned for a
// reverse proxy hot path. Each field below is set explicitly with a short
// note so the reasoning is easy to follow.
func newTunedTransport() *http.Transport {
	dialer := &net.Dialer{
		// How long we'll wait for a TCP connection to come up. The Go
		// default is no timeout at all, which can cause a request to hang
		// forever if the upstream stops accepting connections.
		Timeout: 5 * time.Second,

		// How often to send TCP keep-alive probes once a connection is
		// open. Helps detect dead upstream connections without waiting for
		// the OS default (which can be many minutes).
		KeepAlive: 30 * time.Second,
	}

	return &http.Transport{
		// DialContext is what http.Transport calls to actually open a TCP
		// connection. Using our own *net.Dialer lets us set the timeouts
		// above.
		DialContext: dialer.DialContext,

		// Total number of idle connections kept across all upstreams.
		// Default is 100. We bump this up because a gateway can talk to
		// many upstreams at once.
		MaxIdleConns: 1024,

		// Idle connections kept per upstream. The Go default is 2, which
		// is way too low for a proxy: under load you'd constantly close
		// and reopen connections to the same backend. 256 means a single
		// hot upstream can keep that many warm connections ready to go.
		MaxIdleConnsPerHost: 256,

		// 0 means "no limit" on total open (idle + in-use) connections to
		// a single host. We don't want to bottleneck the gateway behind a
		// connection cap; the upstream is the right place to enforce one.
		MaxConnsPerHost: 0,

		// How long an idle connection stays in the pool before being
		// closed. 90 seconds matches the Go default and is fine for most
		// upstreams.
		IdleConnTimeout: 90 * time.Second,

		// Limits how long the TLS handshake can take. Without this, a
		// slow or buggy TLS server could hold a request open forever.
		TLSHandshakeTimeout: 5 * time.Second,

		// Limits how long we'll wait for the upstream to send response
		// headers after the request body is fully written. The body can
		// still stream slowly after this; this only covers the headers.
		ResponseHeaderTimeout: 30 * time.Second,

		// How long to wait for an upstream's "100 Continue" reply when a
		// client uses Expect: 100-continue. 1s is the Go-recommended
		// value.
		ExpectContinueTimeout: 1 * time.Second,

		// Try HTTP/2 to upstreams when the upstream supports it. HTTP/2
		// multiplexes many streams over one connection, which can reduce
		// connection-pool pressure and improve throughput.
		ForceAttemptHTTP2: true,

		// Don't have the transport transparently decompress responses;
		// pass them through as-is. Decompressing here would waste CPU,
		// since the gateway just forwards the body to the client anyway.
		DisableCompression: true,
	}
}
