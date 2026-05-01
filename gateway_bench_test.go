package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// silenceStdout redirects os.Stdout to /dev/null for the duration of the
// benchmark so per-request log lines don't drown out benchmark results.
func silenceStdout(b *testing.B) {
	b.Helper()
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		b.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = devNull
	b.Cleanup(func() {
		os.Stdout = original
		_ = devNull.Close()
	})
}

// upstreamForBench is a minimal upstream that returns a small fixed body.
// httptest.NewServer is reused across all benchmarks in this file to keep
// the work outside the gateway as small and consistent as possible.
func upstreamForBench(b *testing.B) *httptest.Server {
	b.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	}))
	b.Cleanup(srv.Close)
	return srv
}

// gatewayForBench builds a gateway with the given config, hooks it up to a
// test server, and returns the gateway server URL.
func gatewayForBench(b *testing.B, config Config) string {
	b.Helper()

	store, err := openStore(":memory:")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { store.Close() })

	gw, err := newGateway(store, config)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(gw.Close)

	srv := httptest.NewServer(gw.gatewayHandler())
	b.Cleanup(srv.Close)
	return srv.URL
}

// drainResponse reads and discards the response body so the upstream
// connection can be reused. Failing to do this skews benchmarks heavily.
func drainResponse(b *testing.B, resp *http.Response) {
	b.Helper()
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// BenchmarkProxyBasicRoute measures the cost of forwarding a request through
// a single route with no policy attached.
func BenchmarkProxyBasicRoute(b *testing.B) {
	silenceStdout(b)
	upstream := upstreamForBench(b)
	url := gatewayForBench(b, Config{
		Routes: []Route{
			{Name: "bench", PathPrefix: "/api/bench", Target: upstream.URL},
		},
	}) + "/api/bench/path"

	client := &http.Client{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(url)
		if err != nil {
			b.Fatal(err)
		}
		drainResponse(b, resp)
	}
}

// BenchmarkProxyWithPolicy measures the per-request overhead added by a
// policy that touches request and response headers but does no IO of its own.
func BenchmarkProxyWithPolicy(b *testing.B) {
	silenceStdout(b)
	upstream := upstreamForBench(b)
	url := gatewayForBench(b, Config{
		Policies: []Policy{
			{
				Name:               "bench",
				AddRequestHeaders:  []string{"X-Bench: yes"},
				AddResponseHeaders: []string{"X-Out: yes"},
			},
		},
		Routes: []Route{
			{Name: "bench", PathPrefix: "/api/bench", Target: upstream.URL, PolicyName: "bench"},
		},
	}) + "/api/bench/path"

	client := &http.Client{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(url)
		if err != nil {
			b.Fatal(err)
		}
		drainResponse(b, resp)
	}
}

// BenchmarkProxyCacheHit measures the fast path when responses are served
// directly from the in-memory cache and never reach the upstream.
func BenchmarkProxyCacheHit(b *testing.B) {
	silenceStdout(b)
	upstream := upstreamForBench(b)
	url := gatewayForBench(b, Config{
		Policies: []Policy{
			{Name: "cached", CacheTTLSeconds: 60},
		},
		Routes: []Route{
			{Name: "cached", PathPrefix: "/api/cached", Target: upstream.URL, PolicyName: "cached"},
		},
	}) + "/api/cached/path"

	client := &http.Client{}

	// prime the cache once so every benchmark iteration is a hit
	resp, err := client.Get(url)
	if err != nil {
		b.Fatal(err)
	}
	drainResponse(b, resp)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(url)
		if err != nil {
			b.Fatal(err)
		}
		drainResponse(b, resp)
	}
}

// BenchmarkRouteMatch measures matchRoute() in isolation against a config
// with many routes. This is the part of the hot path most affected by the
// route count.
func BenchmarkRouteMatch(b *testing.B) {
	routes := make([]Route, 0, 50)
	for i := 0; i < 50; i++ {
		routes = append(routes, Route{
			Name:       fmt.Sprintf("r%d", i),
			PathPrefix: fmt.Sprintf("/svc%d/api", i),
			Target:     "http://localhost:9999",
		})
	}

	store, err := openStore(":memory:")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { store.Close() })

	gw, err := newGateway(store, Config{
		Routes: routes,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(gw.Close)

	// hit a route near the end of the list to stress the matcher more
	path := "/svc49/api/items/42"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := gw.matchRoute(path); !ok {
			b.Fatal("expected route to match")
		}
	}
}
