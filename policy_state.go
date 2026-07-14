package main

import (
	"bytes"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// rateLimiterShardCount splits client state across independent locks so
// concurrent requests from different clients don't serialize on one mutex.
const rateLimiterShardCount = 16

// rateLimiterMaxEntriesPerShard bounds memory per shard so a flood of
// unique client addresses can't grow the map without limit; mirrors the cap
// responseCache applies to its own entries.
const rateLimiterMaxEntriesPerShard = 1024

type rateLimiter struct {
	limit  int
	window time.Duration
	shards [rateLimiterShardCount]rateLimiterShard
}

type rateLimiterShard struct {
	mu      sync.Mutex
	entries map[netip.Addr]*rateLimiterEntry
	calls   int
}

type rateLimiterEntry struct {
	count       int
	windowStart time.Time
}

// rateLimiterSweepEvery controls how often Allow sweeps expired keys out of
// a shard's entries map. Amortizes cleanup cost so the hot path stays O(1).
const rateLimiterSweepEvery = 256

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	r := &rateLimiter{limit: limit, window: window}
	for i := range r.shards {
		r.shards[i].entries = map[netip.Addr]*rateLimiterEntry{}
	}
	return r
}

// rateLimiterShardIndex hashes the address bytes with FNV-1a. It only needs
// to spread keys evenly across shards, not resist a determined attacker, so
// a small non-cryptographic hash is the right tool here.
func rateLimiterShardIndex(key netip.Addr) int {
	b := key.As16()
	var h uint64 = 1469598103934665603
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return int(h % rateLimiterShardCount)
}

func (r *rateLimiter) Allow(key netip.Addr, now time.Time) bool {
	shard := &r.shards[rateLimiterShardIndex(key)]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	shard.calls++
	if shard.calls >= rateLimiterSweepEvery {
		shard.calls = 0
		for k, entry := range shard.entries {
			if k == key {
				continue
			}
			if now.Sub(entry.windowStart) >= r.window {
				delete(shard.entries, k)
			}
		}
	}

	entry := shard.entries[key]
	if entry == nil {
		if len(shard.entries) >= rateLimiterMaxEntriesPerShard {
			// Shard is full and this is a new key. Evict one arbitrary
			// entry in O(1) rather than scanning for the oldest; the sweep
			// above already reclaims expired entries on a regular cadence.
			for k := range shard.entries {
				delete(shard.entries, k)
				break
			}
		}
		shard.entries[key] = &rateLimiterEntry{count: 1, windowStart: now}
		return true
	}

	// If the window expired, start a new one.
	if now.Sub(entry.windowStart) >= r.window {
		entry.count = 1
		entry.windowStart = now
		return true
	}

	if entry.count >= r.limit {
		return false
	}
	entry.count++
	return true
}

type circuitBreaker struct {
	mu          sync.Mutex
	threshold   int
	resetWindow time.Duration
	failures    int
	openUntil   time.Time
}

func (c *circuitBreaker) Allow(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !now.Before(c.openUntil)
}

func (c *circuitBreaker) RecordSuccess() {
	c.mu.Lock()
	c.failures = 0
	c.openUntil = time.Time{}
	c.mu.Unlock()
}

func (c *circuitBreaker) RecordFailure(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures++
	if c.failures >= c.threshold {
		c.openUntil = now.Add(c.resetWindow)
		c.failures = 0
	}
}

type retryTransport struct {
	base    http.RoundTripper
	retries int
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	var resp *http.Response
	var err error
	// Prepare a getBody helper so we can replay the request body for retries.
	var getBody func() (io.ReadCloser, error)
	if req.GetBody != nil {
		getBody = func() (io.ReadCloser, error) { return req.GetBody() }
	} else if req.Body != nil && req.ContentLength != 0 {
		originalBody := req.Body
		bodyBytes, readErr := io.ReadAll(originalBody)
		if readErr != nil {
			return nil, readErr
		}
		if closeErr := originalBody.Close(); closeErr != nil {
			return nil, closeErr
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		getBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(bodyBytes)), nil }
	} else {
		getBody = func() (io.ReadCloser, error) { return nil, nil }
	}

	for attempt := 0; attempt <= t.retries; attempt++ {
		// stop retrying once the client is gone or the policy timeout fired
		if ctxErr := req.Context().Err(); ctxErr != nil {
			return nil, ctxErr
		}
		clone := req.Clone(req.Context())
		if attempt == 0 && req.GetBody == nil {
			clone.Body = req.Body
		} else if b, gerr := getBody(); gerr != nil {
			return nil, gerr
		} else if b != nil {
			clone.Body = b
		}
		resp, err = base.RoundTrip(clone)
		if err == nil {
			return resp, nil
		}
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}
	return nil, err
}

type responseCache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[string]cachedResponse
	sets    int
}

type cachedResponse struct {
	status    int
	header    http.Header
	body      []byte
	expiresAt time.Time
}

type cacheRecorder struct {
	header http.Header
	body   bytes.Buffer
	status int
}

var cacheRecorderPool = sync.Pool{
	New: func() any {
		return &cacheRecorder{
			header: make(http.Header),
			status: http.StatusOK,
		}
	},
}

// responseCacheSweepEvery controls how often Set sweeps expired entries out
// of the cache. Popular-then-cold keys would otherwise accumulate forever.
const responseCacheSweepEvery = 64

// maxResponseCacheEntries caps the cache so unique query strings cannot grow
// memory without bound inside the TTL window.
const maxResponseCacheEntries = 1024

func (c *responseCache) Get(key string, now time.Time) (cachedResponse, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return cachedResponse{}, false
	}
	if now.After(entry.expiresAt) {
		c.mu.Lock()
		// re-check under write lock so we don't delete a fresh entry written
		// in between the unlock and lock above.
		if existing, stillOK := c.entries[key]; stillOK && now.After(existing.expiresAt) {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		return cachedResponse{}, false
	}
	return entry, true
}

func (c *responseCache) Set(key string, status int, header http.Header, body []byte, now time.Time) {
	c.mu.Lock()
	if _, exists := c.entries[key]; !exists && len(c.entries) >= maxResponseCacheEntries {
		// Evict one arbitrary entry in O(1) instead of scanning the whole
		// map for expired ones on every Set once the cache is full; the
		// periodic sweep below already reclaims expired entries on a
		// regular cadence. Upgrade to LRU if cache hit rates ever matter
		// enough to measure.
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	c.entries[key] = cachedResponse{
		status:    status,
		header:    cloneHeader(header),
		body:      append([]byte(nil), body...),
		expiresAt: now.Add(c.ttl),
	}
	c.sets++
	if c.sets >= responseCacheSweepEvery {
		c.sets = 0
		for k, entry := range c.entries {
			if now.After(entry.expiresAt) {
				delete(c.entries, k)
			}
		}
	}
	c.mu.Unlock()
}

func (w *cacheRecorder) Header() http.Header {
	return w.header
}

func (w *cacheRecorder) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

func (w *cacheRecorder) WriteHeader(statusCode int) {
	w.status = statusCode
}

func (w *cacheRecorder) Flush() {}

func getCacheRecorder() *cacheRecorder {
	recorder := cacheRecorderPool.Get().(*cacheRecorder)
	recorder.status = http.StatusOK
	return recorder
}

func putCacheRecorder(recorder *cacheRecorder) {
	for key := range recorder.header {
		delete(recorder.header, key)
	}
	recorder.body.Reset()
	recorder.status = http.StatusOK
	cacheRecorderPool.Put(recorder)
}

func cacheKey(r *http.Request) string {
	return r.Method + " " + r.URL.RequestURI()
}

func copyResponse(w http.ResponseWriter, recorder *cacheRecorder, cacheState string) {
	dst := w.Header()
	for key, values := range recorder.header {
		dst[key] = append([]string(nil), values...)
	}
	if cacheState != "" {
		dst.Set("X-Waiteway-Cache", cacheState)
	}
	w.WriteHeader(recorder.status)
	_, _ = w.Write(recorder.body.Bytes())
}

func writeCachedResponse(w http.ResponseWriter, cached cachedResponse, cacheState string) {
	dst := w.Header()
	for key, values := range cached.header {
		dst[key] = append([]string(nil), values...)
	}
	if cacheState != "" {
		dst.Set("X-Waiteway-Cache", cacheState)
	}
	w.WriteHeader(cached.status)
	_, _ = w.Write(cached.body)
}

func cloneHeader(header http.Header) http.Header {
	cloned := make(http.Header, len(header))
	for key, values := range header {
		cloned[key] = append([]string(nil), values...)
	}
	return cloned
}

func shouldCacheRouteResponse(route compiledRoute, r *http.Request) bool {
	return route.policy != nil && route.policy.cache != nil && r.Method == http.MethodGet
}
