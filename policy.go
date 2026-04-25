package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

type Policy struct {
	Name                       string
	RequestTimeoutSeconds      int
	RetryCount                 int
	RequireAPIKey              bool
	APIKeys                    []string
	BasicAuthUsername          string
	BasicAuthPassword          string
	RateLimitRequests          int
	RateLimitWindowSeconds     int
	AllowedMethods             []string
	RewritePathPrefix          string
	AddRequestHeaders          []string
	RemoveRequestHeaders       []string
	MaxPayloadBytes            int64
	RequestTransformFind       string
	RequestTransformReplace    string
	CacheTTLSeconds            int
	AddResponseHeaders         []string
	RemoveResponseHeaders      []string
	ResponseTransformFind      string
	ResponseTransformReplace   string
	MaxResponseBytes           int64
	CORSAllowOrigins           []string
	CORSAllowMethods           []string
	CORSAllowHeaders           []string
	IPAllowList                []string
	IPBlockList                []string
	CircuitBreakerFailures     int
	CircuitBreakerResetSeconds int
}

type compiledPolicy struct {
	Policy
	apiKeys               map[string]struct{}
	allowedMethods        map[string]struct{}
	addRequestHeaders     map[string]string
	removeRequestHeaders  map[string]struct{}
	addResponseHeaders    map[string]string
	removeResponseHeaders map[string]struct{}
	requestTimeout        time.Duration
	ipAllowList           []netip.Prefix
	ipBlockList           []netip.Prefix
	rateLimiter           *rateLimiter
	cache                 *responseCache
	circuitBreaker        *circuitBreaker
}

type rateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string][]time.Time
	calls   int
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

type retryTransport struct {
	base    http.RoundTripper
	retries int
}

type circuitBreaker struct {
	mu          sync.Mutex
	threshold   int
	resetWindow time.Duration
	failures    int
	openUntil   time.Time
}

func compilePolicy(policy Policy) (*compiledPolicy, error) {
	policy.RewritePathPrefix = normalizePathPrefix(policy.RewritePathPrefix)
	compiled := &compiledPolicy{
		Policy:  policy,
		apiKeys: make(map[string]struct{}, len(policy.APIKeys)),
	}
	for _, key := range policy.APIKeys {
		if key != "" {
			compiled.apiKeys[key] = struct{}{}
		}
	}
	compiled.allowedMethods = make(map[string]struct{}, len(policy.AllowedMethods))
	for _, method := range policy.AllowedMethods {
		if method != "" {
			compiled.allowedMethods[strings.ToUpper(method)] = struct{}{}
		}
	}

	compiled.addRequestHeaders = parseHeaderMap(policy.AddRequestHeaders)
	compiled.removeRequestHeaders = parseHeaderSet(policy.RemoveRequestHeaders)
	compiled.addResponseHeaders = parseHeaderMap(policy.AddResponseHeaders)
	compiled.removeResponseHeaders = parseHeaderSet(policy.RemoveResponseHeaders)
	compiled.requestTimeout = time.Duration(policy.RequestTimeoutSeconds) * time.Second

	allowList, err := parsePrefixes(policy.IPAllowList)
	if err != nil {
		return nil, fmt.Errorf("parse allow list: %w", err)
	}
	blockList, err := parsePrefixes(policy.IPBlockList)
	if err != nil {
		return nil, fmt.Errorf("parse block list: %w", err)
	}
	compiled.ipAllowList = allowList
	compiled.ipBlockList = blockList

	if policy.RateLimitRequests > 0 && policy.RateLimitWindowSeconds > 0 {
		compiled.rateLimiter = &rateLimiter{
			limit:   policy.RateLimitRequests,
			window:  time.Duration(policy.RateLimitWindowSeconds) * time.Second,
			entries: map[string][]time.Time{},
		}
	}

	if policy.CacheTTLSeconds > 0 {
		compiled.cache = &responseCache{
			ttl:     time.Duration(policy.CacheTTLSeconds) * time.Second,
			entries: map[string]cachedResponse{},
		}
	}

	if policy.CircuitBreakerFailures > 0 && policy.CircuitBreakerResetSeconds > 0 {
		compiled.circuitBreaker = &circuitBreaker{
			threshold:   policy.CircuitBreakerFailures,
			resetWindow: time.Duration(policy.CircuitBreakerResetSeconds) * time.Second,
		}
	}

	return compiled, nil
}

func parseHeaderMap(values []string) map[string]string {
	parsed := map[string]string{}
	for _, value := range values {
		parts := strings.SplitN(value, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(parts[0]))
		body := strings.TrimSpace(parts[1])
		if name == "" {
			continue
		}
		parsed[name] = body
	}
	return parsed
}

func parseHeaderSet(values []string) map[string]struct{} {
	parsed := map[string]struct{}{}
	for _, value := range values {
		name := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(value))
		if name == "" {
			continue
		}
		parsed[name] = struct{}{}
	}
	return parsed
}

func parsePrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		if strings.Contains(value, "/") {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, prefix)
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

func (p *compiledPolicy) blocksIP(ip netip.Addr) bool {
	for _, prefix := range p.ipBlockList {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (p *compiledPolicy) allowsIP(ip netip.Addr) bool {
	if len(p.ipAllowList) == 0 {
		return true
	}
	for _, prefix := range p.ipAllowList {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func remoteIP(remoteAddr string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	host = strings.TrimSpace(host)
	host = strings.Trim(host, "[]")
	return netip.ParseAddr(host)
}

func requestAPIKey(r *http.Request) string {
	key := r.Header.Get("X-API-Key")
	if key != "" {
		return key
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func requestBasicAuth(r *http.Request) (string, string, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func shouldReadBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

func shouldCacheRouteResponse(route compiledRoute, r *http.Request) bool {
	return route.policy != nil && route.policy.cache != nil && r.Method == http.MethodGet
}

func (g *Gateway) authorizePolicy(route compiledRoute, r *http.Request, apiKey string, clientIP netip.Addr, hasClientIP bool, now time.Time) (bool, int, string) {
	if route.policy == nil {
		return true, http.StatusOK, ""
	}

	if route.policy.circuitBreaker != nil && !route.policy.circuitBreaker.Allow(now) {
		return false, http.StatusServiceUnavailable, "circuit open"
	}

	if len(route.policy.allowedMethods) > 0 {
		if _, ok := route.policy.allowedMethods[r.Method]; !ok {
			return false, http.StatusMethodNotAllowed, "method not allowed"
		}
	}

	needsClientIP := len(route.policy.ipAllowList) > 0 || len(route.policy.ipBlockList) > 0 || route.policy.rateLimiter != nil
	if needsClientIP {
		if !hasClientIP {
			return false, http.StatusForbidden, "forbidden"
		}

		if route.policy.blocksIP(clientIP) {
			return false, http.StatusForbidden, "forbidden"
		}
		if !route.policy.allowsIP(clientIP) {
			return false, http.StatusForbidden, "forbidden"
		}
	}

	if err := processRequestBody(route.policy, r); err != nil {
		if err == errPayloadTooLarge {
			return false, http.StatusRequestEntityTooLarge, "payload too large"
		}
		return false, http.StatusBadRequest, "bad request"
	}

	if route.policy.RequireAPIKey && !g.authorizePolicyAPIKey(route.policy, apiKey) {
		return false, http.StatusUnauthorized, "unauthorized"
	}

	if route.policy.BasicAuthUsername != "" || route.policy.BasicAuthPassword != "" {
		username, password, ok := requestBasicAuth(r)
		if !ok || username != route.policy.BasicAuthUsername || password != route.policy.BasicAuthPassword {
			return false, http.StatusUnauthorized, "unauthorized"
		}
	}

	if route.policy.rateLimiter != nil && !route.policy.rateLimiter.Allow(clientIP.String(), now) {
		return false, http.StatusTooManyRequests, "rate limit exceeded"
	}

	applyRequestHeaders(route.policy, r)

	return true, http.StatusOK, ""
}

func (g *Gateway) authorizePolicyAPIKey(policy *compiledPolicy, key string) bool {
	if len(policy.apiKeys) == 0 {
		return key != ""
	}
	_, ok := policy.apiKeys[key]
	return ok
}

func (g *Gateway) cachedPolicyResponse(route compiledRoute, key string, now time.Time) (cachedResponse, bool) {
	if route.policy == nil || route.policy.cache == nil || key == "" || now.IsZero() {
		return cachedResponse{}, false
	}
	return route.policy.cache.Get(key, now)
}

func applyRequestHeaders(policy *compiledPolicy, r *http.Request) {
	for key := range policy.removeRequestHeaders {
		r.Header.Del(key)
	}
	for key, value := range policy.addRequestHeaders {
		r.Header.Set(key, value)
	}
}

var errPayloadTooLarge = fmt.Errorf("payload too large")

func processRequestBody(policy *compiledPolicy, r *http.Request) error {
	if policy == nil || !shouldReadBody(r.Method) {
		return nil
	}
	if policy.MaxPayloadBytes > 0 && r.ContentLength > policy.MaxPayloadBytes {
		return errPayloadTooLarge
	}
	if policy.MaxPayloadBytes <= 0 && policy.RequestTransformFind == "" {
		return nil
	}

	limit := int64(10 << 20)
	if policy.MaxPayloadBytes > 0 {
		limit = policy.MaxPayloadBytes + 1
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, limit))
	if err != nil {
		return err
	}
	if policy.MaxPayloadBytes > 0 && int64(len(body)) > policy.MaxPayloadBytes {
		return errPayloadTooLarge
	}
	if policy.RequestTransformFind != "" {
		body = bytes.ReplaceAll(body, []byte(policy.RequestTransformFind), []byte(policy.RequestTransformReplace))
	}
	setRequestBody(r, body)
	return nil
}

func setRequestBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	r.ContentLength = int64(len(body))
}

func (g *Gateway) storeCachedPolicyResponse(route compiledRoute, key string, now time.Time, recorder *cacheRecorder) {
	if route.policy == nil || route.policy.cache == nil || key == "" || now.IsZero() || recorder.status != http.StatusOK {
		return
	}
	route.policy.cache.Set(key, recorder.status, recorder.header, recorder.body.Bytes(), now)
}

// rateLimiterSweepEvery controls how often Allow sweeps expired keys out of
// the entries map. Amortizes cleanup cost so the hot path stays O(1).
const rateLimiterSweepEvery = 256

func (r *rateLimiter) Allow(key string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := now.Add(-r.window)

	r.calls++
	if r.calls >= rateLimiterSweepEvery {
		r.calls = 0
		for k, hits := range r.entries {
			if k == key {
				continue
			}
			if len(hits) == 0 || !hits[len(hits)-1].After(cutoff) {
				delete(r.entries, k)
			}
		}
	}

	hits := r.entries[key]
	kept := hits[:0]
	for _, hit := range hits {
		if hit.After(cutoff) {
			kept = append(kept, hit)
		}
	}
	if len(kept) >= r.limit {
		r.entries[key] = kept
		return false
	}
	r.entries[key] = append(kept, now)
	return true
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
		bodyBytes, readErr := io.ReadAll(req.Body)
		if readErr != nil {
			return nil, readErr
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		getBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(bodyBytes)), nil }
	} else {
		getBody = func() (io.ReadCloser, error) { return nil, nil }
	}

	for attempt := 0; attempt <= t.retries; attempt++ {
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
	}
	return nil, err
}

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

// responseCacheSweepEvery controls how often Set sweeps expired entries out
// of the cache. Popular-then-cold keys would otherwise accumulate forever.
const responseCacheSweepEvery = 64

func (c *responseCache) Set(key string, status int, header http.Header, body []byte, now time.Time) {
	c.mu.Lock()
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

func copyResponse(w http.ResponseWriter, recorder *cacheRecorder) {
	dst := w.Header()
	for key, values := range recorder.header {
		dst[key] = values
	}
	w.WriteHeader(recorder.status)
	_, _ = w.Write(recorder.body.Bytes())
}

func writeCachedResponse(w http.ResponseWriter, cached cachedResponse) {
	dst := w.Header()
	for key, values := range cached.header {
		dst[key] = values
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

func applyResponsePolicy(policy *compiledPolicy, resp *http.Response) error {
	if policy == nil {
		return nil
	}

	for key := range policy.removeResponseHeaders {
		resp.Header.Del(key)
	}
	for key, value := range policy.addResponseHeaders {
		resp.Header.Set(key, value)
	}

	if len(policy.CORSAllowOrigins) > 0 {
		origin := "*"
		if len(policy.CORSAllowOrigins) == 1 {
			origin = policy.CORSAllowOrigins[0]
		}
		resp.Header.Set("Access-Control-Allow-Origin", origin)
		if len(policy.CORSAllowMethods) > 0 {
			resp.Header.Set("Access-Control-Allow-Methods", strings.Join(policy.CORSAllowMethods, ", "))
		}
		if len(policy.CORSAllowHeaders) > 0 {
			resp.Header.Set("Access-Control-Allow-Headers", strings.Join(policy.CORSAllowHeaders, ", "))
		}
	}

	needsBody := policy.MaxResponseBytes > 0 || policy.ResponseTransformFind != ""
	if !needsBody || resp.Body == nil {
		return nil
	}

	limit := int64(0)
	if policy.MaxResponseBytes > 0 {
		limit = policy.MaxResponseBytes + 1
	} else {
		limit = 10 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if policy.MaxResponseBytes > 0 && int64(len(body)) > policy.MaxResponseBytes {
		return fmt.Errorf("response too large")
	}
	if policy.ResponseTransformFind != "" {
		body = []byte(strings.ReplaceAll(string(body), policy.ResponseTransformFind, policy.ResponseTransformReplace))
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return nil
}

func applyCORSPreflight(policy *compiledPolicy, w http.ResponseWriter, r *http.Request) bool {
	if policy == nil || len(policy.CORSAllowOrigins) == 0 {
		return false
	}
	if r.Method != http.MethodOptions || r.Header.Get("Origin") == "" {
		return false
	}
	origin := "*"
	if len(policy.CORSAllowOrigins) == 1 {
		origin = policy.CORSAllowOrigins[0]
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	if len(policy.CORSAllowMethods) > 0 {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(policy.CORSAllowMethods, ", "))
	}
	if len(policy.CORSAllowHeaders) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(policy.CORSAllowHeaders, ", "))
	}
	w.WriteHeader(http.StatusNoContent)
	return true
}

func requestWithPolicyContext(r *http.Request, policy *compiledPolicy) (*http.Request, context.CancelFunc) {
	if policy == nil || policy.requestTimeout <= 0 {
		return r, func() {}
	}
	ctx, cancel := context.WithTimeout(r.Context(), policy.requestTimeout)
	return r.WithContext(ctx), cancel
}

func routePolicyLabel(route Route) string {
	if route.PolicyName != "" {
		return route.PolicyName
	}
	if route.RequireAPIKey {
		return "legacy api key"
	}
	return "none"
}

func policySummary(policy Policy) string {
	parts := make([]string, 0, 12)
	if policy.RequestTimeoutSeconds > 0 {
		parts = append(parts, fmt.Sprintf("timeout %ds", policy.RequestTimeoutSeconds))
	}
	if policy.RetryCount > 0 {
		parts = append(parts, fmt.Sprintf("retry %d", policy.RetryCount))
	}
	if policy.RequireAPIKey {
		parts = append(parts, "api key")
	}
	if policy.BasicAuthUsername != "" || policy.BasicAuthPassword != "" {
		parts = append(parts, "basic auth")
	}
	if policy.RateLimitRequests > 0 {
		parts = append(parts, fmt.Sprintf("%d/%ds", policy.RateLimitRequests, policy.RateLimitWindowSeconds))
	}
	if len(policy.AllowedMethods) > 0 {
		parts = append(parts, "methods")
	}
	if policy.RewritePathPrefix != "" {
		parts = append(parts, "rewrite")
	}
	if len(policy.AddRequestHeaders) > 0 || len(policy.RemoveRequestHeaders) > 0 {
		parts = append(parts, "request headers")
	}
	if policy.MaxPayloadBytes > 0 {
		parts = append(parts, fmt.Sprintf("payload %d", policy.MaxPayloadBytes))
	}
	if policy.RequestTransformFind != "" {
		parts = append(parts, "request transform")
	}
	if policy.CacheTTLSeconds > 0 {
		parts = append(parts, fmt.Sprintf("cache %ds", policy.CacheTTLSeconds))
	}
	if len(policy.AddResponseHeaders) > 0 || len(policy.RemoveResponseHeaders) > 0 {
		parts = append(parts, "response headers")
	}
	if policy.ResponseTransformFind != "" {
		parts = append(parts, "response transform")
	}
	if policy.MaxResponseBytes > 0 {
		parts = append(parts, fmt.Sprintf("response %d", policy.MaxResponseBytes))
	}
	if len(policy.CORSAllowOrigins) > 0 {
		parts = append(parts, "cors")
	}
	if len(policy.IPAllowList) > 0 || len(policy.IPBlockList) > 0 {
		parts = append(parts, "ip rules")
	}
	if policy.CircuitBreakerFailures > 0 {
		parts = append(parts, "circuit breaker")
	}
	if len(parts) == 0 {
		return "basic"
	}
	return strings.Join(parts, ", ")
}
