package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type Policy struct {
	Name                   string
	RequireAPIKey          bool
	APIKeys                []string
	RateLimitRequests      int
	RateLimitWindowSeconds int
	MaxPayloadBytes        int64
	CacheTTLSeconds        int
	IPAllowList            []string
	IPBlockList            []string
}

type compiledPolicy struct {
	Policy
	apiKeys     map[string]struct{}
	ipAllowList []netip.Prefix
	ipBlockList []netip.Prefix
	rateLimiter *rateLimiter
	cache       *responseCache
}

type rateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string][]time.Time
}

type responseCache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[string]cachedResponse
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

func compilePolicy(policy Policy) (*compiledPolicy, error) {
	compiled := &compiledPolicy{
		Policy:  policy,
		apiKeys: make(map[string]struct{}, len(policy.APIKeys)),
	}
	for _, key := range policy.APIKeys {
		if key != "" {
			compiled.apiKeys[key] = struct{}{}
		}
	}

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

	return compiled, nil
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

func (g *Gateway) authorizePolicy(route compiledRoute, r *http.Request) (bool, int, string) {
	if route.policy == nil {
		return true, http.StatusOK, ""
	}

	ip, err := remoteIP(r.RemoteAddr)
	if err != nil {
		return false, http.StatusForbidden, "forbidden"
	}

	if route.policy.blocksIP(ip) {
		return false, http.StatusForbidden, "forbidden"
	}
	if !route.policy.allowsIP(ip) {
		return false, http.StatusForbidden, "forbidden"
	}

	if route.policy.MaxPayloadBytes > 0 {
		if r.ContentLength > route.policy.MaxPayloadBytes {
			return false, http.StatusRequestEntityTooLarge, "payload too large"
		}
		if shouldReadBody(r.Method) {
			body, err := io.ReadAll(io.LimitReader(r.Body, route.policy.MaxPayloadBytes+1))
			if err != nil {
				return false, http.StatusBadRequest, "bad request"
			}
			if int64(len(body)) > route.policy.MaxPayloadBytes {
				return false, http.StatusRequestEntityTooLarge, "payload too large"
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}
	}

	if route.policy.RequireAPIKey && !g.authorizePolicyAPIKey(route.policy, r) {
		return false, http.StatusUnauthorized, "unauthorized"
	}

	if route.policy.rateLimiter != nil && !route.policy.rateLimiter.Allow(ip.String(), time.Now()) {
		return false, http.StatusTooManyRequests, "rate limit exceeded"
	}

	return true, http.StatusOK, ""
}

func (g *Gateway) authorizePolicyAPIKey(policy *compiledPolicy, r *http.Request) bool {
	key := requestAPIKey(r)
	if len(policy.apiKeys) == 0 {
		return key != ""
	}
	_, ok := policy.apiKeys[key]
	return ok
}

func (g *Gateway) cachedPolicyResponse(route compiledRoute, r *http.Request) (cachedResponse, bool) {
	if !shouldCacheRouteResponse(route, r) {
		return cachedResponse{}, false
	}
	return route.policy.cache.Get(cacheKey(r), time.Now())
}

func (g *Gateway) storeCachedPolicyResponse(route compiledRoute, r *http.Request, recorder *cacheRecorder) {
	if !shouldCacheRouteResponse(route, r) || recorder.status != http.StatusOK {
		return
	}
	route.policy.cache.Set(cacheKey(r), recorder.status, recorder.header, recorder.body.Bytes(), time.Now())
}

func (r *rateLimiter) Allow(key string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	hits := r.entries[key]
	cutoff := now.Add(-r.window)
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

func (c *responseCache) Get(key string, now time.Time) (cachedResponse, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || now.After(entry.expiresAt) {
		if ok {
			c.mu.Lock()
			delete(c.entries, key)
			c.mu.Unlock()
		}
		return cachedResponse{}, false
	}
	return entry, true
}

func (c *responseCache) Set(key string, status int, header http.Header, body []byte, now time.Time) {
	c.mu.Lock()
	c.entries[key] = cachedResponse{
		status:    status,
		header:    cloneHeader(header),
		body:      append([]byte(nil), body...),
		expiresAt: now.Add(c.ttl),
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

func cacheKey(r *http.Request) string {
	return r.Method + " " + r.URL.RequestURI()
}

func copyResponse(w http.ResponseWriter, recorder *cacheRecorder) {
	for key, values := range recorder.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(recorder.status)
	_, _ = w.Write(recorder.body.Bytes())
}

func writeCachedResponse(w http.ResponseWriter, cached cachedResponse) {
	for key, values := range cached.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
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
	parts := make([]string, 0, 5)
	if policy.RequireAPIKey {
		parts = append(parts, "api key")
	}
	if policy.RateLimitRequests > 0 {
		parts = append(parts, fmt.Sprintf("%d/%ds", policy.RateLimitRequests, policy.RateLimitWindowSeconds))
	}
	if policy.MaxPayloadBytes > 0 {
		parts = append(parts, fmt.Sprintf("payload %d", policy.MaxPayloadBytes))
	}
	if policy.CacheTTLSeconds > 0 {
		parts = append(parts, fmt.Sprintf("cache %ds", policy.CacheTTLSeconds))
	}
	if len(policy.IPAllowList) > 0 || len(policy.IPBlockList) > 0 {
		parts = append(parts, "ip rules")
	}
	if len(parts) == 0 {
		return "basic"
	}
	return strings.Join(parts, ", ")
}
