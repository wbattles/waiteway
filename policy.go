package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"strings"
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
