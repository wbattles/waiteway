package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

type compiledRoute struct {
	Route
	proxy  *httputil.ReverseProxy
	policy *compiledPolicy
}

type routeMatcher struct {
	buckets map[string][]compiledRoute
	root    []compiledRoute
}

func compileConfig(config Config) ([]compiledRoute, error) {
	policies := make(map[string]*compiledPolicy, len(config.Policies))
	seenPrefixes := make(map[string]string, len(config.Routes))

	for _, policy := range config.Policies {
		compiled, err := compilePolicy(policy)
		if err != nil {
			return nil, fmt.Errorf("compile policy %q: %w", policy.Name, err)
		}
		policies[policy.Name] = compiled
	}

	routes := make([]compiledRoute, 0, len(config.Routes))
	for _, route := range config.Routes {
		route.PathPrefix = normalizePathPrefix(route.PathPrefix)
		if route.PathPrefix == "" || route.Target == "" {
			return nil, errors.New("every route needs path_prefix and target")
		}
		if existingName, ok := seenPrefixes[route.PathPrefix]; ok {
			return nil, fmt.Errorf("route path prefix %q is already in use (conflicts with route %q)", route.PathPrefix, existingName)
		}
		seenPrefixes[route.PathPrefix] = route.Name

		targetURL, err := url.Parse(route.Target)
		if err != nil {
			return nil, fmt.Errorf("parse target %q: %w", route.Target, err)
		}

		var policyRef *compiledPolicy
		if route.PolicyName != "" {
			var ok bool
			policyRef, ok = policies[route.PolicyName]
			if !ok {
				return nil, fmt.Errorf("route %q uses unknown policy %q", route.Name, route.PolicyName)
			}
		}

		proxy, err := newSingleHostProxy(targetURL, route, policyRef)
		if err != nil {
			return nil, fmt.Errorf("build proxy for route %q: %w", route.Name, err)
		}
		routes = append(routes, compiledRoute{
			Route:  route,
			proxy:  proxy,
			policy: policyRef,
		})
	}

	sort.Slice(routes, func(i, j int) bool {
		return len(routes[i].PathPrefix) > len(routes[j].PathPrefix)
	})

	return routes, nil
}

func newSingleHostProxy(target *url.URL, route Route, policy *compiledPolicy) (*httputil.ReverseProxy, error) {
	proxy := httputil.NewSingleHostReverseProxy(target)
	prefixLen := len(route.PathPrefix)
	targetPath := target.Path
	targetQuery := target.RawQuery
	rewritePathPrefix := policyRewritePathPrefix(policy)
	proxy.Director = func(req *http.Request) {
		incomingPath := req.URL.Path
		incomingHost := req.Host
		remainder := incomingPath[prefixLen:]
		if remainder != "" && remainder[0] != '/' {
			remainder = "/" + remainder
		}

		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		if rewritePathPrefix != "" {
			// rewrite takes priority over strip prefix
			req.URL.Path = joinURLPath(targetPath, rewritePathPrefix+remainder)
		} else if route.StripPrefix {
			if remainder == "" || remainder == "/" {
				req.URL.Path = targetPath
			} else {
				req.URL.Path = joinURLPath(targetPath, remainder)
			}
		} else {
			req.URL.Path = joinURLPath(targetPath, incomingPath)
		}
		req.URL.RawPath = ""
		req.URL.RawQuery = joinURLQuery(targetQuery, req.URL.RawQuery)

		req.Host = target.Host
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", "")
		}
		req.Header.Set("X-Forwarded-Host", incomingHost)
		req.Header.Set("X-Waiteway-Route", route.Name)
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		return applyResponsePolicy(policy, resp)
	}
	// Every proxy uses the shared tuned transport so connections can be
	// pooled across routes that hit the same upstream. Routes with retries
	// wrap that same transport so retries reuse the pool too.
	transport, err := sharedTransport()
	if err != nil {
		return nil, err
	}
	if policy != nil && policy.RetryCount > 0 {
		proxy.Transport = &retryTransport{base: transport, retries: policy.RetryCount}
	} else {
		proxy.Transport = transport
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if err != nil && err.Error() == "response too large" {
			http.Error(w, "response too large", http.StatusBadGateway)
			return
		}
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	return proxy, nil
}

func buildRouteMatcher(routes []compiledRoute) *routeMatcher {
	matcher := &routeMatcher{buckets: make(map[string][]compiledRoute)}
	for _, route := range routes {
		key := firstPathSegment(route.PathPrefix)
		if key == "" {
			matcher.root = append(matcher.root, route)
			continue
		}
		matcher.buckets[key] = append(matcher.buckets[key], route)
	}
	for key := range matcher.buckets {
		sort.Slice(matcher.buckets[key], func(i, j int) bool {
			return len(matcher.buckets[key][i].PathPrefix) > len(matcher.buckets[key][j].PathPrefix)
		})
	}
	sort.Slice(matcher.root, func(i, j int) bool {
		return len(matcher.root[i].PathPrefix) > len(matcher.root[j].PathPrefix)
	})
	return matcher
}

func (g *Gateway) matchRoute(path string) (compiledRoute, bool) {
	matcher := g.compiledState().routeMatcher
	for _, route := range matcher.buckets[firstPathSegment(path)] {
		if routeMatchesPath(route.PathPrefix, path) {
			return route, true
		}
	}
	for _, route := range matcher.root {
		if routeMatchesPath(route.PathPrefix, path) {
			return route, true
		}
	}

	return compiledRoute{}, false
}

func routeNeedsAPIKey(route compiledRoute) bool {
	return route.policy != nil && route.policy.RequireAPIKey
}

func routeNeedsClientAddr(route compiledRoute) bool {
	if route.policy == nil {
		return false
	}
	return len(route.policy.ipAllowList) > 0 || len(route.policy.ipBlockList) > 0 || route.policy.rateLimiter != nil
}

func routeNeedsPolicyNow(route compiledRoute) bool {
	if route.policy == nil {
		return false
	}
	return route.policy.circuitBreaker != nil || route.policy.rateLimiter != nil
}

func routeMatchesPath(prefix, path string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	if path == prefix || prefix == "/" {
		return true
	}
	// prefixes are normalized without trailing slash, so require a
	// segment boundary after the prefix to avoid matching /apifoo against /api
	return strings.HasPrefix(path[len(prefix):], "/")
}

func joinURLPath(basePath, extraPath string) string {
	switch {
	case basePath == "":
		return extraPath
	case extraPath == "":
		return basePath
	case strings.HasSuffix(basePath, "/") && strings.HasPrefix(extraPath, "/"):
		return basePath + strings.TrimPrefix(extraPath, "/")
	case !strings.HasSuffix(basePath, "/") && !strings.HasPrefix(extraPath, "/"):
		return basePath + "/" + extraPath
	default:
		return basePath + extraPath
	}
}

func joinURLQuery(targetQuery, requestQuery string) string {
	switch {
	case targetQuery == "":
		return requestQuery
	case requestQuery == "":
		return targetQuery
	default:
		return targetQuery + "&" + requestQuery
	}
}

func policyRewritePathPrefix(policy *compiledPolicy) string {
	if policy == nil {
		return ""
	}
	return policy.RewritePathPrefix
}

func firstPathSegment(path string) string {
	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "" {
		return ""
	}
	segment, _, _ := strings.Cut(trimmed, "/")
	return segment
}

func normalizePathPrefix(value string) string {
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	for len(value) > 1 && strings.HasSuffix(value, "/") {
		value = strings.TrimRight(value, "/")
	}
	return value
}

type compiledClientIPConfig struct {
	stripPort bool
	headers   []string
}

func (g *Gateway) clientIP(r *http.Request) string {
	state := g.compiledState()
	for _, name := range state.clientIP.headers {
		if ip := requestIPCandidate(r, name, state.clientIP.stripPort); ip != "" {
			return ip
		}
	}

	if ip := normalizeClientIP(r.RemoteAddr, state.clientIP.stripPort); ip != "" {
		return ip
	}

	return strings.TrimSpace(r.RemoteAddr)
}

func clientIPHeaderChain(config LoadBalancerConfig) []string {
	config = normalizeLoadBalancerConfig(config)

	switch config.Mode {
	case "cloudflare":
		return []string{"CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP", "Forwarded", "RemoteAddr"}
	case "standard":
		return []string{"X-Forwarded-For", "X-Real-IP", "Forwarded", "RemoteAddr"}
	case "custom":
		chain := []string{}
		if config.ClientIPHeader != "" {
			chain = append(chain, config.ClientIPHeader)
		}
		for _, header := range []string{"X-Forwarded-For", "X-Real-IP", "Forwarded", "RemoteAddr"} {
			if !strings.EqualFold(header, config.ClientIPHeader) {
				chain = append(chain, header)
			}
		}
		return chain
	default:
		return []string{"RemoteAddr"}
	}
}

func requestIPCandidate(r *http.Request, headerName string, stripPort bool) string {
	switch headerName {
	case "RemoteAddr":
		return ""
	case "X-Forwarded-For":
		return firstForwardedIP(r.Header.Get(headerName), stripPort)
	case "Forwarded":
		return firstStandardForwardedIP(r.Header.Get(headerName), stripPort)
	default:
		return normalizeClientIP(r.Header.Get(headerName), stripPort)
	}
}

func firstForwardedIP(value string, stripPort bool) string {
	for _, part := range strings.Split(value, ",") {
		if ip := normalizeClientIP(part, stripPort); ip != "" {
			return ip
		}
	}
	return ""
}

func firstStandardForwardedIP(value string, stripPort bool) string {
	for _, entry := range strings.Split(value, ",") {
		for _, part := range strings.Split(entry, ";") {
			key, value, ok := strings.Cut(part, "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "for") {
				continue
			}
			if ip := normalizeClientIP(value, stripPort); ip != "" {
				return ip
			}
		}
	}
	return ""
}

func normalizeClientIP(value string, stripPort bool) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	if value == "" || strings.EqualFold(value, "unknown") {
		return ""
	}

	if !stripPort {
		return value
	}

	if ip := cleanForwardedIP(value); ip != "" {
		if addr, err := netip.ParseAddr(ip); err == nil {
			return addr.String()
		}
		return ip
	}

	if addr, err := remoteIP(value); err == nil {
		return addr.String()
	}

	return value
}

func cleanForwardedIP(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	if value == "" || strings.EqualFold(value, "unknown") {
		return ""
	}

	if strings.HasPrefix(value, "[") {
		if addr, err := netip.ParseAddrPort(value); err == nil {
			return addr.Addr().String()
		}
	}

	if host, _, found := strings.Cut(value, ":"); found && strings.Count(value, ":") == 1 {
		return strings.TrimSpace(host)
	}

	return strings.Trim(value, "[]")
}

func parseClientAddr(value string) (netip.Addr, bool) {
	if value == "" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(value)
	if err == nil {
		return addr, true
	}
	addr, err = remoteIP(value)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

func compileClientIPConfig(config LoadBalancerConfig) compiledClientIPConfig {
	config = normalizeLoadBalancerConfig(config)
	return compiledClientIPConfig{
		stripPort: config.StripPort,
		headers:   clientIPHeaderChain(config),
	}
}

func normalizeLoadBalancerConfig(config LoadBalancerConfig) LoadBalancerConfig {
	mode := strings.ToLower(strings.TrimSpace(config.Mode))
	switch mode {
	case "", "direct", "standard", "cloudflare", "custom":
	default:
		mode = "direct"
	}
	if mode == "" {
		mode = "direct"
	}

	config.Mode = mode
	config.ClientIPHeader = strings.TrimSpace(config.ClientIPHeader)
	if mode != "custom" {
		config.ClientIPHeader = ""
	}

	return config
}
