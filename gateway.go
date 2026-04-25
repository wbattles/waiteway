package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Gateway struct {
	mu          sync.RWMutex
	store       *Store
	config      Config
	state       atomic.Pointer[compiledGatewayState]
	tmpl        *template.Template
	loginTmpl   *template.Template
	startedAt   time.Time
	listenAddr  string
	adminListen string

	logCh     chan requestLog
	stopCh    chan struct{}
	doneCh    chan struct{}
	metrics   gatewayMetrics
	closeOnce sync.Once
}

type gatewayMetrics struct {
	requestsTotal uint64
	errorsTotal   uint64
}

type compiledRoute struct {
	Route
	proxy   *httputil.ReverseProxy
	apiKeys map[string]struct{}
	policy  *compiledPolicy
}

type compiledGatewayState struct {
	routeMatcher *routeMatcher
	clientIP     compiledClientIPConfig
	logLimit     int
}

type routeMatcher struct {
	buckets map[string][]compiledRoute
	root    []compiledRoute
}

type compiledClientIPConfig struct {
	stripPort bool
	headers   []string
}

type requestLog struct {
	Time       time.Time
	Method     string
	Path       string
	Status     int
	Route      string
	RemoteAddr string
	Duration   time.Duration
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

var logBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 256)
		return &buf
	},
}

func newGateway(store *Store, config Config) (*Gateway, error) {
	tmpl, err := template.New("admin").Funcs(template.FuncMap{
		"formatDurationMS": formatDurationMS,
		"formatClientIP":   formatClientIP,
		"formatPercent":    formatPercent,
		"routePolicyLabel": routePolicyLabel,
		"policySummary":    policySummary,
	}).Parse(adminTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse admin template: %w", err)
	}

	loginTmpl, err := template.New("login").Parse(loginTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse login template: %w", err)
	}

	g := &Gateway{
		store:       store,
		startedAt:   time.Now(),
		tmpl:        tmpl,
		loginTmpl:   loginTmpl,
		listenAddr:  envOrDefault("WAITEWAY_LISTEN", ":8080"),
		adminListen: envOrDefault("WAITEWAY_ADMIN_LISTEN", ":9090"),
		logCh:       make(chan requestLog, 1024),
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}

	if err := g.applyConfig(config); err != nil {
		return nil, err
	}

	go g.drainLogs()

	return g, nil
}

// Close stops the background log drainer and waits for it to finish. Pending
// in-memory log entries are flushed to the store before returning. Safe to
// call from multiple goroutines.
func (g *Gateway) Close() {
	g.closeOnce.Do(func() { close(g.stopCh) })
	<-g.doneCh
}

func (g *Gateway) applyConfig(config Config) error {
	config.LoadBalancer = normalizeLoadBalancerConfig(config.LoadBalancer)
	routes, err := compileConfig(config)
	if err != nil {
		return err
	}
	state := &compiledGatewayState{
		routeMatcher: buildRouteMatcher(routes),
		clientIP:     compileClientIPConfig(config.LoadBalancer),
		logLimit:     config.LogLimit,
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	g.config = config
	g.state.Store(state)
	return nil
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

		routeAPIKeys := make(map[string]struct{}, len(route.APIKeys))
		for _, key := range route.APIKeys {
			if key == "" {
				continue
			}
			routeAPIKeys[key] = struct{}{}
		}

		var policyRef *compiledPolicy
		if route.PolicyName != "" {
			var ok bool
			policyRef, ok = policies[route.PolicyName]
			if !ok {
				return nil, fmt.Errorf("route %q uses unknown policy %q", route.Name, route.PolicyName)
			}
		}

		proxy := newSingleHostProxy(targetURL, route, policyRef)
		routes = append(routes, compiledRoute{
			Route:   route,
			proxy:   proxy,
			apiKeys: routeAPIKeys,
			policy:  policyRef,
		})
	}

	sort.Slice(routes, func(i, j int) bool {
		return len(routes[i].PathPrefix) > len(routes[j].PathPrefix)
	})

	return routes, nil
}

func newSingleHostProxy(target *url.URL, route Route, policy *compiledPolicy) *httputil.ReverseProxy {
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
	transport := sharedTransport()
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

	return proxy
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

func (g *Gateway) gatewayHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/", g.handleProxy)
	return mux
}

func (g *Gateway) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/favicon.ico" {
		http.NotFound(w, r)
		return
	}

	route, ok := g.matchRoute(r.URL.Path)
	if !ok {
		clientIP := g.clientIP(r)
		g.recordRequest(r, clientIP, "", http.StatusNotFound, 0, time.Now())
		http.NotFound(w, r)
		return
	}

	var apiKey string
	if routeNeedsAPIKey(route) {
		apiKey = requestAPIKey(r)
	}

	needsClientIP := routeNeedsClientAddr(route)
	clientIP := ""
	if needsClientIP {
		clientIP = g.clientIP(r)
	}

	if route.RequireAPIKey && !g.authorizeAPIKey(route, apiKey) {
		if clientIP == "" {
			clientIP = g.clientIP(r)
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		g.recordRequest(r, clientIP, route.Name, http.StatusUnauthorized, 0, time.Now())
		return
	}

	if applyCORSPreflight(route.policy, w, r) {
		if clientIP == "" {
			clientIP = g.clientIP(r)
		}
		g.recordRequest(r, clientIP, route.Name, http.StatusNoContent, 0, time.Now())
		return
	}

	var clientAddr netip.Addr
	hasClientAddr := false
	if needsClientIP {
		clientAddr, hasClientAddr = parseClientAddr(clientIP)
	}

	now := time.Time{}
	if routeNeedsPolicyNow(route) {
		now = time.Now()
	}

	if ok, status, message := g.authorizePolicy(route, r, apiKey, clientAddr, hasClientAddr, now); !ok {
		if clientIP == "" {
			clientIP = g.clientIP(r)
		}
		http.Error(w, message, status)
		g.recordRequest(r, clientIP, route.Name, status, 0, time.Now())
		return
	}

	r, cancelTimeout := requestWithPolicyContext(r, route.policy)
	defer cancelTimeout()

	cacheable := shouldCacheRouteResponse(route, r)
	cacheKeyValue := ""
	cacheNow := time.Time{}
	if cacheable {
		cacheKeyValue = cacheKey(r)
		cacheNow = time.Now()
		if cached, ok := g.cachedPolicyResponse(route, cacheKeyValue, cacheNow); ok {
			if clientIP == "" {
				clientIP = g.clientIP(r)
			}
			writeCachedResponse(w, cached, "HIT")
			g.recordRequest(r, clientIP, route.Name, cached.status, 0, cacheNow)
			return
		}
	}

	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	var writer http.ResponseWriter = recorder
	var cacheBuf *cacheRecorder
	if cacheable {
		cacheBuf = getCacheRecorder()
		writer = cacheBuf
	}

	start := time.Now()
	route.proxy.ServeHTTP(writer, r)
	end := time.Now()

	if cacheBuf != nil {
		copyResponse(w, cacheBuf, "MISS")
		recorder.status = cacheBuf.status
		g.storeCachedPolicyResponse(route, cacheKeyValue, cacheNow, cacheBuf)
		putCacheRecorder(cacheBuf)
	}
	if route.policy != nil && route.policy.circuitBreaker != nil {
		if recorder.status >= http.StatusInternalServerError {
			route.policy.circuitBreaker.RecordFailure(end)
		} else {
			route.policy.circuitBreaker.RecordSuccess()
		}
	}
	if clientIP == "" {
		clientIP = g.clientIP(r)
	}
	g.recordRequest(r, clientIP, route.Name, recorder.status, end.Sub(start), end)
}

func (g *Gateway) recordRequest(r *http.Request, clientIP, routeName string, status int, duration time.Duration, now time.Time) {
	entry := requestLog{
		Time:       now,
		Method:     r.Method,
		Path:       r.URL.Path,
		Status:     status,
		Route:      routeName,
		RemoteAddr: clientIP,
		Duration:   duration,
	}

	atomic.AddUint64(&g.metrics.requestsTotal, 1)
	if status >= http.StatusInternalServerError {
		atomic.AddUint64(&g.metrics.errorsTotal, 1)
	}

	// Non-blocking send keeps the request hot path free of SQLite writes.
	// If the drainer falls behind, drop the entry rather than slow requests.
	select {
	case g.logCh <- entry:
	default:
	}
}

func (g *Gateway) logRequest(entry requestLog) {
	// Hand-built JSON to avoid the map[string]any + reflection overhead of
	// json.Marshal on every log entry. Field order is intentional and stable.
	bufPtr := logBufferPool.Get().(*[]byte)
	buf := (*bufPtr)[:0]
	buf = append(buf, '{', '"', 't', 'i', 'm', 'e', '"', ':', '"')
	buf = entry.Time.AppendFormat(buf, time.RFC3339Nano)
	buf = append(buf, `","level":"info","event":"request","method":`...)
	buf = appendJSONString(buf, entry.Method)
	buf = append(buf, `,"path":`...)
	buf = appendJSONString(buf, entry.Path)
	buf = append(buf, `,"route":`...)
	buf = appendJSONString(buf, entry.Route)
	buf = append(buf, `,"status":`...)
	buf = strconv.AppendInt(buf, int64(entry.Status), 10)
	buf = append(buf, `,"ip":`...)
	buf = appendJSONString(buf, entry.RemoteAddr)
	buf = append(buf, `,"duration_ms":`...)
	buf = strconv.AppendFloat(buf, float64(entry.Duration)/float64(time.Millisecond), 'f', -1, 64)
	buf = append(buf, '}', '\n')

	if _, err := os.Stdout.Write(buf); err != nil {
		log.Printf("waiteway failed to write request log: %v", err)
	}
	*bufPtr = buf[:0]
	logBufferPool.Put(bufPtr)
}

func appendJSONString(buf []byte, s string) []byte {
	encoded, err := json.Marshal(s)
	if err != nil {
		return append(buf, '"', '"')
	}
	return append(buf, encoded...)
}

// drainLogs is a single background consumer for request logs. It writes each
// entry to the store and periodically trims the log table so it cannot grow
// unbounded. Exits when stopCh is closed, flushing any pending entries first.
func (g *Gateway) drainLogs() {
	defer close(g.doneCh)
	const trimEvery = 100
	count := 0

	write := func(entry requestLog) {
		g.logRequest(entry)
		if err := g.store.AddLog(entry); err != nil {
			log.Printf("waiteway failed to store request log: %v", err)
			return
		}
		count++
		if count >= trimEvery {
			count = 0
			limit := g.compiledState().logLimit
			if limit > 0 {
				if err := g.store.TrimLogs(limit); err != nil {
					log.Printf("waiteway failed to trim logs: %v", err)
				}
			}
		}
	}

	for {
		select {
		case <-g.stopCh:
			// flush any remaining entries then exit
			for {
				select {
				case entry := <-g.logCh:
					write(entry)
				default:
					return
				}
			}
		case entry := <-g.logCh:
			write(entry)
		}
	}
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

	if host, _, err := strings.Cut(value, ":"); err && strings.Count(value, ":") == 1 {
		return strings.TrimSpace(host)
	}

	return strings.Trim(value, "[]")
}

func (g *Gateway) authorizeAPIKey(route compiledRoute, key string) bool {
	if len(route.apiKeys) == 0 {
		return false
	}
	_, ok := route.apiKeys[key]
	return ok
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
	return route.RequireAPIKey || (route.policy != nil && route.policy.RequireAPIKey)
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

func (g *Gateway) currentConfig() Config {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.config
}

func (g *Gateway) compiledState() *compiledGatewayState {
	state := g.state.Load()
	if state == nil {
		return &compiledGatewayState{
			routeMatcher: &routeMatcher{buckets: map[string][]compiledRoute{}},
			clientIP: compiledClientIPConfig{
				stripPort: true,
				headers:   []string{"RemoteAddr"},
			},
		}
	}
	return state
}

func (s *statusRecorder) WriteHeader(statusCode int) {
	s.status = statusCode
	s.ResponseWriter.WriteHeader(statusCode)
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

func policyRewritePathPrefix(policy *compiledPolicy) string {
	if policy == nil {
		return ""
	}
	return policy.RewritePathPrefix
}

func compileClientIPConfig(config LoadBalancerConfig) compiledClientIPConfig {
	config = normalizeLoadBalancerConfig(config)
	return compiledClientIPConfig{
		stripPort: config.StripPort,
		headers:   clientIPHeaderChain(config),
	}
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
	return matcher
}

func firstPathSegment(path string) string {
	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "" {
		return ""
	}
	segment, _, _ := strings.Cut(trimmed, "/")
	return segment
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
