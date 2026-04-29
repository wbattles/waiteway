package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type Gateway struct {
	mu           sync.RWMutex
	store        *Store
	config       Config
	state        atomic.Pointer[compiledGatewayState]
	tmpl         *template.Template
	usersTmpl    *template.Template
	settingsTmpl *template.Template
	loginTmpl    *template.Template
	startedAt    time.Time
	listenAddr   string
	adminListen  string

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

type compiledGatewayState struct {
	routeMatcher *routeMatcher
	clientIP     compiledClientIPConfig
	logLimit     int
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func newGateway(store *Store, config Config) (*Gateway, error) {
	tmpl, err := template.New("admin").Funcs(template.FuncMap{
		"formatDurationMS":  formatDurationMS,
		"formatClientIP":    formatClientIP,
		"formatPercent":     formatPercent,
		"routePolicyLabel":  routePolicyLabel,
		"policySummary":     policySummary,
		"policyButtonAttrs": policyButtonAttrs,
	}).Parse(adminTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse admin template: %w", err)
	}

	loginTmpl, err := template.New("login").Parse(loginTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse login template: %w", err)
	}

	usersTmpl, err := template.New("users").Parse(usersAdminTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse users template: %w", err)
	}

	settingsTmpl, err := template.New("settings").Parse(settingsTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse settings template: %w", err)
	}

	g := &Gateway{
		store:        store,
		startedAt:    time.Now(),
		tmpl:         tmpl,
		usersTmpl:    usersTmpl,
		settingsTmpl: settingsTmpl,
		loginTmpl:    loginTmpl,
		listenAddr:   envOrDefault("WAITEWAY_LISTEN", ":8080"),
		adminListen:  envOrDefault("WAITEWAY_ADMIN_LISTEN", ":9090"),
		logCh:        make(chan requestLog, 1024),
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
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
	var requestUser User
	var hasRequestUser bool
	if routeNeedsAPIKey(route) {
		apiKey = requestAPIKey(r)
		requestUser, hasRequestUser = g.requestUser(r)
	}

	needsClientIP := routeNeedsClientAddr(route)
	clientIP := ""
	if needsClientIP {
		clientIP = g.clientIP(r)
	}

	if route.RequireAPIKey && !g.authorizeRouteAPIKey(route, apiKey, requestUser, hasRequestUser) {
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

	if ok, status, message := g.authorizePolicy(route, r, apiKey, requestUser, hasRequestUser, clientAddr, hasClientAddr, now); !ok {
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

type requestLog struct {
	Time       time.Time
	Method     string
	Path       string
	Status     int
	Route      string
	RemoteAddr string
	Duration   time.Duration
}

var logBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 256)
		return &buf
	},
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
