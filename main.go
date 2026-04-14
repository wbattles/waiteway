package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Listen   string      `json:"listen"`
	Admin    AdminConfig `json:"admin"`
	APIKeys  []string    `json:"api_keys"`
	LogLimit int         `json:"log_limit"`
	Routes   []Route     `json:"routes"`
}

type AdminConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Route struct {
	Name          string `json:"name"`
	PathPrefix    string `json:"path_prefix"`
	Target        string `json:"target"`
	RequireAPIKey bool   `json:"require_api_key"`
	StripPrefix   bool   `json:"strip_prefix"`
}

type Gateway struct {
	config  Config
	routes  []compiledRoute
	apiKeys map[string]struct{}
	logs    *requestLogStore
	tmpl    *template.Template
}

type compiledRoute struct {
	Route
	targetURL *url.URL
	proxy     *httputil.ReverseProxy
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

type requestLogStore struct {
	mu      sync.Mutex
	limit   int
	entries []requestLog
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

type adminPageData struct {
	Listen string
	Routes []Route
	Logs   []requestLog
	Now    time.Time
}

const defaultConfigPath = "waiteway.json"

func main() {
	configPath := defaultConfigPath
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatal(err)
	}

	gateway, err := newGateway(config)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("waiteway listening on %s", config.Listen)
	if err := http.ListenAndServe(config.Listen, gateway.routesHandler()); err != nil {
		log.Fatal(err)
	}
}

func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	if config.Listen == "" {
		config.Listen = ":8080"
	}
	if config.LogLimit <= 0 {
		config.LogLimit = 100
	}

	if len(config.Routes) == 0 {
		return Config{}, errors.New("config needs at least one route")
	}

	return config, nil
}

func newGateway(config Config) (*Gateway, error) {
	tmpl, err := template.New("admin").Parse(adminTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse admin template: %w", err)
	}

	g := &Gateway{
		config:  config,
		apiKeys: make(map[string]struct{}, len(config.APIKeys)),
		logs:    &requestLogStore{limit: config.LogLimit},
		tmpl:    tmpl,
	}

	for _, key := range config.APIKeys {
		if key == "" {
			continue
		}
		g.apiKeys[key] = struct{}{}
	}

	routes := make([]compiledRoute, 0, len(config.Routes))
	for _, route := range config.Routes {
		if route.PathPrefix == "" || route.Target == "" {
			return nil, errors.New("every route needs path_prefix and target")
		}

		targetURL, err := url.Parse(route.Target)
		if err != nil {
			return nil, fmt.Errorf("parse target %q: %w", route.Target, err)
		}

		proxy := newSingleHostProxy(targetURL, route)
		routes = append(routes, compiledRoute{
			Route:     route,
			targetURL: targetURL,
			proxy:     proxy,
		})
	}

	sort.Slice(routes, func(i, j int) bool {
		return len(routes[i].PathPrefix) > len(routes[j].PathPrefix)
	})

	g.routes = routes
	return g, nil
}

func newSingleHostProxy(target *url.URL, route Route) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		incomingPath := req.URL.Path
		if route.StripPrefix {
			trimmed := strings.TrimPrefix(incomingPath, route.PathPrefix)
			if trimmed == "" {
				trimmed = "/"
			}
			if !strings.HasPrefix(trimmed, "/") {
				trimmed = "/" + trimmed
			}
			req.URL.Path = joinURLPath(target.Path, trimmed)
		} else {
			req.URL.Path = joinURLPath(target.Path, incomingPath)
		}

		req.Host = target.Host
		req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
		req.Header.Set("X-Waiteway-Route", route.Name)
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	return proxy
}

func (g *Gateway) routesHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/admin", g.handleAdmin)
	mux.HandleFunc("/admin/", g.handleAdmin)
	mux.HandleFunc("/", g.handleProxy)
	return mux
}

func (g *Gateway) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if !g.authorizeAdmin(w, r) {
		return
	}

	data := adminPageData{
		Listen: g.config.Listen,
		Logs:   g.logs.list(),
		Now:    time.Now(),
	}

	data.Routes = make([]Route, 0, len(g.routes))
	for _, route := range g.routes {
		data.Routes = append(data.Routes, route.Route)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := g.tmpl.Execute(w, data); err != nil {
		http.Error(w, "admin render failed", http.StatusInternalServerError)
	}
}

func (g *Gateway) authorizeAdmin(w http.ResponseWriter, r *http.Request) bool {
	if g.config.Admin.Username == "" && g.config.Admin.Password == "" {
		return true
	}

	username, password, ok := r.BasicAuth()
	if ok && username == g.config.Admin.Username && password == g.config.Admin.Password {
		return true
	}

	w.Header().Set("WWW-Authenticate", `Basic realm="waiteway admin"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

func (g *Gateway) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/favicon.ico" {
		http.NotFound(w, r)
		return
	}

	route, ok := g.matchRoute(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}

	if route.RequireAPIKey && !g.authorizeAPIKey(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		g.logs.add(requestLog{
			Time:       time.Now(),
			Method:     r.Method,
			Path:       r.URL.Path,
			Status:     http.StatusUnauthorized,
			Route:      route.Name,
			RemoteAddr: r.RemoteAddr,
		})
		return
	}

	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	start := time.Now()
	route.proxy.ServeHTTP(recorder, r)
	g.logs.add(requestLog{
		Time:       time.Now(),
		Method:     r.Method,
		Path:       r.URL.Path,
		Status:     recorder.status,
		Route:      route.Name,
		RemoteAddr: r.RemoteAddr,
		Duration:   time.Since(start),
	})
}

func (g *Gateway) authorizeAPIKey(r *http.Request) bool {
	if len(g.apiKeys) == 0 {
		return false
	}

	key := r.Header.Get("X-API-Key")
	if key == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			key = strings.TrimPrefix(auth, "Bearer ")
		}
	}

	_, ok := g.apiKeys[key]
	return ok
}

func (g *Gateway) matchRoute(path string) (compiledRoute, bool) {
	for _, route := range g.routes {
		if strings.HasPrefix(path, route.PathPrefix) {
			return route, true
		}
	}

	return compiledRoute{}, false
}

func (l *requestLogStore) add(entry requestLog) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.entries = append([]requestLog{entry}, l.entries...)
	if len(l.entries) > l.limit {
		l.entries = l.entries[:l.limit]
	}
}

func (l *requestLogStore) list() []requestLog {
	l.mu.Lock()
	defer l.mu.Unlock()

	entries := make([]requestLog, len(l.entries))
	copy(entries, l.entries)
	return entries
}

func (s *statusRecorder) WriteHeader(statusCode int) {
	s.status = statusCode
	s.ResponseWriter.WriteHeader(statusCode)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
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

const adminTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Waiteway Admin</title>
  <style>
    :root {
      color-scheme: light dark;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
    }
    body {
      margin: 0;
      padding: 2rem;
      background: #111;
      color: #f5f5f5;
    }
    main {
      max-width: 980px;
      margin: 0 auto;
    }
    h1, h2 {
      font-weight: 600;
    }
    .card {
      background: #1a1a1a;
      border: 1px solid #2f2f2f;
      border-radius: 12px;
      padding: 1rem;
      margin: 0 0 1rem;
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      text-align: left;
      padding: 0.6rem;
      border-bottom: 1px solid #2f2f2f;
      vertical-align: top;
    }
    .muted {
      color: #b5b5b5;
    }
    code {
      font-family: ui-monospace, SFMono-Regular, monospace;
    }
  </style>
</head>
<body>
  <main>
    <h1>Waiteway</h1>
    <p class="muted">simple api gateway and admin portal</p>

    <section class="card">
      <h2>Server</h2>
      <p><strong>listen:</strong> <code>{{ .Listen }}</code></p>
      <p><strong>time:</strong> <code>{{ .Now.Format "2006-01-02 15:04:05 MST" }}</code></p>
    </section>

    <section class="card">
      <h2>Routes</h2>
      <table>
        <thead>
          <tr>
            <th>name</th>
            <th>path</th>
            <th>target</th>
            <th>api key</th>
          </tr>
        </thead>
        <tbody>
          {{ range .Routes }}
          <tr>
            <td>{{ .Name }}</td>
            <td><code>{{ .PathPrefix }}</code></td>
            <td><code>{{ .Target }}</code></td>
            <td>{{ if .RequireAPIKey }}yes{{ else }}no{{ end }}</td>
          </tr>
          {{ end }}
        </tbody>
      </table>
    </section>

    <section class="card">
      <h2>Recent Requests</h2>
      <table>
        <thead>
          <tr>
            <th>time</th>
            <th>route</th>
            <th>request</th>
            <th>status</th>
            <th>duration</th>
          </tr>
        </thead>
        <tbody>
          {{ range .Logs }}
          <tr>
            <td><code>{{ .Time.Format "15:04:05" }}</code></td>
            <td>{{ .Route }}</td>
            <td><code>{{ .Method }} {{ .Path }}</code></td>
            <td>{{ .Status }}</td>
            <td>{{ .Duration }}</td>
          </tr>
          {{ else }}
          <tr>
            <td colspan="5" class="muted">no requests yet</td>
          </tr>
          {{ end }}
        </tbody>
      </table>
    </section>
  </main>
</body>
</html>`
