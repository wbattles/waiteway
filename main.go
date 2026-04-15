package main

import (
	"crypto/rand"
	"encoding/hex"
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
	"strconv"
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
	Name          string   `json:"name"`
	PathPrefix    string   `json:"path_prefix"`
	Target        string   `json:"target"`
	RequireAPIKey bool     `json:"require_api_key"`
	StripPrefix   bool     `json:"strip_prefix"`
	APIKeys       []string `json:"api_keys,omitempty"`
}

type Gateway struct {
	mu         sync.RWMutex
	configPath string
	config     Config
	routes     []compiledRoute
	apiKeys    map[string]struct{}
	logs       *requestLogStore
	tmpl       *template.Template
	loginTmpl  *template.Template
	sessionsMu sync.Mutex
	sessions   map[string]struct{}
}

type compiledRoute struct {
	Route
	targetURL *url.URL
	proxy     *httputil.ReverseProxy
	apiKeys   map[string]struct{}
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
	Listen          string
	AdminUsername   string
	AdminPassword   string
	LogLimit        int
	Routes          []Route
	OpenRoutes      int
	ProtectedRoutes int
	RouteKeyCount   int
	Logs            []requestLog
	LogStats        logStats
	RouteStats      []routeStat
	Now             time.Time
	Message         string
	Error           string
}

type logStats struct {
	Total        int
	Success      int
	Errors       int
	Unauthorized int
	UniqueRoutes int
	Average      time.Duration
	Slowest      time.Duration
}

type routeStat struct {
	Name  string
	Count int
}

type loginPageData struct {
	Error string
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

	gateway, err := newGateway(configPath, config)
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

func newGateway(configPath string, config Config) (*Gateway, error) {
	tmpl, err := template.New("admin").Funcs(template.FuncMap{
		"formatDurationMS": formatDurationMS,
	}).Parse(adminTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse admin template: %w", err)
	}

	loginTmpl, err := template.New("login").Parse(loginTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse login template: %w", err)
	}

	g := &Gateway{
		configPath: configPath,
		logs:       &requestLogStore{limit: config.LogLimit},
		tmpl:       tmpl,
		loginTmpl:  loginTmpl,
		sessions:   make(map[string]struct{}),
	}

	if err := g.applyConfig(config); err != nil {
		return nil, err
	}

	return g, nil
}

func (g *Gateway) applyConfig(config Config) error {
	routes, apiKeys, err := compileConfig(config)
	if err != nil {
		return err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	g.config = config
	g.routes = routes
	g.apiKeys = apiKeys
	g.logs.setLimit(config.LogLimit)
	return nil
}

func compileConfig(config Config) ([]compiledRoute, map[string]struct{}, error) {
	apiKeys := make(map[string]struct{}, len(config.APIKeys))

	for _, key := range config.APIKeys {
		if key == "" {
			continue
		}
		apiKeys[key] = struct{}{}
	}

	routes := make([]compiledRoute, 0, len(config.Routes))
	for _, route := range config.Routes {
		if route.PathPrefix == "" || route.Target == "" {
			return nil, nil, errors.New("every route needs path_prefix and target")
		}

		targetURL, err := url.Parse(route.Target)
		if err != nil {
			return nil, nil, fmt.Errorf("parse target %q: %w", route.Target, err)
		}

		proxy := newSingleHostProxy(targetURL, route)
		routeAPIKeys := make(map[string]struct{}, len(route.APIKeys))
		for _, key := range route.APIKeys {
			if key == "" {
				continue
			}
			routeAPIKeys[key] = struct{}{}
		}
		routes = append(routes, compiledRoute{
			Route:     route,
			targetURL: targetURL,
			proxy:     proxy,
			apiKeys:   routeAPIKeys,
		})
	}

	sort.Slice(routes, func(i, j int) bool {
		return len(routes[i].PathPrefix) > len(routes[j].PathPrefix)
	})

	return routes, apiKeys, nil
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
	mux.HandleFunc("/admin/login", g.handleAdminLogin)
	mux.HandleFunc("/admin/logout", g.handleAdminLogout)
	mux.HandleFunc("/admin", g.handleAdmin)
	mux.HandleFunc("/admin/", g.handleAdmin)
	mux.HandleFunc("/", g.handleProxy)
	return mux
}

func (g *Gateway) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if !g.authorizeAdmin(r) {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		g.handleAdminPost(w, r)
		return
	}

	message := r.URL.Query().Get("message")
	errText := r.URL.Query().Get("error")
	g.renderAdminPage(w, g.adminPageData(message, errText), http.StatusOK)
}

func (g *Gateway) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		g.renderLogin(w, "")
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		g.renderLogin(w, "login failed")
		return
	}

	config := g.currentConfig()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username != config.Admin.Username || password != config.Admin.Password {
		g.renderLogin(w, "login failed")
		return
	}

	sessionID, err := newSessionID()
	if err != nil {
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	g.sessionsMu.Lock()
	g.sessions[sessionID] = struct{}{}
	g.sessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "waiteway_admin",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (g *Gateway) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if cookie, err := r.Cookie("waiteway_admin"); err == nil {
		g.sessionsMu.Lock()
		delete(g.sessions, cookie.Value)
		g.sessionsMu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "waiteway_admin",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (g *Gateway) handleAdminPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		g.renderAdminError(w, "could not read form")
		return
	}

	switch r.FormValue("action") {
	case "save_settings":
		g.handleAdminSaveSettings(w, r)
	case "change_password":
		g.handleAdminChangePassword(w, r)
	case "save_logging":
		g.handleAdminSaveLogging(w, r)
	case "clear_logs":
		g.handleAdminClearLogs(w, r)
	case "add_route":
		g.handleAdminAddRoute(w, r)
	case "update_route":
		g.handleAdminUpdateRoute(w, r)
	case "delete_route":
		g.handleAdminDeleteRoute(w, r)
	default:
		g.renderAdminError(w, "unknown admin action")
	}
}

func (g *Gateway) handleAdminClearLogs(w http.ResponseWriter, r *http.Request) {
	g.logs.clear()
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (g *Gateway) handleAdminSaveSettings(w http.ResponseWriter, r *http.Request) {
	config, err := settingsConfigFromForm(r, g.currentConfig())
	if err != nil {
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	if err := g.saveConfig(config); err != nil {
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (g *Gateway) handleAdminChangePassword(w http.ResponseWriter, r *http.Request) {
	config := g.currentConfig()
	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")

	if currentPassword != config.Admin.Password {
		g.renderAdminForm(w, config, "", "current password is wrong")
		return
	}
	if strings.TrimSpace(newPassword) == "" {
		g.renderAdminForm(w, config, "", "new password is required")
		return
	}

	config.Admin.Password = newPassword
	if err := g.saveConfig(config); err != nil {
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (g *Gateway) handleAdminSaveLogging(w http.ResponseWriter, r *http.Request) {
	config, err := loggingConfigFromForm(r, g.currentConfig())
	if err != nil {
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	if err := g.saveConfig(config); err != nil {
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (g *Gateway) handleAdminAddRoute(w http.ResponseWriter, r *http.Request) {
	config := g.currentConfig()
	route, err := routeFromForm(r)
	if err != nil {
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	config.Routes = append(config.Routes, route)
	if err := g.saveConfig(config); err != nil {
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (g *Gateway) handleAdminUpdateRoute(w http.ResponseWriter, r *http.Request) {
	config := g.currentConfig()
	index, err := routeIndexFromForm(r, len(config.Routes))
	if err != nil {
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	route, err := routeFromForm(r)
	if err != nil {
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	config.Routes[index] = route
	if err := g.saveConfig(config); err != nil {
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (g *Gateway) handleAdminDeleteRoute(w http.ResponseWriter, r *http.Request) {
	config := g.currentConfig()
	index, err := routeIndexFromForm(r, len(config.Routes))
	if err != nil {
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	config.Routes = append(config.Routes[:index], config.Routes[index+1:]...)
	if len(config.Routes) == 0 {
		g.renderAdminForm(w, config, "", "config needs at least one route")
		return
	}

	if err := g.saveConfig(config); err != nil {
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (g *Gateway) saveConfig(config Config) error {
	config, err := normalizeConfig(config)
	if err != nil {
		return err
	}
	if _, _, err := compileConfig(config); err != nil {
		return err
	}

	pretty, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return errors.New("could not format config")
	}

	if err := os.WriteFile(g.configPath, append(pretty, '\n'), 0644); err != nil {
		return errors.New("could not save config")
	}

	if err := g.applyConfig(config); err != nil {
		return err
	}

	return nil
}

func (g *Gateway) adminPageData(message, errText string) adminPageData {
	config := g.currentConfig()
	routes := make([]Route, len(config.Routes))
	copy(routes, config.Routes)
	logs := g.logs.list()
	stats, routeStats := summarizeLogs(logs)
	openRoutes := 0
	protectedRoutes := 0
	routeKeyCount := 0
	for _, route := range routes {
		if route.RequireAPIKey {
			protectedRoutes++
		} else {
			openRoutes++
		}
		routeKeyCount += len(route.APIKeys)
	}

	data := adminPageData{
		Listen:          config.Listen,
		AdminUsername:   config.Admin.Username,
		AdminPassword:   config.Admin.Password,
		LogLimit:        config.LogLimit,
		Routes:          routes,
		OpenRoutes:      openRoutes,
		ProtectedRoutes: protectedRoutes,
		RouteKeyCount:   routeKeyCount,
		Logs:            logs,
		LogStats:        stats,
		RouteStats:      routeStats,
		Now:             time.Now(),
		Message:         message,
		Error:           errText,
	}

	return data
}

func (g *Gateway) renderAdminError(w http.ResponseWriter, message string) {
	g.renderAdminPage(w, g.adminPageData("", message), http.StatusBadRequest)
}

func (g *Gateway) renderAdminForm(w http.ResponseWriter, config Config, message, errText string) {
	data := g.adminPageData(message, errText)
	data.Listen = config.Listen
	data.AdminUsername = config.Admin.Username
	data.AdminPassword = config.Admin.Password
	data.LogLimit = config.LogLimit
	data.Routes = make([]Route, len(config.Routes))
	copy(data.Routes, config.Routes)
	g.renderAdminPage(w, data, http.StatusBadRequest)
}

func (g *Gateway) renderAdminPage(w http.ResponseWriter, data adminPageData, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := g.tmpl.Execute(w, data); err != nil {
		http.Error(w, "admin render failed", http.StatusInternalServerError)
	}
}

func (g *Gateway) authorizeAdmin(r *http.Request) bool {
	config := g.currentConfig()
	if config.Admin.Username == "" && config.Admin.Password == "" {
		return true
	}

	cookie, err := r.Cookie("waiteway_admin")
	if err != nil || cookie.Value == "" {
		return false
	}

	g.sessionsMu.Lock()
	_, ok := g.sessions[cookie.Value]
	g.sessionsMu.Unlock()
	if ok {
		return true
	}

	return false
}

func (g *Gateway) renderLogin(w http.ResponseWriter, errText string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := g.loginTmpl.Execute(w, loginPageData{Error: errText}); err != nil {
		http.Error(w, "login render failed", http.StatusInternalServerError)
	}
}

func newSessionID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func summarizeLogs(logs []requestLog) (logStats, []routeStat) {
	stats := logStats{Total: len(logs)}
	routeCounts := map[string]int{}
	var totalDuration time.Duration

	for _, entry := range logs {
		name := entry.Route
		if name == "" {
			name = "unknown"
		}
		routeCounts[name]++

		switch {
		case entry.Status == http.StatusUnauthorized:
			stats.Unauthorized++
		case entry.Status >= 400:
			stats.Errors++
		default:
			stats.Success++
		}

		totalDuration += entry.Duration
		if entry.Duration > stats.Slowest {
			stats.Slowest = entry.Duration
		}
	}

	stats.UniqueRoutes = len(routeCounts)
	if stats.Total > 0 {
		stats.Average = totalDuration / time.Duration(stats.Total)
	}

	routeStats := make([]routeStat, 0, len(routeCounts))
	for name, count := range routeCounts {
		routeStats = append(routeStats, routeStat{Name: name, Count: count})
	}
	sort.Slice(routeStats, func(i, j int) bool {
		if routeStats[i].Count == routeStats[j].Count {
			return routeStats[i].Name < routeStats[j].Name
		}
		return routeStats[i].Count > routeStats[j].Count
	})

	return stats, routeStats
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

	if route.RequireAPIKey && !g.authorizeAPIKey(route, r) {
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

func (g *Gateway) authorizeAPIKey(route compiledRoute, r *http.Request) bool {
	g.mu.RLock()
	apiKeys := g.apiKeys
	g.mu.RUnlock()

	key := r.Header.Get("X-API-Key")
	if key == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			key = strings.TrimPrefix(auth, "Bearer ")
		}
	}

	if len(route.apiKeys) > 0 {
		_, ok := route.apiKeys[key]
		return ok
	}

	if len(apiKeys) == 0 {
		return false
	}

	_, ok := apiKeys[key]
	return ok
}

func (g *Gateway) matchRoute(path string) (compiledRoute, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, route := range g.routes {
		if strings.HasPrefix(path, route.PathPrefix) {
			return route, true
		}
	}

	return compiledRoute{}, false
}

func (g *Gateway) currentConfig() Config {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.config
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

func (l *requestLogStore) setLimit(limit int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.limit = limit
	if len(l.entries) > l.limit {
		l.entries = l.entries[:l.limit]
	}
}

func (l *requestLogStore) clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = nil
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

func normalizeConfig(config Config) (Config, error) {
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

func settingsConfigFromForm(r *http.Request, current Config) (Config, error) {
	config := Config{
		Listen: strings.TrimSpace(r.FormValue("listen")),
		Admin: AdminConfig{
			Username: strings.TrimSpace(r.FormValue("admin_username")),
			Password: r.FormValue("admin_password"),
		},
		APIKeys:  current.APIKeys,
		LogLimit: current.LogLimit,
		Routes:   current.Routes,
	}

	return config, nil
}

func loggingConfigFromForm(r *http.Request, current Config) (Config, error) {
	logLimit := current.LogLimit
	logLimitValue := strings.TrimSpace(r.FormValue("log_limit"))
	if logLimitValue != "" {
		parsed, err := strconv.Atoi(logLimitValue)
		if err != nil {
			return Config{}, errors.New("log limit must be a number")
		}
		logLimit = parsed
	}

	current.LogLimit = logLimit
	return current, nil
}

func routeFromForm(r *http.Request) (Route, error) {
	route := Route{
		Name:          strings.TrimSpace(r.FormValue("route_name")),
		PathPrefix:    normalizePathPrefix(strings.TrimSpace(r.FormValue("route_path_prefix"))),
		Target:        strings.TrimSpace(r.FormValue("route_target")),
		RequireAPIKey: r.FormValue("route_require_api_key") == "true",
		StripPrefix:   r.FormValue("route_strip_prefix") == "true",
		APIKeys:       splitLines(r.FormValue("route_api_keys")),
	}

	if route.Name == "" {
		return Route{}, errors.New("route name is required")
	}
	if route.PathPrefix == "" {
		return Route{}, errors.New("route path prefix is required")
	}
	if route.Target == "" {
		return Route{}, errors.New("route target is required")
	}

	return route, nil
}

func routeIndexFromForm(r *http.Request, routeCount int) (int, error) {
	value := strings.TrimSpace(r.FormValue("route_index"))
	index, err := strconv.Atoi(value)
	if err != nil {
		return 0, errors.New("route index is invalid")
	}
	if index < 0 || index >= routeCount {
		return 0, errors.New("route index is out of range")
	}
	return index, nil
}

func splitLines(value string) []string {
	lines := strings.Split(value, "\n")
	items := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		items = append(items, line)
	}
	return items
}

func formatDurationMS(d time.Duration) string {
	ms := float64(d) / float64(time.Millisecond)
	return fmt.Sprintf("%.3fms", ms)
}

func normalizePathPrefix(value string) string {
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, "/") {
		return "/" + value
	}
	return value
}

const adminTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>waiteway - admin</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, -apple-system, sans-serif; background: #fff; color: #000; }
    header { display: flex; align-items: center; justify-content: space-between; padding: 12px 16px; border-bottom: 1px solid #000; }
    .header-actions { display: flex; gap: 8px; }
    .admin-main { width: 100%; max-width: 1000px; margin: 0 auto; }
    .message { padding: 12px 24px 0 24px; font-size: 0.875rem; }
    .admin-tabs { display: flex; border-bottom: 1px solid #000; background: #fff; width: 100%; }
    .tab-btn { padding: 12px 24px; border: none; border-bottom: 2px solid transparent; background: none; cursor: pointer; font-size: 0.875rem; font-family: inherit; min-width: 80px; text-align: center; }
    .tab-btn.active { border-bottom-color: #000; }
    .tab-content { padding: 24px; position: relative; width: 100%; }
    .tab-panel { display: none; width: 100%; }
    .tab-panel.active { display: block; }
    .tab-panel h3 { font-size: 1rem; font-weight: 500; margin-bottom: 12px; }
    .settings-panel { padding: 20px; border: 1px solid #000; display: flex; flex-direction: column; gap: 12px; box-sizing: border-box; }
    .settings-panel form { display: flex; flex-direction: column; gap: 12px; }
    .settings-panel label { font-size: 0.875rem; }
    .settings-panel textarea { min-height: 90px; resize: vertical; }
    .users-layout { display: grid; grid-template-columns: 300px 1fr; gap: 24px; }
    .settings-left { display: flex; flex-direction: column; gap: 24px; width: 300px; }
    .settings-right { display: flex; flex-direction: column; gap: 24px; }
    .create-user-panel { padding: 20px; border: 1px solid #000; height: fit-content; }
    .create-user-panel h3 { margin-bottom: 16px; }
    .create-user-panel form { display: flex; flex-direction: column; gap: 12px; }
    .settings-row { display: flex; align-items: center; gap: 8px; }
    .settings-row label { flex-shrink: 0; width: 70px; }
    .settings-panel select { width: 100%; box-sizing: border-box; }
    .settings-panel button { margin-top: 4px; }
    .logging-layout { display: grid; grid-template-columns: 240px 1fr; gap: 24px; align-items: stretch; min-height: 78vh; }
    .logging-sidebar { display: flex; flex-direction: column; gap: 16px; height: 78vh; }
    .stats-grid { display: grid; grid-template-columns: 1fr; gap: 8px; margin-bottom: 0; flex: 1; }
    .stat-card { border: 1px solid #000; padding: 10px 12px; min-height: 0; }
    .stat-label { font-size: 0.75rem; opacity: 0.7; margin-bottom: 4px; }
    .stat-value { font-size: 1rem; }
    .route-stats { border: 1px solid #000; padding: 16px; }
    .route-stats-list { max-height: 96px; overflow-y: auto; }
    .route-stats ul { list-style: none; margin: 0; }
    .route-stats li { display: flex; align-items: center; gap: 8px; }
    .route-stats li + li { margin-top: 8px; }
    .route-stat-name { flex: 1; min-width: 0; white-space: nowrap; overflow-x: auto; overflow-y: hidden; scrollbar-width: none; -ms-overflow-style: none; }
    .route-stat-name::-webkit-scrollbar { display: none; }
    .route-stat-count { flex-shrink: 0; }
    .log-panel { min-height: 78vh; height: 78vh; }
    .log-table-wrap { overflow-y: auto; overflow-x: hidden; max-height: 70vh; }
    .user-list-panel { border: 1px solid #000; display: flex; flex-direction: column; min-height: 420px; }
    .user-list-panel h3 { padding: 16px 20px 0 20px; margin-bottom: 16px; border-bottom: 1px solid #000; padding-bottom: 12px; flex-shrink: 0; }
    .panel-body { padding: 0 20px 20px 20px; flex: 1; overflow-y: auto; min-height: 0; }
    .log-panel-body { overflow: hidden; }
    table { width: 100%; border-collapse: collapse; table-layout: fixed; }
    th, td { text-align: left; padding: 8px 0; border-bottom: 1px solid #000; vertical-align: top; }
    .routes-table th:nth-child(1), .routes-table td:nth-child(1) { width: 18%; padding-right: 12px; }
    .routes-table th:nth-child(2), .routes-table td:nth-child(2) { width: 22%; padding-right: 12px; }
    .routes-table th:nth-child(3), .routes-table td:nth-child(3) { width: 28%; padding-right: 12px; }
    .routes-table th:nth-child(4), .routes-table td:nth-child(4) { width: 12%; padding-right: 12px; }
    .routes-table th:nth-child(5), .routes-table td:nth-child(5) { width: 20%; }
    .logs-table th:nth-child(1), .logs-table td:nth-child(1) { width: 20%; padding-right: 12px; }
    .logs-table th:nth-child(2), .logs-table td:nth-child(2) { width: 20%; padding-right: 12px; }
    .logs-table th:nth-child(3), .logs-table td:nth-child(3) { width: 34%; padding-right: 12px; overflow: hidden; }
    .logs-table th:nth-child(4), .logs-table td:nth-child(4) { width: 10%; padding-right: 12px; }
    .logs-table th:nth-child(5), .logs-table td:nth-child(5) { width: 16%; }
    .scroll-cell { display: block; max-width: 100%; white-space: nowrap; overflow-x: auto; overflow-y: hidden; scrollbar-width: none; -ms-overflow-style: none; }
    .scroll-cell::-webkit-scrollbar { display: none; }
    .request-scroll { display: block; width: 100%; white-space: nowrap; overflow-x: auto; overflow-y: hidden; scrollbar-width: none; -ms-overflow-style: none; -webkit-overflow-scrolling: touch; }
    .request-scroll::-webkit-scrollbar { display: none; }
    .row-actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .muted { opacity: 0.7; }
    .info-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
    .info-block p + p { margin-top: 6px; }
    .settings-table th:nth-child(1), .settings-table td:nth-child(1) { width: 32%; padding-right: 12px; }
    .settings-table th:nth-child(2), .settings-table td:nth-child(2) { width: 28%; padding-right: 12px; }
    .settings-table th:nth-child(3), .settings-table td:nth-child(3) { width: 20%; padding-right: 12px; }
    .settings-table th:nth-child(4), .settings-table td:nth-child(4) { width: 20%; }
    .modal { position: fixed; inset: 0; background: rgba(0,0,0,0.25); display: flex; align-items: center; justify-content: center; z-index: 10; }
    .modal.hidden { display: none; }
    .modal-box { background: #fff; padding: 24px; width: 420px; max-width: 90vw; border: 1px solid #000; display: flex; flex-direction: column; gap: 12px; }
    .modal-box h2 { font-size: 0.95rem; font-weight: 500; }
    .modal-box form { display: flex; flex-direction: column; gap: 12px; }
    .modal-box textarea { min-height: 90px; resize: vertical; }
    .modal-actions { display: flex; gap: 8px; }
  </style>
</head>
<body>
  <header>
    <div>waiteway</div>
    <div class="header-actions">
      <form method="post" action="/admin/logout"><button type="submit">logout</button></form>
    </div>
  </header>

  {{ if .Message }}<div class="message">{{ .Message }}</div>{{ end }}
  {{ if .Error }}<div class="message">{{ .Error }}</div>{{ end }}

  <main class="admin-main">
    <nav class="admin-tabs">
      <button class="tab-btn active" type="button" onclick="showTab('gateway', this)">gateway</button>
      <button class="tab-btn" type="button" onclick="showTab('logging', this)">logging</button>
      <button class="tab-btn" type="button" onclick="showTab('settings', this)">settings</button>
    </nav>

    <div class="tab-content">
      <section id="gateway-tab" class="tab-panel active">
        <div class="user-list-panel">
          <h3>routes</h3>
          <div class="panel-body">
            <p><button type="button" onclick="openAddRoute()">add route</button></p>
            <table class="routes-table">
              <thead>
                <tr>
                  <th>name</th>
                  <th>path</th>
                  <th>target</th>
                  <th>auth</th>
                  <th>actions</th>
                </tr>
              </thead>
              <tbody>
                {{ range $index, $route := .Routes }}
                <tr>
                  <td><span class="scroll-cell">{{ $route.Name }}</span></td>
                  <td><span class="scroll-cell">{{ $route.PathPrefix }}</span></td>
                  <td><span class="scroll-cell">{{ $route.Target }}</span></td>
                  <td>{{ if $route.RequireAPIKey }}{{ len $route.APIKeys }} keys{{ else }}open{{ end }}</td>
                  <td>
                    <div class="row-actions">
                      <button type="button" data-route-index="{{ $index }}" data-route-name="{{ $route.Name }}" data-route-path-prefix="{{ $route.PathPrefix }}" data-route-target="{{ $route.Target }}" data-route-require-api-key="{{ if $route.RequireAPIKey }}true{{ else }}false{{ end }}" data-route-strip-prefix="{{ if $route.StripPrefix }}true{{ else }}false{{ end }}" data-route-api-keys="{{ range $i, $key := $route.APIKeys }}{{ if $i }}&#10;{{ end }}{{ $key }}{{ end }}" onclick="openEditRouteButton(this)">edit</button>
                      <form method="post" action="/admin">
                        <input type="hidden" name="action" value="delete_route">
                        <input type="hidden" name="route_index" value="{{ $index }}">
                        <button type="submit">delete</button>
                      </form>
                    </div>
                  </td>
                </tr>
                {{ end }}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section id="logging-tab" class="tab-panel">
        <div class="logging-layout">
          <div class="logging-sidebar">
            <div class="route-stats">
              <h3>top routes</h3>
              <div class="route-stats-list">
                <ul>
                  {{ range .RouteStats }}
                  <li><span class="route-stat-name">{{ .Name }}</span><span class="route-stat-count">{{ .Count }}</span></li>
                  {{ else }}
                  <li class="muted">no requests yet</li>
                  {{ end }}
                </ul>
              </div>
            </div>
            <div class="stats-grid">
              <div class="stat-card"><div class="stat-label">recent requests</div><div class="stat-value">{{ .LogStats.Total }}</div></div>
              <div class="stat-card"><div class="stat-label">errors</div><div class="stat-value">{{ .LogStats.Errors }}</div></div>
              <div class="stat-card"><div class="stat-label">unauthorized</div><div class="stat-value">{{ .LogStats.Unauthorized }}</div></div>
              <div class="stat-card"><div class="stat-label">successful</div><div class="stat-value">{{ .LogStats.Success }}</div></div>
              <div class="stat-card"><div class="stat-label">avg duration</div><div class="stat-value">{{ .LogStats.Average }}</div></div>
              <div class="stat-card"><div class="stat-label">slowest</div><div class="stat-value">{{ .LogStats.Slowest }}</div></div>
            </div>
          </div>
          <div>
            <div class="user-list-panel log-panel">
            <h3>recent requests</h3>
            <div class="panel-body log-panel-body">
              <div class="log-table-wrap">
              <table class="logs-table">
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
                    <td>{{ .Time.Format "15:04:05" }}</td>
                    <td><span class="scroll-cell">{{ .Route }}</span></td>
                    <td><span class="request-scroll">{{ .Method }} {{ .Path }}</span></td>
                    <td>{{ .Status }}</td>
                    <td>{{ formatDurationMS .Duration }}</td>
                  </tr>
                  {{ else }}
                  <tr><td colspan="5" class="muted">no requests yet</td></tr>
                {{ end }}
              </tbody>
              </table>
              </div>
            </div>
          </div>
          </div>
        </div>
      </section>

      <section id="settings-tab" class="tab-panel">
        <div class="users-layout">
          <div class="settings-left">
            <div class="create-user-panel">
              <h3>admin account</h3>
              <form method="post" action="/admin">
                <input type="hidden" name="action" value="save_settings">
                <input type="hidden" name="listen" value="{{ .Listen }}">
                <input type="text" name="admin_username" value="{{ .AdminUsername }}" placeholder="admin username">
                <button type="submit">save username</button>
              </form>
              <form method="post" action="/admin">
                <input type="hidden" name="action" value="change_password">
                <input type="password" name="current_password" placeholder="current password" required>
                <input type="password" name="new_password" placeholder="new password" required>
                <button type="submit">save password</button>
              </form>
            </div>

            <div class="create-user-panel">
              <h3>gateway</h3>
              <p class="muted">changing listen takes effect after restart</p>
              <form method="post" action="/admin">
                <input type="hidden" name="action" value="save_settings">
                <input type="text" id="listen" name="listen" value="{{ .Listen }}" placeholder="listen">
                <button type="submit">save gateway</button>
              </form>
            </div>

            <div class="create-user-panel">
              <h3>logging</h3>
              <form method="post" action="/admin">
                <input type="hidden" name="action" value="save_logging">
                <input type="number" name="log_limit" value="{{ .LogLimit }}" placeholder="log limit">
                <button type="submit">save logging</button>
              </form>
              <form method="post" action="/admin">
                <input type="hidden" name="action" value="clear_logs">
                <button type="submit">clear logs</button>
              </form>
            </div>
          </div>

          <div class="settings-right">
            <div class="user-list-panel">
              <h3>overview</h3>
              <div class="panel-body">
                <div class="info-grid">
                  <div class="info-block">
                    <p><strong>listen</strong></p>
                    <p>{{ .Listen }}</p>
                  </div>
                  <div class="info-block">
                    <p><strong>admin username</strong></p>
                    <p>{{ .AdminUsername }}</p>
                  </div>
                  <div class="info-block">
                    <p><strong>routes</strong></p>
                    <p>{{ len .Routes }}</p>
                  </div>
                  <div class="info-block">
                    <p><strong>log limit</strong></p>
                    <p>{{ .LogLimit }}</p>
                  </div>
                  <div class="info-block">
                    <p><strong>protected routes</strong></p>
                    <p>{{ .ProtectedRoutes }}</p>
                  </div>
                  <div class="info-block">
                    <p><strong>open routes</strong></p>
                    <p>{{ .OpenRoutes }}</p>
                  </div>
                  <div class="info-block">
                    <p><strong>route api keys</strong></p>
                    <p>{{ .RouteKeyCount }}</p>
                  </div>
                  <div class="info-block">
                    <p><strong>time</strong></p>
                    <p>{{ .Now.Format "2006-01-02 15:04:05 MST" }}</p>
                  </div>
                </div>
              </div>
            </div>

            <div class="user-list-panel">
              <h3>route access</h3>
              <div class="panel-body">
                <table class="settings-table">
                  <thead>
                    <tr>
                      <th>route</th>
                      <th>path</th>
                      <th>auth</th>
                      <th>keys</th>
                    </tr>
                  </thead>
                  <tbody>
                    {{ range .Routes }}
                    <tr>
                      <td><span class="scroll-cell">{{ .Name }}</span></td>
                      <td><span class="scroll-cell">{{ .PathPrefix }}</span></td>
                      <td>{{ if .RequireAPIKey }}api key{{ else }}open{{ end }}</td>
                      <td>{{ len .APIKeys }}</td>
                    </tr>
                    {{ else }}
                    <tr><td colspan="4" class="muted">no routes yet</td></tr>
                    {{ end }}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  </main>

  <div id="route-modal" class="modal hidden">
    <div class="modal-box">
      <h2 id="route-modal-title">add route</h2>
      <form method="post" action="/admin">
        <input type="hidden" id="route-action" name="action" value="add_route">
        <input type="hidden" id="route-index" name="route_index" value="">
        <label for="route-name">name</label>
        <input id="route-name" type="text" name="route_name" value="">
        <label for="route-path-prefix">path prefix</label>
        <input id="route-path-prefix" type="text" name="route_path_prefix" value="">
        <label for="route-target">target</label>
        <input id="route-target" type="text" name="route_target" value="">
        <div class="settings-row">
          <label for="route-require-api-key">auth</label>
          <select id="route-require-api-key" name="route_require_api_key">
            <option value="false">open</option>
            <option value="true">api key</option>
          </select>
        </div>
        <div class="settings-row">
          <label for="route-strip-prefix">strip</label>
          <select id="route-strip-prefix" name="route_strip_prefix">
            <option value="false">no</option>
            <option value="true">yes</option>
          </select>
        </div>
        <label for="route-api-keys">route api keys</label>
        <textarea id="route-api-keys" name="route_api_keys" placeholder="one key per line"></textarea>
        <div class="modal-actions">
          <button type="submit">save</button>
          <button type="button" onclick="closeRouteModal()">cancel</button>
        </div>
      </form>
    </div>
  </div>

  <script>
    function showTab(name, button) {
      document.querySelectorAll('.tab-btn').forEach((button) => button.classList.remove('active'))
      document.querySelectorAll('.tab-panel').forEach((panel) => panel.classList.remove('active'))
      button.classList.add('active')
      document.getElementById(name + '-tab').classList.add('active')
    }

    function openAddRoute() {
      document.getElementById('route-modal-title').textContent = 'add route'
      document.getElementById('route-action').value = 'add_route'
      document.getElementById('route-index').value = ''
      document.getElementById('route-name').value = ''
      document.getElementById('route-path-prefix').value = ''
      document.getElementById('route-target').value = ''
      document.getElementById('route-require-api-key').value = 'false'
      document.getElementById('route-strip-prefix').value = 'false'
      document.getElementById('route-api-keys').value = ''
      document.getElementById('route-modal').classList.remove('hidden')
    }

    function openEditRouteButton(button) {
      const data = button.dataset
      document.getElementById('route-modal-title').textContent = 'edit route'
      document.getElementById('route-action').value = 'update_route'
      document.getElementById('route-index').value = data.routeIndex
      document.getElementById('route-name').value = data.routeName
      document.getElementById('route-path-prefix').value = data.routePathPrefix
      document.getElementById('route-target').value = data.routeTarget
      document.getElementById('route-require-api-key').value = data.routeRequireApiKey
      document.getElementById('route-strip-prefix').value = data.routeStripPrefix
      document.getElementById('route-api-keys').value = data.routeApiKeys
      document.getElementById('route-modal').classList.remove('hidden')
    }

    function closeRouteModal() {
      document.getElementById('route-modal').classList.add('hidden')
    }
  </script>
</body>
</html>`

const loginTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>waiteway - login</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, -apple-system, sans-serif; background: #fff; color: #000; }
    .login-container { height: 100vh; display: flex; align-items: center; justify-content: center; background: #fff; }
    .login-box { width: 300px; padding: 32px; border: 1px solid #000; display: flex; flex-direction: column; gap: 16px; }
    .login-box h1 { font-size: 1.5rem; font-weight: 500; text-align: center; margin-bottom: 8px; }
    .login-box input { width: 100%; border: 1px solid #000; padding: 8px 10px; font-size: 0.875rem; font-family: inherit; outline: none; }
    .login-box button { width: 100%; }
    .error { color: #000; font-size: 0.8rem; text-align: center; }
    .hidden { display: none; }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-box">
      <h1>waiteway</h1>
      <form method="post" action="/admin/login">
        <input type="text" name="username" placeholder="username" autocomplete="username" required>
        <input type="password" name="password" placeholder="password" autocomplete="current-password" required>
        <button type="submit">login</button>
      </form>
      <div class="{{ if .Error }}error{{ else }}error hidden{{ end }}">{{ .Error }}</div>
    </div>
  </div>
</body>
</html>`
