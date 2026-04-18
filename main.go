package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	Admin        AdminConfig
	LogLimit     int
	LoadBalancer LoadBalancerConfig
	Policies     []Policy
	Routes       []Route
	ActiveTab    string
}

type AdminConfig struct {
	Username string
	Password string
}

type LoadBalancerConfig struct {
	Mode           string
	ClientIPHeader string
	StripPort      bool
}

type Route struct {
	Name          string
	PathPrefix    string
	Target        string
	PolicyName    string
	RequireAPIKey bool
	StripPrefix   bool
	APIKeys       []string
}

type Gateway struct {
	mu          sync.RWMutex
	store       *Store
	config      Config
	policies    map[string]*compiledPolicy
	routes      []compiledRoute
	tmpl        *template.Template
	loginTmpl   *template.Template
	startedAt   time.Time
	listenAddr  string
	adminListen string

	logCh     chan requestLog
	stopCh    chan struct{}
	doneCh    chan struct{}
	closeOnce sync.Once
}

type compiledRoute struct {
	Route
	targetURL *url.URL
	proxy     *httputil.ReverseProxy
	apiKeys   map[string]struct{}
	policy    *compiledPolicy
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

type adminPageData struct {
	AdminUsername         string
	AdminPassword         string
	LogLimit              int
	LoadBalancerMode      string
	LoadBalancerHeader    string
	LoadBalancerHeaders   string
	LoadBalancerStripPort bool
	GatewayListen         string
	AdminListen           string
	GatewayHealthPath     string
	AdminHealthPath       string
	Policies              []Policy
	Routes                []Route
	ActiveTab             string
	OpenRoutes            int
	ProtectedRoutes       int
	Logs                  []requestLog
	LogStats              logStats
	RouteStats            []routeStat
	Uptime                string
	Message               string
	Error                 string
}

type logStats struct {
	Total        int
	Success      int
	Errors       int
	Unauthorized int
	UniqueRoutes int
	ErrorRate    float64
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

const defaultDBPath = "waiteway.db"

func main() {
	dbPath := defaultDBPath
	if len(os.Args) > 1 {
		dbPath = os.Args[1]
	}

	store, err := openStore(dbPath)
	if err != nil {
		log.Fatal(err)
	}

	if !store.HasRoutes() {
		store.AddRoute(Route{
			Name:       "example",
			PathPrefix: "/api/example",
			Target:     "http://localhost:3000",
		})
	}

	seedFromEnv(store)

	config, err := store.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	listen := envOrDefault("WAITEWAY_LISTEN", ":8080")
	adminListen := envOrDefault("WAITEWAY_ADMIN_LISTEN", ":9090")

	gateway, err := newGateway(store, config)
	if err != nil {
		log.Fatal(err)
	}

	gwServer := &http.Server{Addr: listen, Handler: gateway.gatewayHandler()}
	adminServer := &http.Server{Addr: adminListen, Handler: gateway.adminHandler()}

	go func() {
		log.Printf("waiteway admin listening on %s", adminListen)
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	go func() {
		log.Printf("waiteway gateway listening on %s", listen)
		if err := gwServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// Wait for SIGINT or SIGTERM, then shut down cleanly: stop accepting new
	// connections, let in-flight requests finish, flush pending log entries,
	// close the store. Without this, container restarts lose buffered logs.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("waiteway shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = gwServer.Shutdown(ctx)
	_ = adminServer.Shutdown(ctx)
	gateway.Close()
	store.Close()
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func seedFromEnv(store *Store) {
	if store.HasSettings() {
		return
	}

	username := os.Getenv("WAITEWAY_ADMIN_USERNAME")
	password := os.Getenv("WAITEWAY_ADMIN_PASSWORD")

	if username != "" {
		store.SetSetting("admin_username", username)
	}
	if password != "" {
		store.SetSetting("admin_password", password)
	}
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
	routes, policies, err := compileConfig(config)
	if err != nil {
		return err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	g.config = config
	g.policies = policies
	g.routes = routes
	return nil
}

func compileConfig(config Config) ([]compiledRoute, map[string]*compiledPolicy, error) {
	policies := make(map[string]*compiledPolicy, len(config.Policies))
	seenPrefixes := make(map[string]string, len(config.Routes))

	for _, policy := range config.Policies {
		compiled, err := compilePolicy(policy)
		if err != nil {
			return nil, nil, fmt.Errorf("compile policy %q: %w", policy.Name, err)
		}
		policies[policy.Name] = compiled
	}

	routes := make([]compiledRoute, 0, len(config.Routes))
	for _, route := range config.Routes {
		route.PathPrefix = normalizePathPrefix(route.PathPrefix)
		if route.PathPrefix == "" || route.Target == "" {
			return nil, nil, errors.New("every route needs path_prefix and target")
		}
		if existingName, ok := seenPrefixes[route.PathPrefix]; ok {
			return nil, nil, fmt.Errorf("route path prefix %q is already in use (conflicts with route %q)", route.PathPrefix, existingName)
		}
		seenPrefixes[route.PathPrefix] = route.Name

		targetURL, err := url.Parse(route.Target)
		if err != nil {
			return nil, nil, fmt.Errorf("parse target %q: %w", route.Target, err)
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
				return nil, nil, fmt.Errorf("route %q uses unknown policy %q", route.Name, route.PolicyName)
			}
		}

		proxy := newSingleHostProxy(targetURL, route, policyRef)
		routes = append(routes, compiledRoute{
			Route:     route,
			targetURL: targetURL,
			proxy:     proxy,
			apiKeys:   routeAPIKeys,
			policy:    policyRef,
		})
	}

	sort.Slice(routes, func(i, j int) bool {
		return len(routes[i].PathPrefix) > len(routes[j].PathPrefix)
	})

	return routes, policies, nil
}

func newSingleHostProxy(target *url.URL, route Route, policy *compiledPolicy) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		incomingPath := req.URL.Path
		originalDirector(req)

		remainder := strings.TrimPrefix(incomingPath, route.PathPrefix)
		if remainder != "" && !strings.HasPrefix(remainder, "/") {
			remainder = "/" + remainder
		}

		if policy != nil && policy.RewritePathPrefix != "" {
			// rewrite takes priority over strip prefix
			req.URL.Path = joinURLPath(target.Path, policy.RewritePathPrefix+remainder)
		} else if route.StripPrefix {
			if remainder == "" || remainder == "/" {
				req.URL.Path = target.Path
			} else {
				req.URL.Path = joinURLPath(target.Path, remainder)
			}
		}

		req.Host = target.Host
		req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
		req.Header.Set("X-Waiteway-Route", route.Name)
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		return applyResponsePolicy(policy, resp)
	}
	if policy != nil && policy.RetryCount > 0 {
		proxy.Transport = &retryTransport{base: http.DefaultTransport, retries: policy.RetryCount}
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

func (g *Gateway) gatewayHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/", g.handleProxy)
	return mux
}

func (g *Gateway) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/login", g.handleAdminLogin)
	mux.HandleFunc("/logout", g.handleAdminLogout)
	mux.HandleFunc("/", g.handleAdmin)
	return mux
}

func (g *Gateway) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if !g.authorizeAdmin(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		g.handleAdminPost(w, r)
		return
	}

	message := r.URL.Query().Get("message")
	errText := r.URL.Query().Get("error")
	activeTab := normalizeAdminTab(r.URL.Query().Get("tab"))
	g.renderAdminPage(w, g.adminPageData(message, errText, activeTab), http.StatusOK)
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

	g.store.AddSession(sessionID)

	http.SetCookie(w, &http.Cookie{
		Name:     "waiteway_admin",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (g *Gateway) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if cookie, err := r.Cookie("waiteway_admin"); err == nil {
		g.store.DeleteSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "waiteway_admin",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (g *Gateway) handleAdminPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		g.renderAdminError(w, "could not read form")
		return
	}

	switch r.FormValue("action") {
	case "add_policy":
		g.handleAdminAddPolicy(w, r)
	case "update_policy":
		g.handleAdminUpdatePolicy(w, r)
	case "delete_policy":
		g.handleAdminDeletePolicy(w, r)
	case "save_settings":
		g.handleAdminSaveSettings(w, r)
	case "change_password":
		g.handleAdminChangePassword(w, r)
	case "save_logging":
		g.handleAdminSaveLogging(w, r)
	case "save_load_balancer":
		g.handleAdminSaveLoadBalancer(w, r)
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
	g.store.ClearLogs()
	http.Redirect(w, r, "/?tab=settings", http.StatusSeeOther)
}

func (g *Gateway) handleAdminAddPolicy(w http.ResponseWriter, r *http.Request) {
	config := g.currentConfig()
	policy, err := policyFromForm(r)
	if err != nil {
		config.Policies = policiesFromFormOrCurrent(r, config.Policies)
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	if err := g.store.AddPolicy(policy); err != nil {
		config.Policies = policiesFromFormOrCurrent(r, config.Policies)
		config.ActiveTab = "policy"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	g.finishAdminAction(w, r, "/?tab=policy", "policy")
}

func (g *Gateway) handleAdminUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	config := g.currentConfig()
	index, err := policyIndexFromForm(r, len(config.Policies))
	if err != nil {
		config.ActiveTab = "policy"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	policy, err := policyFromForm(r)
	if err != nil {
		config.Policies = policiesFromFormOrCurrent(r, config.Policies)
		config.ActiveTab = "policy"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	if err := g.store.UpdatePolicy(index, policy); err != nil {
		config.Policies = policiesFromFormOrCurrent(r, config.Policies)
		config.ActiveTab = "policy"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	g.finishAdminAction(w, r, "/?tab=policy", "policy")
}

func (g *Gateway) handleAdminDeletePolicy(w http.ResponseWriter, r *http.Request) {
	config := g.currentConfig()
	index, err := policyIndexFromForm(r, len(config.Policies))
	if err != nil {
		config.ActiveTab = "policy"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	if err := g.store.DeletePolicy(index); err != nil {
		config.ActiveTab = "policy"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	g.finishAdminAction(w, r, "/?tab=policy", "policy")
}

func (g *Gateway) handleAdminSaveSettings(w http.ResponseWriter, r *http.Request) {
	config, err := settingsConfigFromForm(r, g.currentConfig())
	if err != nil {
		config.ActiveTab = "settings"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	if err := g.saveConfig(config); err != nil {
		config.ActiveTab = "settings"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	http.Redirect(w, r, "/?tab=settings", http.StatusSeeOther)
}

func (g *Gateway) handleAdminChangePassword(w http.ResponseWriter, r *http.Request) {
	config := g.currentConfig()
	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")

	if currentPassword != config.Admin.Password {
		config.ActiveTab = "settings"
		g.renderAdminForm(w, config, "", "current password is wrong")
		return
	}
	if strings.TrimSpace(newPassword) == "" {
		config.ActiveTab = "settings"
		g.renderAdminForm(w, config, "", "new password is required")
		return
	}

	config.Admin.Password = newPassword
	if err := g.saveConfig(config); err != nil {
		config.ActiveTab = "settings"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	// New password invalidates every existing session so old cookies
	// cannot be reused. The admin will be sent back to the login page.
	if err := g.store.DeleteAllSessions(); err != nil {
		log.Printf("clear sessions after password change failed: %v", err)
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (g *Gateway) handleAdminSaveLogging(w http.ResponseWriter, r *http.Request) {
	config, err := loggingConfigFromForm(r, g.currentConfig())
	if err != nil {
		config.ActiveTab = "settings"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	if err := g.saveConfig(config); err != nil {
		config.ActiveTab = "settings"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	http.Redirect(w, r, "/?tab=settings", http.StatusSeeOther)
}

func (g *Gateway) handleAdminSaveLoadBalancer(w http.ResponseWriter, r *http.Request) {
	config, err := loadBalancerConfigFromForm(r, g.currentConfig())
	if err != nil {
		config.ActiveTab = "settings"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	if err := g.saveConfig(config); err != nil {
		config.ActiveTab = "settings"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	tab := normalizeAdminTab(r.URL.Query().Get("tab"))
	http.Redirect(w, r, "/?tab="+tab, http.StatusSeeOther)
}

func (g *Gateway) handleAdminDeleteRoute(w http.ResponseWriter, r *http.Request) {
	config := g.currentConfig()
	index, err := routeIndexFromForm(r, len(config.Routes))
	if err != nil {
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	if err := g.store.DeleteRoute(index); err != nil {
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	g.finishAdminAction(w, r, "/", "gateway")
}

func (g *Gateway) saveConfig(config Config) error {
	config, err := normalizeConfig(config)
	if err != nil {
		return err
	}
	if _, _, err := compileConfig(config); err != nil {
		return err
	}

	if err := g.store.SaveSettings(config); err != nil {
		return errors.New("could not save config")
	}

	if err := g.applyConfig(config); err != nil {
		return err
	}

	return nil
}

func (g *Gateway) reloadConfig() error {
	config, err := g.store.LoadConfig()
	if err != nil {
		return err
	}
	return g.applyConfig(config)
}

// finishAdminAction reloads the live config after a successful admin write
// and either redirects on success or renders the form with a visible error.
// This prevents silent divergence between the database and the running gateway.
func (g *Gateway) finishAdminAction(w http.ResponseWriter, r *http.Request, redirectURL, activeTab string) {
	if err := g.reloadConfig(); err != nil {
		log.Printf("reload config after admin change failed: %v", err)
		config := g.currentConfig()
		config.ActiveTab = activeTab
		g.renderAdminForm(w, config, "", "change saved but reload failed: "+err.Error())
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (g *Gateway) handleAdminAddRoute(w http.ResponseWriter, r *http.Request) {
	route, err := routeFromForm(r)
	if err != nil {
		silentAdminRedirect(w, r)
		return
	}

	if err := g.store.AddRoute(route); err != nil {
		silentAdminRedirect(w, r)
		return
	}

	g.finishAdminAction(w, r, "/", "gateway")
}

func (g *Gateway) handleAdminUpdateRoute(w http.ResponseWriter, r *http.Request) {
	config := g.currentConfig()
	index, err := routeIndexFromForm(r, len(config.Routes))
	if err != nil {
		silentAdminRedirect(w, r)
		return
	}

	route, err := routeFromForm(r)
	if err != nil {
		silentAdminRedirect(w, r)
		return
	}

	if err := g.store.UpdateRoute(index, route); err != nil {
		silentAdminRedirect(w, r)
		return
	}

	g.finishAdminAction(w, r, "/", "gateway")
}

// silentAdminRedirect sends the admin back to a clean GET URL. Client-side
// validation catches the common mistakes; the rare server-side failure (two
// tabs racing, JS disabled) just returns to the admin page without polluting
// the URL with state.
func silentAdminRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (g *Gateway) adminPageData(message, errText, activeTab string) adminPageData {
	config := g.currentConfig()
	routes := make([]Route, len(config.Routes))
	copy(routes, config.Routes)
	policies := make([]Policy, len(config.Policies))
	copy(policies, config.Policies)
	logs, _ := g.store.ListLogs(config.LogLimit)
	stats, routeStats := summarizeLogs(logs)
	openRoutes := 0
	protectedRoutes := 0
	for _, route := range routes {
		if route.PolicyName != "" || route.RequireAPIKey {
			protectedRoutes++
		} else {
			openRoutes++
		}
	}

	data := adminPageData{
		AdminUsername:         config.Admin.Username,
		AdminPassword:         config.Admin.Password,
		LogLimit:              config.LogLimit,
		LoadBalancerMode:      config.LoadBalancer.Mode,
		LoadBalancerHeader:    config.LoadBalancer.ClientIPHeader,
		LoadBalancerHeaders:   strings.Join(clientIPHeaderChain(config.LoadBalancer), " → "),
		LoadBalancerStripPort: config.LoadBalancer.StripPort,
		GatewayListen:         g.listenAddr,
		AdminListen:           g.adminListen,
		GatewayHealthPath:     "/health",
		AdminHealthPath:       "/health",
		Policies:              policies,
		Routes:                routes,
		ActiveTab:             normalizeAdminTab(activeTab),
		OpenRoutes:            openRoutes,
		ProtectedRoutes:       protectedRoutes,
		Logs:                  logs,
		LogStats:              stats,
		RouteStats:            routeStats,
		Uptime:                formatUptime(time.Since(g.startedAt)),
		Message:               message,
		Error:                 errText,
	}

	return data
}

func (g *Gateway) renderAdminError(w http.ResponseWriter, message string) {
	g.renderAdminPage(w, g.adminPageData("", message, "gateway"), http.StatusBadRequest)
}

func (g *Gateway) renderAdminForm(w http.ResponseWriter, config Config, message, errText string) {
	data := g.adminPageData(message, errText, config.ActiveTab)
	data.AdminUsername = config.Admin.Username
	data.AdminPassword = config.Admin.Password
	data.LogLimit = config.LogLimit
	data.LoadBalancerMode = config.LoadBalancer.Mode
	data.LoadBalancerHeader = config.LoadBalancer.ClientIPHeader
	data.LoadBalancerHeaders = strings.Join(clientIPHeaderChain(config.LoadBalancer), " → ")
	data.LoadBalancerStripPort = config.LoadBalancer.StripPort
	data.Policies = make([]Policy, len(config.Policies))
	copy(data.Policies, config.Policies)
	data.Routes = make([]Route, len(config.Routes))
	copy(data.Routes, config.Routes)
	data.ActiveTab = normalizeAdminTab(config.ActiveTab)
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

	return g.store.HasSession(cookie.Value)
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
		name, _ := routeStatName(entry)
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
		stats.ErrorRate = float64(stats.Errors+stats.Unauthorized) / float64(stats.Total) * 100
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
		g.recordRequest(r, "", http.StatusNotFound, 0)
		http.NotFound(w, r)
		return
	}

	if route.RequireAPIKey && !g.authorizeAPIKey(route, r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		g.recordRequest(r, route.Name, http.StatusUnauthorized, 0)
		return
	}

	if applyCORSPreflight(route.policy, w, r) {
		g.recordRequest(r, route.Name, http.StatusNoContent, 0)
		return
	}

	if ok, status, message := g.authorizePolicy(route, r); !ok {
		http.Error(w, message, status)
		g.recordRequest(r, route.Name, status, 0)
		return
	}

	r, cancelTimeout := requestWithPolicyContext(r, route.policy)
	defer cancelTimeout()

	if cached, ok := g.cachedPolicyResponse(route, r); ok {
		w.Header().Set("X-Waiteway-Cache", "HIT")
		writeCachedResponse(w, cached)
		g.recordRequest(r, route.Name, cached.status, 0)
		return
	}

	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	writer := http.ResponseWriter(recorder)
	cacheRecorder := &cacheRecorder{header: make(http.Header), status: http.StatusOK}
	if shouldCacheRouteResponse(route, r) {
		writer = cacheRecorder
	}
	start := time.Now()
	route.proxy.ServeHTTP(writer, r)
	if writer == cacheRecorder {
		w.Header().Set("X-Waiteway-Cache", "MISS")
		copyResponse(w, cacheRecorder)
		recorder.status = cacheRecorder.status
		g.storeCachedPolicyResponse(route, r, cacheRecorder)
	}
	if route.policy != nil && route.policy.circuitBreaker != nil {
		if recorder.status >= http.StatusInternalServerError {
			route.policy.circuitBreaker.RecordFailure(time.Now())
		} else {
			route.policy.circuitBreaker.RecordSuccess()
		}
	}
	g.recordRequest(r, route.Name, recorder.status, time.Since(start))
}

func (g *Gateway) recordRequest(r *http.Request, routeName string, status int, duration time.Duration) {
	entry := requestLog{
		Time:       time.Now(),
		Method:     r.Method,
		Path:       r.URL.Path,
		Status:     status,
		Route:      routeName,
		RemoteAddr: g.clientIP(r),
		Duration:   duration,
	}

	// Non-blocking send keeps the request hot path free of SQLite writes.
	// If the drainer falls behind, drop the entry rather than slow requests.
	select {
	case g.logCh <- entry:
	default:
	}

	log.Printf("request method=%s path=%s route=%s status=%d ip=%s duration=%s", entry.Method, entry.Path, entry.Route, entry.Status, entry.RemoteAddr, entry.Duration)
}

// drainLogs is a single background consumer for request logs. It writes each
// entry to the store and periodically trims the log table so it cannot grow
// unbounded. Exits when stopCh is closed, flushing any pending entries first.
func (g *Gateway) drainLogs() {
	defer close(g.doneCh)
	const trimEvery = 100
	count := 0

	write := func(entry requestLog) {
		if err := g.store.AddLog(entry); err != nil {
			log.Printf("waiteway failed to store request log: %v", err)
			return
		}
		count++
		if count >= trimEvery {
			count = 0
			limit := g.currentConfig().LogLimit
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
	config := g.currentConfig().LoadBalancer
	for _, candidate := range requestIPCandidates(r, config) {
		if ip := normalizeClientIP(candidate, config.StripPort); ip != "" {
			return ip
		}
	}

	if ip := normalizeClientIP(r.RemoteAddr, config.StripPort); ip != "" {
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

func requestIPCandidates(r *http.Request, config LoadBalancerConfig) []string {
	var ips []string

	for _, name := range clientIPHeaderChain(config) {
		switch name {
		case "RemoteAddr":
			continue
		case "X-Forwarded-For":
			for _, part := range strings.Split(r.Header.Get(name), ",") {
				if ip := cleanForwardedIP(part); ip != "" {
					ips = append(ips, ip)
				}
			}
		case "Forwarded":
			for _, entry := range strings.Split(r.Header.Get(name), ",") {
				for _, part := range strings.Split(entry, ";") {
					key, value, ok := strings.Cut(part, "=")
					if !ok || !strings.EqualFold(strings.TrimSpace(key), "for") {
						continue
					}
					if ip := cleanForwardedIP(value); ip != "" {
						ips = append(ips, ip)
					}
				}
			}
		default:
			if ip := cleanForwardedIP(r.Header.Get(name)); ip != "" {
				ips = append(ips, ip)
			}
		}
	}

	return ips
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

func (g *Gateway) authorizeAPIKey(route compiledRoute, r *http.Request) bool {
	key := r.Header.Get("X-API-Key")
	if key == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			key = strings.TrimPrefix(auth, "Bearer ")
		}
	}

	if len(route.apiKeys) == 0 {
		return false
	}
	_, ok := route.apiKeys[key]
	return ok
}

func (g *Gateway) matchRoute(path string) (compiledRoute, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, route := range g.routes {
		if routeMatchesPath(route.PathPrefix, path) {
			return route, true
		}
	}

	return compiledRoute{}, false
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

func routeStatName(entry requestLog) (string, bool) {
	name := strings.TrimSpace(entry.Path)
	name = strings.TrimPrefix(name, "/")
	if name == "" {
		name = "root"
	}

	return name, strings.TrimSpace(entry.Route) != ""
}

func (g *Gateway) currentConfig() Config {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.config
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
	if config.LogLimit <= 0 {
		config.LogLimit = 100
	}
	config.LoadBalancer = normalizeLoadBalancerConfig(config.LoadBalancer)
	if len(config.Routes) == 0 {
		return Config{}, errors.New("config needs at least one route")
	}
	seenPolicies := map[string]struct{}{}
	for i, policy := range config.Policies {
		policy.Name = strings.TrimSpace(policy.Name)
		if policy.Name == "" {
			return Config{}, errors.New("policy name is required")
		}
		key := strings.ToLower(policy.Name)
		if _, ok := seenPolicies[key]; ok {
			return Config{}, fmt.Errorf("policy %q already exists", policy.Name)
		}
		seenPolicies[key] = struct{}{}
		config.Policies[i] = policy
	}
	return config, nil
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

func settingsConfigFromForm(r *http.Request, current Config) (Config, error) {
	username := strings.TrimSpace(r.FormValue("admin_username"))
	if username == "" {
		username = current.Admin.Username
	}

	config := Config{
		Admin: AdminConfig{
			Username: username,
			Password: current.Admin.Password,
		},
		LogLimit:     current.LogLimit,
		LoadBalancer: current.LoadBalancer,
		Policies:     current.Policies,
		Routes:       current.Routes,
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

func loadBalancerConfigFromForm(r *http.Request, current Config) (Config, error) {
	current.LoadBalancer = normalizeLoadBalancerConfig(LoadBalancerConfig{
		Mode:           r.FormValue("load_balancer_mode"),
		ClientIPHeader: r.FormValue("load_balancer_client_ip_header"),
		StripPort:      r.FormValue("load_balancer_strip_port") != "false",
	})

	if current.LoadBalancer.Mode == "custom" && current.LoadBalancer.ClientIPHeader == "" {
		return current, errors.New("client ip header is required for custom mode")
	}

	return current, nil
}

func routeFromForm(r *http.Request) (Route, error) {
	route := Route{
		Name:          strings.TrimSpace(r.FormValue("route_name")),
		PathPrefix:    normalizePathPrefix(strings.TrimSpace(r.FormValue("route_path_prefix"))),
		Target:        strings.TrimSpace(r.FormValue("route_target")),
		PolicyName:    strings.TrimSpace(r.FormValue("route_policy_name")),
		RequireAPIKey: false,
		StripPrefix:   r.FormValue("route_strip_prefix") == "true",
		APIKeys:       nil,
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
	if err := validateRouteTarget(route.Target); err != nil {
		return Route{}, err
	}

	return route, nil
}

func validateRouteTarget(target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("route target %q is not a valid URL: %w", target, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("route target %q must include scheme and host (e.g. https://example.com)", target)
	}
	return nil
}

func policyFromForm(r *http.Request) (Policy, error) {
	requestTimeoutSeconds, err := intFromForm(r, "policy_request_timeout_seconds")
	if err != nil {
		return Policy{}, err
	}
	retryCount, err := intFromForm(r, "policy_retry_count")
	if err != nil {
		return Policy{}, err
	}
	rateLimitRequests, err := intFromForm(r, "policy_rate_limit_requests")
	if err != nil {
		return Policy{}, err
	}
	rateLimitWindowSeconds, err := intFromForm(r, "policy_rate_limit_window_seconds")
	if err != nil {
		return Policy{}, err
	}
	maxPayloadBytes, err := int64FromForm(r, "policy_max_payload_bytes")
	if err != nil {
		return Policy{}, err
	}
	cacheTTLSeconds, err := intFromForm(r, "policy_cache_ttl_seconds")
	if err != nil {
		return Policy{}, err
	}
	maxResponseBytes, err := int64FromForm(r, "policy_max_response_bytes")
	if err != nil {
		return Policy{}, err
	}
	circuitBreakerFailures, err := intFromForm(r, "policy_circuit_breaker_failures")
	if err != nil {
		return Policy{}, err
	}
	circuitBreakerResetSeconds, err := intFromForm(r, "policy_circuit_breaker_reset_seconds")
	if err != nil {
		return Policy{}, err
	}

	policy := Policy{
		Name:                       strings.TrimSpace(r.FormValue("policy_name")),
		RequestTimeoutSeconds:      requestTimeoutSeconds,
		RetryCount:                 retryCount,
		RequireAPIKey:              r.FormValue("policy_require_api_key") == "true",
		APIKeys:                    splitLines(r.FormValue("policy_api_keys")),
		BasicAuthUsername:          strings.TrimSpace(r.FormValue("policy_basic_auth_username")),
		BasicAuthPassword:          r.FormValue("policy_basic_auth_password"),
		RateLimitRequests:          rateLimitRequests,
		RateLimitWindowSeconds:     rateLimitWindowSeconds,
		AllowedMethods:             splitLines(strings.ToUpper(r.FormValue("policy_allowed_methods"))),
		RewritePathPrefix:          normalizePathPrefix(strings.TrimSpace(r.FormValue("policy_rewrite_path_prefix"))),
		AddRequestHeaders:          splitLines(r.FormValue("policy_add_request_headers")),
		RemoveRequestHeaders:       splitLines(r.FormValue("policy_remove_request_headers")),
		MaxPayloadBytes:            maxPayloadBytes,
		RequestTransformFind:       r.FormValue("policy_request_transform_find"),
		RequestTransformReplace:    r.FormValue("policy_request_transform_replace"),
		CacheTTLSeconds:            cacheTTLSeconds,
		AddResponseHeaders:         splitLines(r.FormValue("policy_add_response_headers")),
		RemoveResponseHeaders:      splitLines(r.FormValue("policy_remove_response_headers")),
		ResponseTransformFind:      r.FormValue("policy_response_transform_find"),
		ResponseTransformReplace:   r.FormValue("policy_response_transform_replace"),
		MaxResponseBytes:           maxResponseBytes,
		CORSAllowOrigins:           splitLines(r.FormValue("policy_cors_allow_origins")),
		CORSAllowMethods:           splitLines(strings.ToUpper(r.FormValue("policy_cors_allow_methods"))),
		CORSAllowHeaders:           splitLines(r.FormValue("policy_cors_allow_headers")),
		IPAllowList:                splitLines(r.FormValue("policy_ip_allow_list")),
		IPBlockList:                splitLines(r.FormValue("policy_ip_block_list")),
		CircuitBreakerFailures:     circuitBreakerFailures,
		CircuitBreakerResetSeconds: circuitBreakerResetSeconds,
	}

	if policy.Name == "" {
		return Policy{}, errors.New("policy name is required")
	}
	if policy.RateLimitRequests > 0 && policy.RateLimitWindowSeconds <= 0 {
		return Policy{}, errors.New("rate limit window seconds is required")
	}
	if policy.RateLimitWindowSeconds > 0 && policy.RateLimitRequests <= 0 {
		return Policy{}, errors.New("rate limit requests is required")
	}
	if policy.CircuitBreakerFailures > 0 && policy.CircuitBreakerResetSeconds <= 0 {
		return Policy{}, errors.New("circuit breaker reset seconds is required")
	}
	if policy.CircuitBreakerResetSeconds > 0 && policy.CircuitBreakerFailures <= 0 {
		return Policy{}, errors.New("circuit breaker failures is required")
	}
	return policy, nil
}

func policiesFromFormOrCurrent(r *http.Request, current []Policy) []Policy {
	policy, err := policyFromForm(r)
	if err != nil {
		return current
	}
	value := strings.TrimSpace(r.FormValue("policy_index"))
	if value == "" {
		return append(append([]Policy(nil), current...), policy)
	}
	index, err := strconv.Atoi(value)
	if err != nil || index < 0 || index >= len(current) {
		return current
	}
	out := append([]Policy(nil), current...)
	out[index] = policy
	return out
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

func policyIndexFromForm(r *http.Request, policyCount int) (int, error) {
	value := strings.TrimSpace(r.FormValue("policy_index"))
	index, err := strconv.Atoi(value)
	if err != nil {
		return 0, errors.New("policy index is invalid")
	}
	if index < 0 || index >= policyCount {
		return 0, errors.New("policy index is out of range")
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

func intFromForm(r *http.Request, key string) (int, error) {
	value := strings.TrimSpace(r.FormValue(key))
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a number", strings.ReplaceAll(key, "_", " "))
	}
	if parsed < 0 {
		return 0, fmt.Errorf("%s must be zero or more", strings.ReplaceAll(key, "_", " "))
	}
	return parsed, nil
}

func int64FromForm(r *http.Request, key string) (int64, error) {
	value := strings.TrimSpace(r.FormValue(key))
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a number", strings.ReplaceAll(key, "_", " "))
	}
	if parsed < 0 {
		return 0, fmt.Errorf("%s must be zero or more", strings.ReplaceAll(key, "_", " "))
	}
	return parsed, nil
}

func formatDurationMS(d time.Duration) string {
	ms := float64(d) / float64(time.Millisecond)
	return fmt.Sprintf("%.3fms", ms)
}

func formatClientIP(value string, stripPort bool) string {
	if ip := normalizeClientIP(value, stripPort); ip != "" {
		return ip
	}
	return strings.TrimSpace(value)
}

func formatPercent(value float64) string {
	return fmt.Sprintf("%.0f%%", value)
}

func formatUptime(d time.Duration) string {
	d = d.Round(time.Second)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
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

func normalizeAdminTab(value string) string {
	switch value {
	case "policy", "logging", "settings":
		return value
	default:
		return "gateway"
	}
}

const adminTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>waiteway</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, -apple-system, sans-serif; background: #fff; color: #000; }
    header { display: flex; align-items: center; justify-content: space-between; padding: 12px 16px; border-bottom: 1px solid #000; }
    .header-actions { display: flex; gap: 8px; }
    .admin-main { width: 100%; max-width: 1000px; margin: 0 auto; }
    .message { padding: 12px 24px 0 24px; font-size: 0.875rem; }
    .modal-error { border-left: 2px solid #000; padding: 6px 10px; font-size: 0.8rem; }
    .modal-error.hidden { display: none; }
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
    .config-table td:nth-child(1) { width: 30%; font-size: 0.875rem; }
    .config-table td:nth-child(2) { width: 55%; font-size: 0.875rem; }
    .config-table td:nth-child(3) { width: 15%; text-align: right; }
    .create-user-panel { padding: 20px; border: 1px solid #000; height: fit-content; }
    .create-user-panel h3 { margin-bottom: 16px; }
    .create-user-panel form { display: flex; flex-direction: column; gap: 12px; }
    .settings-row { display: flex; align-items: center; gap: 8px; }
    .settings-row label { flex-shrink: 0; width: 70px; }
    .settings-panel select { width: 100%; box-sizing: border-box; }
    .settings-panel button { margin-top: 4px; }
    .logging-layout { display: flex; flex-direction: column; gap: 24px; min-height: 500px; }
    .stats-grid { display: grid; grid-template-columns: 1.1fr repeat(4, minmax(0, 1fr)); gap: 8px; align-items: stretch; }
    .stat-card { border: 1px solid #000; padding: 10px 12px; min-height: 0; }
    .stat-label { font-size: 0.75rem; opacity: 0.7; margin-bottom: 4px; }
    .stat-value { font-size: 1rem; }
    .route-stats { border: 1px solid #000; padding: 10px 12px; min-height: 0; grid-row: span 2; }
    .route-stats-list { max-height: 96px; overflow-y: auto; }
    .route-stats ul { list-style: none; margin: 0; }
    .route-stats li { display: flex; align-items: center; gap: 8px; }
    .route-stats li + li { margin-top: 8px; }
    .route-stat-name { flex: 1; min-width: 0; white-space: nowrap; overflow-x: auto; overflow-y: hidden; scrollbar-width: none; -ms-overflow-style: none; }
    .route-stat-name::-webkit-scrollbar { display: none; }
    .route-stat-count { flex-shrink: 0; }
    .log-panel { min-height: 0; height: 520px; }
    .log-table-wrap { overflow-y: auto; overflow-x: hidden; height: 100%; max-height: none; }
    .user-list-panel { border: 1px solid #000; display: flex; flex-direction: column; min-height: 500px; }
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
    .logs-table th:nth-child(1), .logs-table td:nth-child(1) { width: 12%; padding-right: 12px; }
    .logs-table th:nth-child(2), .logs-table td:nth-child(2) { width: 18%; padding-right: 12px; }
    .logs-table th:nth-child(3), .logs-table td:nth-child(3) { width: 14%; padding-right: 12px; }
    .logs-table th:nth-child(4), .logs-table td:nth-child(4) { width: 34%; padding-right: 12px; overflow: hidden; }
    .logs-table th:nth-child(5), .logs-table td:nth-child(5) { width: 10%; padding-right: 12px; }
    .logs-table th:nth-child(6), .logs-table td:nth-child(6) { width: 12%; }
    .logs-table th:nth-child(5), .logs-table td:nth-child(5), .logs-table th:nth-child(6), .logs-table td:nth-child(6) { text-align: right; }
    .scroll-cell { display: block; max-width: 100%; white-space: nowrap; overflow-x: auto; overflow-y: hidden; scrollbar-width: none; -ms-overflow-style: none; }
    .scroll-cell::-webkit-scrollbar { display: none; }
    .request-scroll { display: block; width: 100%; white-space: nowrap; overflow-x: auto; overflow-y: hidden; scrollbar-width: none; -ms-overflow-style: none; -webkit-overflow-scrolling: touch; }
    .request-scroll::-webkit-scrollbar { display: none; }
    .row-actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .muted { opacity: 0.7; }
    .modal { position: fixed; inset: 0; background: rgba(0,0,0,0.25); display: flex; align-items: center; justify-content: center; z-index: 10; }
    .modal.hidden { display: none; }
    .modal-box { background: #fff; padding: 24px; width: 420px; max-width: 90vw; border: 1px solid #000; display: flex; flex-direction: column; gap: 12px; }
    .modal-box h2 { font-size: 0.95rem; font-weight: 500; }
    .modal-box form { display: flex; flex-direction: column; gap: 12px; }
    .modal-box textarea { min-height: 90px; resize: vertical; }
    .modal-actions { display: flex; gap: 8px; }
    .policy-modal-box { width: 720px; max-height: 90vh; overflow-y: auto; }
    .policy-builder-actions { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
    .policy-features { display: flex; flex-direction: column; gap: 12px; max-height: 52vh; overflow-y: auto; padding-right: 4px; }
    .policy-feature-card { border: 1px solid #000; padding: 16px; display: flex; flex-direction: column; gap: 10px; }
    .policy-feature-card.hidden { display: none; }
    .policy-feature-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .policy-feature-header h3 { margin: 0; font-size: 0.95rem; font-weight: 500; }
    .policy-feature-help { font-size: 0.8rem; opacity: 0.7; }
    .policy-field-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 12px; }
    .policy-field-grid.single { grid-template-columns: minmax(0, 1fr); }
    .policy-field { display: flex; flex-direction: column; gap: 6px; min-width: 0; }
    .policy-field label { font-size: 0.8rem; }
    .policy-add-modal { z-index: 20; }
    .policy-add-list { display: flex; flex-direction: column; gap: 8px; max-height: 50vh; overflow-y: auto; }
    .policy-add-option { width: 100%; text-align: left; padding: 12px; border: 1px solid #000; background: #fff; display: flex; flex-direction: column; gap: 4px; }
    .policy-add-option small { opacity: 0.7; }
    @media (max-width: 700px) {
      .stats-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .policy-modal-box { width: 92vw; }
      .policy-field-grid { grid-template-columns: minmax(0, 1fr); }
      .policy-builder-actions { flex-direction: column; align-items: stretch; }
    }
  </style>
</head>
<body>
  <header>
    <div>waiteway</div>
    <div class="header-actions">
      <form method="post" action="/logout"><button type="submit">logout</button></form>
    </div>
  </header>
  <main class="admin-main">
    <nav class="admin-tabs">
      <button class="tab-btn {{ if eq .ActiveTab "gateway" }}active{{ end }}" type="button" onclick="showTab('gateway', this)">gateway</button>
      <button class="tab-btn {{ if eq .ActiveTab "policy" }}active{{ end }}" type="button" onclick="showTab('policy', this)">policy</button>
      <button class="tab-btn {{ if eq .ActiveTab "logging" }}active{{ end }}" type="button" onclick="showTab('logging', this)">logging</button>
      <button class="tab-btn {{ if eq .ActiveTab "settings" }}active{{ end }}" type="button" onclick="showTab('settings', this)">settings</button>
    </nav>

    <div class="tab-content">
      <section id="gateway-tab" class="tab-panel {{ if eq .ActiveTab "gateway" }}active{{ end }}">
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
                  <th>policy</th>
                  <th>actions</th>
                </tr>
              </thead>
              <tbody>
                {{ range $index, $route := .Routes }}
                <tr>
                  <td><span class="scroll-cell">{{ $route.Name }}</span></td>
                  <td><span class="scroll-cell">{{ $route.PathPrefix }}</span></td>
                  <td><span class="scroll-cell">{{ $route.Target }}</span></td>
                  <td>{{ routePolicyLabel $route }}</td>
                  <td>
                    <div class="row-actions">
                      <button type="button" data-route-index="{{ $index }}" data-route-name="{{ $route.Name }}" data-route-path-prefix="{{ $route.PathPrefix }}" data-route-target="{{ $route.Target }}" data-route-policy-name="{{ $route.PolicyName }}" data-route-strip-prefix="{{ if $route.StripPrefix }}true{{ else }}false{{ end }}" onclick="openEditRouteButton(this)">edit</button>
                      <form method="post" action="/">
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

      <section id="policy-tab" class="tab-panel {{ if eq .ActiveTab "policy" }}active{{ end }}">
        <div class="user-list-panel">
          <h3>policies</h3>
          <div class="panel-body">
            <p><button type="button" onclick="openAddPolicy()">add policy</button></p>
            <table class="routes-table">
              <thead>
                <tr>
                  <th>name</th>
                  <th>details</th>
                  <th>actions</th>
                </tr>
              </thead>
              <tbody>
                {{ range $index, $policy := .Policies }}
                <tr>
                  <td><span class="scroll-cell">{{ $policy.Name }}</span></td>
                  <td><span class="scroll-cell">{{ policySummary $policy }}</span></td>
                  <td>
                    <div class="row-actions">
                      <button type="button" data-policy-index="{{ $index }}" data-policy-name="{{ $policy.Name }}" data-policy-request-timeout-seconds="{{ $policy.RequestTimeoutSeconds }}" data-policy-retry-count="{{ $policy.RetryCount }}" data-policy-require-api-key="{{ if $policy.RequireAPIKey }}true{{ else }}false{{ end }}" data-policy-api-keys="{{ range $i, $key := $policy.APIKeys }}{{ if $i }}&#10;{{ end }}{{ $key }}{{ end }}" data-policy-basic-auth-username="{{ $policy.BasicAuthUsername }}" data-policy-basic-auth-password="{{ $policy.BasicAuthPassword }}" data-policy-rate-limit-requests="{{ $policy.RateLimitRequests }}" data-policy-rate-limit-window-seconds="{{ $policy.RateLimitWindowSeconds }}" data-policy-allowed-methods="{{ range $i, $item := $policy.AllowedMethods }}{{ if $i }}&#10;{{ end }}{{ $item }}{{ end }}" data-policy-rewrite-path-prefix="{{ $policy.RewritePathPrefix }}" data-policy-add-request-headers="{{ range $i, $item := $policy.AddRequestHeaders }}{{ if $i }}&#10;{{ end }}{{ $item }}{{ end }}" data-policy-remove-request-headers="{{ range $i, $item := $policy.RemoveRequestHeaders }}{{ if $i }}&#10;{{ end }}{{ $item }}{{ end }}" data-policy-max-payload-bytes="{{ $policy.MaxPayloadBytes }}" data-policy-request-transform-find="{{ $policy.RequestTransformFind }}" data-policy-request-transform-replace="{{ $policy.RequestTransformReplace }}" data-policy-cache-ttl-seconds="{{ $policy.CacheTTLSeconds }}" data-policy-add-response-headers="{{ range $i, $item := $policy.AddResponseHeaders }}{{ if $i }}&#10;{{ end }}{{ $item }}{{ end }}" data-policy-remove-response-headers="{{ range $i, $item := $policy.RemoveResponseHeaders }}{{ if $i }}&#10;{{ end }}{{ $item }}{{ end }}" data-policy-response-transform-find="{{ $policy.ResponseTransformFind }}" data-policy-response-transform-replace="{{ $policy.ResponseTransformReplace }}" data-policy-max-response-bytes="{{ $policy.MaxResponseBytes }}" data-policy-cors-allow-origins="{{ range $i, $item := $policy.CORSAllowOrigins }}{{ if $i }}&#10;{{ end }}{{ $item }}{{ end }}" data-policy-cors-allow-methods="{{ range $i, $item := $policy.CORSAllowMethods }}{{ if $i }}&#10;{{ end }}{{ $item }}{{ end }}" data-policy-cors-allow-headers="{{ range $i, $item := $policy.CORSAllowHeaders }}{{ if $i }}&#10;{{ end }}{{ $item }}{{ end }}" data-policy-ip-allow-list="{{ range $i, $item := $policy.IPAllowList }}{{ if $i }}&#10;{{ end }}{{ $item }}{{ end }}" data-policy-ip-block-list="{{ range $i, $item := $policy.IPBlockList }}{{ if $i }}&#10;{{ end }}{{ $item }}{{ end }}" data-policy-circuit-breaker-failures="{{ $policy.CircuitBreakerFailures }}" data-policy-circuit-breaker-reset-seconds="{{ $policy.CircuitBreakerResetSeconds }}" onclick="openEditPolicyButton(this)">edit</button>
                      <form method="post" action="/">
                        <input type="hidden" name="action" value="delete_policy">
                        <input type="hidden" name="policy_index" value="{{ $index }}">
                        <button type="submit">delete</button>
                      </form>
                    </div>
                  </td>
                </tr>
                {{ else }}
                <tr><td colspan="3" class="muted">no policies yet</td></tr>
                {{ end }}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section id="logging-tab" class="tab-panel {{ if eq .ActiveTab "logging" }}active{{ end }}">
        <div class="logging-layout">
          <div class="stats-grid">
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
            <div class="stat-card"><div class="stat-label">recent requests</div><div class="stat-value">{{ .LogStats.Total }}</div></div>
            <div class="stat-card"><div class="stat-label">errors</div><div class="stat-value">{{ .LogStats.Errors }}</div></div>
            <div class="stat-card"><div class="stat-label">unauthorized</div><div class="stat-value">{{ .LogStats.Unauthorized }}</div></div>
            <div class="stat-card"><div class="stat-label">successful</div><div class="stat-value">{{ .LogStats.Success }}</div></div>
            <div class="stat-card"><div class="stat-label">unique routes</div><div class="stat-value">{{ .LogStats.UniqueRoutes }}</div></div>
            <div class="stat-card"><div class="stat-label">error rate</div><div class="stat-value">{{ formatPercent .LogStats.ErrorRate }}</div></div>
            <div class="stat-card"><div class="stat-label">avg duration</div><div class="stat-value">{{ formatDurationMS .LogStats.Average }}</div></div>
            <div class="stat-card"><div class="stat-label">slowest</div><div class="stat-value">{{ formatDurationMS .LogStats.Slowest }}</div></div>
          </div>

          <div class="user-list-panel log-panel">
            <h3>recent requests</h3>
            <div class="panel-body log-panel-body">
              <div class="log-table-wrap">
				  <table class="logs-table">
				    <thead>
				      <tr>
				        <th>time</th>
				        <th>ip</th>
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
				        <td><span class="scroll-cell">{{ formatClientIP .RemoteAddr $.LoadBalancerStripPort }}</span></td>
				        <td><span class="scroll-cell">{{ .Route }}</span></td>
				        <td><span class="request-scroll">{{ .Method }} {{ .Path }}</span></td>
				        <td>{{ .Status }}</td>
				        <td>{{ formatDurationMS .Duration }}</td>
				      </tr>
				      {{ else }}
				      <tr><td colspan="6" class="muted">no requests yet</td></tr>
				    {{ end }}
              </tbody>
              </table>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="settings-tab" class="tab-panel {{ if eq .ActiveTab "settings" }}active{{ end }}">
        <div class="users-layout">
          <div class="create-user-panel">
            <h3>admin account</h3>
            <form method="post" action="/?tab=settings">
              <input type="hidden" name="action" value="save_settings">
              <input type="text" name="admin_username" value="{{ .AdminUsername }}" placeholder="admin username">
              <button type="submit">save username</button>
            </form>
            <form method="post" action="/?tab=settings">
              <input type="hidden" name="action" value="change_password">
              <input type="password" name="current_password" placeholder="current password" required>
              <input type="password" name="new_password" placeholder="new password" required>
              <button type="submit">save password</button>
            </form>
          </div>

          <div class="settings-right">
            <div class="user-list-panel" style="min-height: 0; height: auto;">
              <h3>load balancer</h3>
              <div class="panel-body">
                <form method="post" action="/?tab=settings" style="display: flex; flex-direction: column; gap: 16px;">
                  <input type="hidden" name="action" value="save_load_balancer">
                  <table class="config-table">
                    <tbody>
                      <tr>
                        <td><strong>mode</strong></td>
                        <td>
                          <select id="load-balancer-mode" name="load_balancer_mode" onchange="toggleLoadBalancerHeader()">
                            <option value="direct" {{ if eq .LoadBalancerMode "direct" }}selected{{ end }}>direct</option>
                            <option value="standard" {{ if eq .LoadBalancerMode "standard" }}selected{{ end }}>standard</option>
                            <option value="cloudflare" {{ if eq .LoadBalancerMode "cloudflare" }}selected{{ end }}>cloudflare</option>
                            <option value="custom" {{ if eq .LoadBalancerMode "custom" }}selected{{ end }}>custom</option>
                          </select>
                        </td>
                        <td></td>
                      </tr>
                      <tr id="load-balancer-header-row" {{ if ne .LoadBalancerMode "custom" }}style="display:none"{{ end }}>
                        <td><strong>client ip header</strong></td>
                        <td><input id="load-balancer-header" type="text" name="load_balancer_client_ip_header" value="{{ .LoadBalancerHeader }}"></td>
                        <td></td>
                      </tr>
                      <tr>
                        <td><strong>strip port from ip</strong></td>
                        <td>
                          <select id="load-balancer-strip-port" name="load_balancer_strip_port">
                            <option value="true" {{ if .LoadBalancerStripPort }}selected{{ end }}>yes</option>
                            <option value="false" {{ if not .LoadBalancerStripPort }}selected{{ end }}>no</option>
                          </select>
                        </td>
                        <td></td>
                      </tr>
                    </tbody>
                  </table>
                  <button type="submit">save load balancer</button>
                </form>

                <table class="config-table" style="margin-top: 16px;">
                  <tbody>
                    <tr>
                      <td><strong>header order</strong></td>
                      <td>{{ .LoadBalancerHeaders }}</td>
                      <td></td>
                    </tr>
                    <tr>
                      <td><strong>gateway listen</strong></td>
                      <td>{{ .GatewayListen }}</td>
                      <td></td>
                    </tr>
                    <tr>
                      <td><strong>gateway health</strong></td>
                      <td>{{ .GatewayListen }}{{ .GatewayHealthPath }}</td>
                      <td></td>
                    </tr>
                    <tr>
                      <td><strong>admin listen</strong></td>
                      <td>{{ .AdminListen }}</td>
                      <td></td>
                    </tr>
                    <tr>
                      <td><strong>admin health</strong></td>
                      <td>{{ .AdminListen }}{{ .AdminHealthPath }}</td>
                      <td></td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div class="user-list-panel" style="min-height: 0; height: auto;">
              <h3>gateway config</h3>
              <div class="panel-body">
                <table class="config-table">
                  <tbody>
                    <tr>
                      <td><strong>log limit</strong></td>
                      <td>{{ .LogLimit }}</td>
                      <td><button type="button" onclick="openSettingsModal('log_limit', '{{ .LogLimit }}')">edit</button></td>
                    </tr>
                    <tr>
                      <td><strong>routes</strong></td>
                      <td>{{ len .Routes }} ({{ .ProtectedRoutes }} using policy, {{ .OpenRoutes }} open)</td>
                      <td></td>
                    </tr>
                    <tr>
                      <td><strong>policies</strong></td>
                      <td>{{ len .Policies }}</td>
                      <td></td>
                    </tr>
                    <tr>
                      <td><strong>uptime</strong></td>
                      <td>{{ .Uptime }}</td>
                      <td></td>
                    </tr>
                  </tbody>
                </table>
                <div style="margin-top: 16px">
                  <form method="post" action="/?tab=settings" style="display:inline">
                    <input type="hidden" name="action" value="clear_logs">
                    <button type="submit">clear logs</button>
                  </form>
                </div>
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
      <form id="route-form" method="post" action="/">
        <div id="route-modal-error" class="modal-error hidden"></div>
        <input type="hidden" id="route-action" name="action" value="add_route">
        <input type="hidden" id="route-index" name="route_index" value="">
        <label for="route-name">name</label>
        <input id="route-name" type="text" name="route_name" value="" required>
        <label for="route-path-prefix">path prefix</label>
        <input id="route-path-prefix" type="text" name="route_path_prefix" value="" required placeholder="/api/example">
        <label for="route-target">target</label>
        <input id="route-target" type="url" name="route_target" value="" required placeholder="https://example.com">
        <div class="settings-row">
          <label for="route-policy-name">policy</label>
          <select id="route-policy-name" name="route_policy_name">
            <option value="">none</option>
            {{ range .Policies }}
            <option value="{{ .Name }}">{{ .Name }}</option>
            {{ end }}
          </select>
        </div>
        <div class="settings-row">
          <label for="route-strip-prefix">strip</label>
          <select id="route-strip-prefix" name="route_strip_prefix">
            <option value="false">no</option>
            <option value="true">yes</option>
          </select>
        </div>
        <div class="modal-actions">
          <button type="submit">save</button>
          <button type="button" onclick="closeRouteModal()">cancel</button>
        </div>
      </form>
    </div>
  </div>

  <div id="settings-modal" class="modal hidden">
    <div class="modal-box">
      <h2 id="settings-modal-title">edit setting</h2>
      <form method="post" action="/?tab=settings">
        <input type="hidden" id="settings-action" name="action" value="save_logging">
        <input id="settings-value" type="text" name="" value="">
        <div class="modal-actions">
          <button type="submit">save</button>
          <button type="button" onclick="closeSettingsModal()">cancel</button>
        </div>
      </form>
    </div>
  </div>

  <div id="policy-modal" class="modal hidden">
    <div class="modal-box policy-modal-box">
      <h2 id="policy-modal-title">add policy</h2>
      <form id="policy-form" method="post" action="/">
        <input type="hidden" id="policy-action" name="action" value="add_policy">
        <input type="hidden" id="policy-index" name="policy_index" value="">
        <label for="policy-name">name</label>
        <input id="policy-name" type="text" name="policy_name" value="" required>
        <div class="policy-builder-actions">
          <div class="policy-feature-help">add only the pieces you want</div>
          <button type="button" onclick="openPolicyAddModal()">add feature</button>
        </div>
        <div id="policy-features" class="policy-features">
          <section id="feature-timeout" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>request timeout</h3>
              <button type="button" onclick="removePolicyFeature('timeout')">remove</button>
            </div>
            <div class="policy-field-grid single">
              <div class="policy-field">
                <label for="policy-request-timeout-seconds">timeout seconds</label>
                <input id="policy-request-timeout-seconds" type="number" name="policy_request_timeout_seconds" value="" min="0">
              </div>
            </div>
          </section>

          <section id="feature-retry" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>retry</h3>
              <button type="button" onclick="removePolicyFeature('retry')">remove</button>
            </div>
            <div class="policy-field-grid single">
              <div class="policy-field">
                <label for="policy-retry-count">retry count</label>
                <input id="policy-retry-count" type="number" name="policy_retry_count" value="" min="0">
              </div>
            </div>
          </section>

          <section id="feature-api-key" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>api key auth</h3>
              <button type="button" onclick="removePolicyFeature('api-key')">remove</button>
            </div>
            <div class="policy-field-grid single">
              <div class="policy-field">
                <label for="policy-require-api-key">mode</label>
                <select id="policy-require-api-key" name="policy_require_api_key">
                  <option value="false">off</option>
                  <option value="true">on</option>
                </select>
              </div>
              <div class="policy-field">
                <label for="policy-api-keys">api keys</label>
                <textarea id="policy-api-keys" name="policy_api_keys" placeholder="one key per line"></textarea>
              </div>
            </div>
          </section>

          <section id="feature-basic-auth" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>basic auth</h3>
              <button type="button" onclick="removePolicyFeature('basic-auth')">remove</button>
            </div>
            <div class="policy-field-grid">
              <div class="policy-field">
                <label for="policy-basic-auth-username">username</label>
                <input id="policy-basic-auth-username" type="text" name="policy_basic_auth_username" value="">
              </div>
              <div class="policy-field">
                <label for="policy-basic-auth-password">password</label>
                <input id="policy-basic-auth-password" type="text" name="policy_basic_auth_password" value="">
              </div>
            </div>
          </section>

          <section id="feature-rate-limit" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>rate limiting</h3>
              <button type="button" onclick="removePolicyFeature('rate-limit')">remove</button>
            </div>
            <div class="policy-field-grid">
              <div class="policy-field">
                <label for="policy-rate-limit-requests">requests</label>
                <input id="policy-rate-limit-requests" type="number" name="policy_rate_limit_requests" value="" min="0">
              </div>
              <div class="policy-field">
                <label for="policy-rate-limit-window-seconds">window seconds</label>
                <input id="policy-rate-limit-window-seconds" type="number" name="policy_rate_limit_window_seconds" value="" min="0">
              </div>
            </div>
          </section>

          <section id="feature-methods" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>method allow list</h3>
              <button type="button" onclick="removePolicyFeature('methods')">remove</button>
            </div>
            <div class="policy-field-grid single">
              <div class="policy-field">
                <label for="policy-allowed-methods">methods</label>
                <textarea id="policy-allowed-methods" name="policy_allowed_methods" placeholder="one method per line"></textarea>
              </div>
            </div>
          </section>

          <section id="feature-rewrite" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>path rewrite</h3>
              <button type="button" onclick="removePolicyFeature('rewrite')">remove</button>
            </div>
            <div class="policy-field-grid single">
              <div class="policy-field">
                <label for="policy-rewrite-path-prefix">new path prefix</label>
                <input id="policy-rewrite-path-prefix" type="text" name="policy_rewrite_path_prefix" value="">
              </div>
            </div>
          </section>

          <section id="feature-request-headers" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>request headers</h3>
              <button type="button" onclick="removePolicyFeature('request-headers')">remove</button>
            </div>
            <div class="policy-field-grid">
              <div class="policy-field">
                <label for="policy-add-request-headers">add headers</label>
                <textarea id="policy-add-request-headers" name="policy_add_request_headers" placeholder="Header-Name: value"></textarea>
              </div>
              <div class="policy-field">
                <label for="policy-remove-request-headers">remove headers</label>
                <textarea id="policy-remove-request-headers" name="policy_remove_request_headers" placeholder="Header-Name"></textarea>
              </div>
            </div>
          </section>

          <section id="feature-payload-limit" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>payload limit</h3>
              <button type="button" onclick="removePolicyFeature('payload-limit')">remove</button>
            </div>
            <div class="policy-field-grid single">
              <div class="policy-field">
                <label for="policy-max-payload-bytes">max payload bytes</label>
                <input id="policy-max-payload-bytes" type="number" name="policy_max_payload_bytes" value="" min="0">
              </div>
            </div>
          </section>

          <section id="feature-request-transform" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>request transform</h3>
              <button type="button" onclick="removePolicyFeature('request-transform')">remove</button>
            </div>
            <div class="policy-field-grid">
              <div class="policy-field">
                <label for="policy-request-transform-find">find</label>
                <input id="policy-request-transform-find" type="text" name="policy_request_transform_find" value="">
              </div>
              <div class="policy-field">
                <label for="policy-request-transform-replace">replace</label>
                <input id="policy-request-transform-replace" type="text" name="policy_request_transform_replace" value="">
              </div>
            </div>
          </section>

          <section id="feature-cache" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>caching</h3>
              <button type="button" onclick="removePolicyFeature('cache')">remove</button>
            </div>
            <div class="policy-field-grid single">
              <div class="policy-field">
                <label for="policy-cache-ttl-seconds">cache ttl seconds</label>
                <input id="policy-cache-ttl-seconds" type="number" name="policy_cache_ttl_seconds" value="" min="0">
              </div>
            </div>
          </section>

          <section id="feature-response-headers" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>response headers</h3>
              <button type="button" onclick="removePolicyFeature('response-headers')">remove</button>
            </div>
            <div class="policy-field-grid">
              <div class="policy-field">
                <label for="policy-add-response-headers">add headers</label>
                <textarea id="policy-add-response-headers" name="policy_add_response_headers" placeholder="Header-Name: value"></textarea>
              </div>
              <div class="policy-field">
                <label for="policy-remove-response-headers">remove headers</label>
                <textarea id="policy-remove-response-headers" name="policy_remove_response_headers" placeholder="Header-Name"></textarea>
              </div>
            </div>
          </section>

          <section id="feature-response-transform" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>response transform</h3>
              <button type="button" onclick="removePolicyFeature('response-transform')">remove</button>
            </div>
            <div class="policy-field-grid">
              <div class="policy-field">
                <label for="policy-response-transform-find">find</label>
                <input id="policy-response-transform-find" type="text" name="policy_response_transform_find" value="">
              </div>
              <div class="policy-field">
                <label for="policy-response-transform-replace">replace</label>
                <input id="policy-response-transform-replace" type="text" name="policy_response_transform_replace" value="">
              </div>
            </div>
          </section>

          <section id="feature-response-limit" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>response size limit</h3>
              <button type="button" onclick="removePolicyFeature('response-limit')">remove</button>
            </div>
            <div class="policy-field-grid single">
              <div class="policy-field">
                <label for="policy-max-response-bytes">max response bytes</label>
                <input id="policy-max-response-bytes" type="number" name="policy_max_response_bytes" value="" min="0">
              </div>
            </div>
          </section>

          <section id="feature-cors" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>cors</h3>
              <button type="button" onclick="removePolicyFeature('cors')">remove</button>
            </div>
            <div class="policy-field-grid">
              <div class="policy-field">
                <label for="policy-cors-allow-origins">allow origins</label>
                <textarea id="policy-cors-allow-origins" name="policy_cors_allow_origins" placeholder="one origin per line"></textarea>
              </div>
              <div class="policy-field">
                <label for="policy-cors-allow-methods">allow methods</label>
                <textarea id="policy-cors-allow-methods" name="policy_cors_allow_methods" placeholder="one method per line"></textarea>
              </div>
              <div class="policy-field">
                <label for="policy-cors-allow-headers">allow headers</label>
                <textarea id="policy-cors-allow-headers" name="policy_cors_allow_headers" placeholder="one header per line"></textarea>
              </div>
            </div>
          </section>

          <section id="feature-ip-allow" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>ip allow list</h3>
              <button type="button" onclick="removePolicyFeature('ip-allow')">remove</button>
            </div>
            <div class="policy-field-grid single">
              <div class="policy-field">
                <label for="policy-ip-allow-list">allowed ips or cidrs</label>
                <textarea id="policy-ip-allow-list" name="policy_ip_allow_list" placeholder="one ip or cidr per line"></textarea>
              </div>
            </div>
          </section>

          <section id="feature-ip-block" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>ip block list</h3>
              <button type="button" onclick="removePolicyFeature('ip-block')">remove</button>
            </div>
            <div class="policy-field-grid single">
              <div class="policy-field">
                <label for="policy-ip-block-list">blocked ips or cidrs</label>
                <textarea id="policy-ip-block-list" name="policy_ip_block_list" placeholder="one ip or cidr per line"></textarea>
              </div>
            </div>
          </section>

          <section id="feature-circuit-breaker" class="policy-feature-card hidden">
            <div class="policy-feature-header">
              <h3>circuit breaker</h3>
              <button type="button" onclick="removePolicyFeature('circuit-breaker')">remove</button>
            </div>
            <div class="policy-field-grid">
              <div class="policy-field">
                <label for="policy-circuit-breaker-failures">failures</label>
                <input id="policy-circuit-breaker-failures" type="number" name="policy_circuit_breaker_failures" value="" min="0">
              </div>
              <div class="policy-field">
                <label for="policy-circuit-breaker-reset-seconds">reset seconds</label>
                <input id="policy-circuit-breaker-reset-seconds" type="number" name="policy_circuit_breaker_reset_seconds" value="" min="0">
              </div>
            </div>
          </section>
        </div>
        <div class="modal-actions">
          <button type="submit">save</button>
          <button type="button" onclick="closePolicyModal()">cancel</button>
        </div>
      </form>
    </div>
  </div>

  <div id="policy-add-modal" class="modal policy-add-modal hidden">
    <div class="modal-box">
      <h2>add policy feature</h2>
      <div class="policy-add-list">
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('timeout')"><strong>request timeout</strong><small>stop slow upstream calls</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('retry')"><strong>retry</strong><small>retry network failures a few times</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('api-key')"><strong>api key auth</strong><small>require a key and optionally list allowed keys</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('basic-auth')"><strong>basic auth</strong><small>protect with username and password</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('rate-limit')"><strong>rate limiting</strong><small>limit requests in a time window</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('methods')"><strong>method allow list</strong><small>allow only specific HTTP methods</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('rewrite')"><strong>path rewrite</strong><small>replace the matched route prefix</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('request-headers')"><strong>request headers</strong><small>add or remove headers before proxying</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('payload-limit')"><strong>payload limit</strong><small>reject bodies over a size limit</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('request-transform')"><strong>request transform</strong><small>simple request body find and replace</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('cache')"><strong>caching</strong><small>cache successful GET responses</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('response-headers')"><strong>response headers</strong><small>add or remove response headers</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('response-transform')"><strong>response transform</strong><small>simple response body find and replace</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('response-limit')"><strong>response size limit</strong><small>reject oversized upstream responses</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('cors')"><strong>cors</strong><small>set allowed origins, methods, and headers</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('ip-allow')"><strong>ip allow list</strong><small>only allow listed ips or cidrs</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('ip-block')"><strong>ip block list</strong><small>deny listed ips or cidrs</small></button>
        <button type="button" class="policy-add-option" onclick="addPolicyFeature('circuit-breaker')"><strong>circuit breaker</strong><small>pause a failing upstream for a short time</small></button>
      </div>
      <div class="modal-actions">
        <button type="button" onclick="closePolicyAddModal()">close</button>
      </div>
    </div>
  </div>

  <script>
    var settingsFieldMap = {
      'log_limit': { title: 'edit log limit', action: 'save_logging' }
    }

    var existingPolicyNames = [{{ range $index, $policy := .Policies }}{{ if $index }}, {{ end }}{{ printf "%q" $policy.Name }}{{ end }}]
    var existingRoutePathPrefixes = [{{ range $index, $route := .Routes }}{{ if $index }}, {{ end }}{{ printf "%q" $route.PathPrefix }}{{ end }}]

    var policyFeatureMap = {
      'timeout': {
        cardId: 'feature-timeout',
        reset: function () {
          document.getElementById('policy-request-timeout-seconds').value = ''
        }
      },
      'retry': {
        cardId: 'feature-retry',
        reset: function () {
          document.getElementById('policy-retry-count').value = ''
        }
      },
      'api-key': {
        cardId: 'feature-api-key',
        reset: function () {
          document.getElementById('policy-require-api-key').value = 'false'
          document.getElementById('policy-api-keys').value = ''
        }
      },
      'basic-auth': {
        cardId: 'feature-basic-auth',
        reset: function () {
          document.getElementById('policy-basic-auth-username').value = ''
          document.getElementById('policy-basic-auth-password').value = ''
        }
      },
      'rate-limit': {
        cardId: 'feature-rate-limit',
        reset: function () {
          document.getElementById('policy-rate-limit-requests').value = ''
          document.getElementById('policy-rate-limit-window-seconds').value = ''
        }
      },
      'methods': {
        cardId: 'feature-methods',
        reset: function () {
          document.getElementById('policy-allowed-methods').value = ''
        }
      },
      'rewrite': {
        cardId: 'feature-rewrite',
        reset: function () {
          document.getElementById('policy-rewrite-path-prefix').value = ''
        }
      },
      'request-headers': {
        cardId: 'feature-request-headers',
        reset: function () {
          document.getElementById('policy-add-request-headers').value = ''
          document.getElementById('policy-remove-request-headers').value = ''
        }
      },
      'payload-limit': {
        cardId: 'feature-payload-limit',
        reset: function () {
          document.getElementById('policy-max-payload-bytes').value = ''
        }
      },
      'request-transform': {
        cardId: 'feature-request-transform',
        reset: function () {
          document.getElementById('policy-request-transform-find').value = ''
          document.getElementById('policy-request-transform-replace').value = ''
        }
      },
      'cache': {
        cardId: 'feature-cache',
        reset: function () {
          document.getElementById('policy-cache-ttl-seconds').value = ''
        }
      },
      'response-headers': {
        cardId: 'feature-response-headers',
        reset: function () {
          document.getElementById('policy-add-response-headers').value = ''
          document.getElementById('policy-remove-response-headers').value = ''
        }
      },
      'response-transform': {
        cardId: 'feature-response-transform',
        reset: function () {
          document.getElementById('policy-response-transform-find').value = ''
          document.getElementById('policy-response-transform-replace').value = ''
        }
      },
      'response-limit': {
        cardId: 'feature-response-limit',
        reset: function () {
          document.getElementById('policy-max-response-bytes').value = ''
        }
      },
      'cors': {
        cardId: 'feature-cors',
        reset: function () {
          document.getElementById('policy-cors-allow-origins').value = ''
          document.getElementById('policy-cors-allow-methods').value = ''
          document.getElementById('policy-cors-allow-headers').value = ''
        }
      },
      'ip-allow': {
        cardId: 'feature-ip-allow',
        reset: function () {
          document.getElementById('policy-ip-allow-list').value = ''
        }
      },
      'ip-block': {
        cardId: 'feature-ip-block',
        reset: function () {
          document.getElementById('policy-ip-block-list').value = ''
        }
      },
      'circuit-breaker': {
        cardId: 'feature-circuit-breaker',
        reset: function () {
          document.getElementById('policy-circuit-breaker-failures').value = ''
          document.getElementById('policy-circuit-breaker-reset-seconds').value = ''
        }
      }
    }

    function openSettingsModal(field, currentValue) {
      var info = settingsFieldMap[field]
      document.getElementById('settings-modal-title').textContent = info.title
      document.getElementById('settings-action').value = info.action
      var input = document.getElementById('settings-value')
      input.name = field
      input.value = currentValue
      if (field === 'log_limit') input.type = 'number'
      else input.type = 'text'
      document.getElementById('settings-modal').classList.remove('hidden')
    }

    function closeSettingsModal() {
      document.getElementById('settings-modal').classList.add('hidden')
    }

    function toggleLoadBalancerHeader() {
      var mode = document.getElementById('load-balancer-mode')
      var row = document.getElementById('load-balancer-header-row')
      if (!mode || !row) return
      row.style.display = mode.value === 'custom' ? 'table-row' : 'none'
    }

    function showTab(name, button) {
      document.querySelectorAll('.tab-btn').forEach((button) => button.classList.remove('active'))
      document.querySelectorAll('.tab-panel').forEach((panel) => panel.classList.remove('active'))
      button.classList.add('active')
      document.getElementById(name + '-tab').classList.add('active')
      var nextURL = new URL(window.location.href)
      if (name === 'gateway') nextURL.searchParams.delete('tab')
      else nextURL.searchParams.set('tab', name)
      window.history.replaceState({}, '', nextURL.toString())
    }

    function showRouteError(msg) {
      var el = document.getElementById('route-modal-error')
      el.textContent = msg
      el.classList.remove('hidden')
    }

    function clearRouteError() {
      var el = document.getElementById('route-modal-error')
      el.textContent = ''
      el.classList.add('hidden')
    }

    function openAddRoute() {
      document.getElementById('route-modal-title').textContent = 'add route'
      document.getElementById('route-action').value = 'add_route'
      document.getElementById('route-index').value = ''
      document.getElementById('route-name').value = ''
      document.getElementById('route-path-prefix').value = ''
      document.getElementById('route-target').value = ''
      document.getElementById('route-policy-name').value = ''
      document.getElementById('route-strip-prefix').value = 'false'
      clearRouteError()
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
      document.getElementById('route-policy-name').value = data.routePolicyName
      document.getElementById('route-strip-prefix').value = data.routeStripPrefix
      clearRouteError()
      document.getElementById('route-modal').classList.remove('hidden')
    }

    function closeRouteModal() {
      clearRouteError()
      document.getElementById('route-modal').classList.add('hidden')
    }

    toggleLoadBalancerHeader()

    function openAddPolicy() {
      document.getElementById('policy-modal-title').textContent = 'add policy'
      document.getElementById('policy-action').value = 'add_policy'
      document.getElementById('policy-index').value = ''
      document.getElementById('policy-name').value = ''
      resetPolicyFeatures()
      document.getElementById('policy-modal').classList.remove('hidden')
    }

    function openEditPolicyButton(button) {
      const data = button.dataset
      document.getElementById('policy-modal-title').textContent = 'edit policy'
      document.getElementById('policy-action').value = 'update_policy'
      document.getElementById('policy-index').value = data.policyIndex
      document.getElementById('policy-name').value = data.policyName
      document.getElementById('policy-request-timeout-seconds').value = data.policyRequestTimeoutSeconds
      document.getElementById('policy-retry-count').value = data.policyRetryCount
      document.getElementById('policy-require-api-key').value = data.policyRequireApiKey
      document.getElementById('policy-api-keys').value = data.policyApiKeys
      document.getElementById('policy-basic-auth-username').value = data.policyBasicAuthUsername
      document.getElementById('policy-basic-auth-password').value = data.policyBasicAuthPassword
      document.getElementById('policy-rate-limit-requests').value = data.policyRateLimitRequests
      document.getElementById('policy-rate-limit-window-seconds').value = data.policyRateLimitWindowSeconds
      document.getElementById('policy-allowed-methods').value = data.policyAllowedMethods
      document.getElementById('policy-rewrite-path-prefix').value = data.policyRewritePathPrefix
      document.getElementById('policy-add-request-headers').value = data.policyAddRequestHeaders
      document.getElementById('policy-remove-request-headers').value = data.policyRemoveRequestHeaders
      document.getElementById('policy-max-payload-bytes').value = data.policyMaxPayloadBytes
      document.getElementById('policy-request-transform-find').value = data.policyRequestTransformFind
      document.getElementById('policy-request-transform-replace').value = data.policyRequestTransformReplace
      document.getElementById('policy-cache-ttl-seconds').value = data.policyCacheTtlSeconds
      document.getElementById('policy-add-response-headers').value = data.policyAddResponseHeaders
      document.getElementById('policy-remove-response-headers').value = data.policyRemoveResponseHeaders
      document.getElementById('policy-response-transform-find').value = data.policyResponseTransformFind
      document.getElementById('policy-response-transform-replace').value = data.policyResponseTransformReplace
      document.getElementById('policy-max-response-bytes').value = data.policyMaxResponseBytes
      document.getElementById('policy-cors-allow-origins').value = data.policyCorsAllowOrigins
      document.getElementById('policy-cors-allow-methods').value = data.policyCorsAllowMethods
      document.getElementById('policy-cors-allow-headers').value = data.policyCorsAllowHeaders
      document.getElementById('policy-ip-allow-list').value = data.policyIpAllowList
      document.getElementById('policy-ip-block-list').value = data.policyIpBlockList
      document.getElementById('policy-circuit-breaker-failures').value = data.policyCircuitBreakerFailures
      document.getElementById('policy-circuit-breaker-reset-seconds').value = data.policyCircuitBreakerResetSeconds
      syncPolicyFeaturesFromValues()
      document.getElementById('policy-modal').classList.remove('hidden')
    }

    function closePolicyModal() {
      document.getElementById('policy-modal').classList.add('hidden')
      closePolicyAddModal()
    }

    function openPolicyAddModal() {
      document.getElementById('policy-add-modal').classList.remove('hidden')
    }

    function closePolicyAddModal() {
      document.getElementById('policy-add-modal').classList.add('hidden')
    }

    function addPolicyFeature(name) {
      var feature = policyFeatureMap[name]
      if (!feature) return
      document.getElementById(feature.cardId).classList.remove('hidden')
      closePolicyAddModal()
    }

    function removePolicyFeature(name) {
      var feature = policyFeatureMap[name]
      if (!feature) return
      feature.reset()
      document.getElementById(feature.cardId).classList.add('hidden')
    }

    function resetPolicyFeatures() {
      Object.keys(policyFeatureMap).forEach(function (name) {
        policyFeatureMap[name].reset()
        document.getElementById(policyFeatureMap[name].cardId).classList.add('hidden')
      })
    }

    function hidePolicyFeatures() {
      Object.keys(policyFeatureMap).forEach(function (name) {
        document.getElementById(policyFeatureMap[name].cardId).classList.add('hidden')
      })
    }

    function syncPolicyFeaturesFromValues() {
      var values = {
        requestTimeoutSeconds: document.getElementById('policy-request-timeout-seconds').value,
        retryCount: document.getElementById('policy-retry-count').value,
        requireApiKey: document.getElementById('policy-require-api-key').value,
        apiKeys: document.getElementById('policy-api-keys').value,
        basicAuthUsername: document.getElementById('policy-basic-auth-username').value,
        basicAuthPassword: document.getElementById('policy-basic-auth-password').value,
        rateLimitRequests: document.getElementById('policy-rate-limit-requests').value,
        rateLimitWindowSeconds: document.getElementById('policy-rate-limit-window-seconds').value,
        allowedMethods: document.getElementById('policy-allowed-methods').value,
        rewritePathPrefix: document.getElementById('policy-rewrite-path-prefix').value,
        addRequestHeaders: document.getElementById('policy-add-request-headers').value,
        removeRequestHeaders: document.getElementById('policy-remove-request-headers').value,
        maxPayloadBytes: document.getElementById('policy-max-payload-bytes').value,
        requestTransformFind: document.getElementById('policy-request-transform-find').value,
        requestTransformReplace: document.getElementById('policy-request-transform-replace').value,
        cacheTTLSeconds: document.getElementById('policy-cache-ttl-seconds').value,
        addResponseHeaders: document.getElementById('policy-add-response-headers').value,
        removeResponseHeaders: document.getElementById('policy-remove-response-headers').value,
        responseTransformFind: document.getElementById('policy-response-transform-find').value,
        responseTransformReplace: document.getElementById('policy-response-transform-replace').value,
        maxResponseBytes: document.getElementById('policy-max-response-bytes').value,
        corsAllowOrigins: document.getElementById('policy-cors-allow-origins').value,
        corsAllowMethods: document.getElementById('policy-cors-allow-methods').value,
        corsAllowHeaders: document.getElementById('policy-cors-allow-headers').value,
        ipAllowList: document.getElementById('policy-ip-allow-list').value,
        ipBlockList: document.getElementById('policy-ip-block-list').value,
        circuitBreakerFailures: document.getElementById('policy-circuit-breaker-failures').value,
        circuitBreakerResetSeconds: document.getElementById('policy-circuit-breaker-reset-seconds').value
      }

      hidePolicyFeatures()

      document.getElementById('policy-request-timeout-seconds').value = values.requestTimeoutSeconds
      document.getElementById('policy-retry-count').value = values.retryCount
      document.getElementById('policy-require-api-key').value = values.requireApiKey
      document.getElementById('policy-api-keys').value = values.apiKeys
      document.getElementById('policy-basic-auth-username').value = values.basicAuthUsername
      document.getElementById('policy-basic-auth-password').value = values.basicAuthPassword
      document.getElementById('policy-rate-limit-requests').value = values.rateLimitRequests
      document.getElementById('policy-rate-limit-window-seconds').value = values.rateLimitWindowSeconds
      document.getElementById('policy-allowed-methods').value = values.allowedMethods
      document.getElementById('policy-rewrite-path-prefix').value = values.rewritePathPrefix
      document.getElementById('policy-add-request-headers').value = values.addRequestHeaders
      document.getElementById('policy-remove-request-headers').value = values.removeRequestHeaders
      document.getElementById('policy-max-payload-bytes').value = values.maxPayloadBytes
      document.getElementById('policy-request-transform-find').value = values.requestTransformFind
      document.getElementById('policy-request-transform-replace').value = values.requestTransformReplace
      document.getElementById('policy-cache-ttl-seconds').value = values.cacheTTLSeconds
      document.getElementById('policy-add-response-headers').value = values.addResponseHeaders
      document.getElementById('policy-remove-response-headers').value = values.removeResponseHeaders
      document.getElementById('policy-response-transform-find').value = values.responseTransformFind
      document.getElementById('policy-response-transform-replace').value = values.responseTransformReplace
      document.getElementById('policy-max-response-bytes').value = values.maxResponseBytes
      document.getElementById('policy-cors-allow-origins').value = values.corsAllowOrigins
      document.getElementById('policy-cors-allow-methods').value = values.corsAllowMethods
      document.getElementById('policy-cors-allow-headers').value = values.corsAllowHeaders
      document.getElementById('policy-ip-allow-list').value = values.ipAllowList
      document.getElementById('policy-ip-block-list').value = values.ipBlockList
      document.getElementById('policy-circuit-breaker-failures').value = values.circuitBreakerFailures
      document.getElementById('policy-circuit-breaker-reset-seconds').value = values.circuitBreakerResetSeconds

      if (featureValueIsEnabled('policy-request-timeout-seconds')) addPolicyFeature('timeout')
      if (featureValueIsEnabled('policy-retry-count')) addPolicyFeature('retry')
      if (document.getElementById('policy-require-api-key').value === 'true' || document.getElementById('policy-api-keys').value.trim() !== '') addPolicyFeature('api-key')
      if (document.getElementById('policy-basic-auth-username').value.trim() !== '' || document.getElementById('policy-basic-auth-password').value.trim() !== '') addPolicyFeature('basic-auth')
      if (featureValueIsEnabled('policy-rate-limit-requests') || featureValueIsEnabled('policy-rate-limit-window-seconds')) addPolicyFeature('rate-limit')
      if (document.getElementById('policy-allowed-methods').value.trim() !== '') addPolicyFeature('methods')
      if (document.getElementById('policy-rewrite-path-prefix').value.trim() !== '') addPolicyFeature('rewrite')
      if (document.getElementById('policy-add-request-headers').value.trim() !== '' || document.getElementById('policy-remove-request-headers').value.trim() !== '') addPolicyFeature('request-headers')
      if (featureValueIsEnabled('policy-max-payload-bytes')) addPolicyFeature('payload-limit')
      if (document.getElementById('policy-request-transform-find').value.trim() !== '' || document.getElementById('policy-request-transform-replace').value.trim() !== '') addPolicyFeature('request-transform')
      if (featureValueIsEnabled('policy-cache-ttl-seconds')) addPolicyFeature('cache')
      if (document.getElementById('policy-add-response-headers').value.trim() !== '' || document.getElementById('policy-remove-response-headers').value.trim() !== '') addPolicyFeature('response-headers')
      if (document.getElementById('policy-response-transform-find').value.trim() !== '' || document.getElementById('policy-response-transform-replace').value.trim() !== '') addPolicyFeature('response-transform')
      if (featureValueIsEnabled('policy-max-response-bytes')) addPolicyFeature('response-limit')
      if (document.getElementById('policy-cors-allow-origins').value.trim() !== '' || document.getElementById('policy-cors-allow-methods').value.trim() !== '' || document.getElementById('policy-cors-allow-headers').value.trim() !== '') addPolicyFeature('cors')
      if (document.getElementById('policy-ip-allow-list').value.trim() !== '') addPolicyFeature('ip-allow')
      if (document.getElementById('policy-ip-block-list').value.trim() !== '') addPolicyFeature('ip-block')
      if (featureValueIsEnabled('policy-circuit-breaker-failures') || featureValueIsEnabled('policy-circuit-breaker-reset-seconds')) addPolicyFeature('circuit-breaker')
    }

    function featureValueIsEnabled(id) {
      var value = document.getElementById(id).value.trim()
      if (value === '') return false
      var number = Number(value)
      if (Number.isNaN(number)) return true
      return number > 0
    }

    document.getElementById('policy-form').addEventListener('submit', function (event) {
      var nameInput = document.getElementById('policy-name')
      var nextName = nameInput.value.trim().toLowerCase()
      var currentIndex = document.getElementById('policy-index').value
      var duplicate = existingPolicyNames.some(function (name, index) {
        if (currentIndex !== '' && String(index) === currentIndex) return false
        return name.trim().toLowerCase() === nextName
      })
      if (!duplicate) return
      event.preventDefault()
      window.alert('policy name already exists')
    })

    function normalizeRoutePathPrefix(value) {
      var trimmed = (value || '').trim()
      if (trimmed === '') return ''
      if (trimmed.charAt(0) !== '/') trimmed = '/' + trimmed
      while (trimmed.length > 1 && trimmed.charAt(trimmed.length - 1) === '/') {
        trimmed = trimmed.slice(0, -1)
      }
      return trimmed
    }

    document.getElementById('route-form').addEventListener('submit', function (event) {
      var name = document.getElementById('route-name').value.trim()
      var prefix = normalizeRoutePathPrefix(document.getElementById('route-path-prefix').value)
      var target = document.getElementById('route-target').value.trim()
      var currentIndex = document.getElementById('route-index').value

      clearRouteError()

      if (name === '') { event.preventDefault(); showRouteError('name is required'); return }
      if (prefix === '') { event.preventDefault(); showRouteError('path prefix is required'); return }
      if (target === '') { event.preventDefault(); showRouteError('target is required'); return }

      if (!/^https?:\/\/[^\s/]+/.test(target)) {
        event.preventDefault()
        showRouteError('target must start with http:// or https:// and include a host')
        return
      }

      var duplicate = existingRoutePathPrefixes.some(function (existing, index) {
        if (currentIndex !== '' && String(index) === currentIndex) return false
        return existing === prefix
      })
      if (duplicate) {
        event.preventDefault()
        showRouteError('path prefix "' + prefix + '" is already in use')
      }
    })
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
      <form method="post" action="/login">
        <input type="text" name="username" placeholder="username" autocomplete="username" required>
        <input type="password" name="password" placeholder="password" autocomplete="current-password" required>
        <button type="submit">login</button>
      </form>
      <div class="{{ if .Error }}error{{ else }}error hidden{{ end }}">{{ .Error }}</div>
    </div>
  </div>
</body>
</html>`
