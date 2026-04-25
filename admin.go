package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type adminPageData struct {
	AdminUsername         string
	LogLimit              int
	LoadBalancerMode      string
	LoadBalancerHeader    string
	LoadBalancerHeaders   string
	LoadBalancerStripPort bool
	GatewayListen         string
	AdminListen           string
	Policies              []Policy
	Routes                []Route
	ActiveTab             string
	OpenRoutes            int
	ProtectedRoutes       int
	Logs                  []requestLog
	LogStats              logStats
	RouteStats            []routeStat
	Uptime                string
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

func (g *Gateway) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/metrics", g.handleMetrics)
	mux.HandleFunc("/login", g.handleAdminLogin)
	mux.HandleFunc("/logout", g.handleAdminLogout)
	mux.HandleFunc("/", g.handleAdmin)
	return mux
}

func (g *Gateway) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprintf(
		w,
		"# HELP waiteway_requests_total Total gateway requests.\n"+
			"# TYPE waiteway_requests_total counter\n"+
			"waiteway_requests_total %d\n"+
			"# HELP waiteway_errors_total Total gateway requests with 5xx status.\n"+
			"# TYPE waiteway_errors_total counter\n"+
			"waiteway_errors_total %d\n",
		atomic.LoadUint64(&g.metrics.requestsTotal),
		atomic.LoadUint64(&g.metrics.errorsTotal),
	)
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

	errText := r.URL.Query().Get("error")
	activeTab := normalizeAdminTab(r.URL.Query().Get("tab"))
	g.renderAdminPage(w, g.adminPageData(errText, activeTab), http.StatusOK)
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
	if _, err := compileConfig(config); err != nil {
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

func (g *Gateway) adminPageData(errText, activeTab string) adminPageData {
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
		LogLimit:              config.LogLimit,
		LoadBalancerMode:      config.LoadBalancer.Mode,
		LoadBalancerHeader:    config.LoadBalancer.ClientIPHeader,
		LoadBalancerHeaders:   strings.Join(clientIPHeaderChain(config.LoadBalancer), " → "),
		LoadBalancerStripPort: config.LoadBalancer.StripPort,
		GatewayListen:         g.listenAddr,
		AdminListen:           g.adminListen,
		Policies:              policies,
		Routes:                routes,
		ActiveTab:             normalizeAdminTab(activeTab),
		OpenRoutes:            openRoutes,
		ProtectedRoutes:       protectedRoutes,
		Logs:                  logs,
		LogStats:              stats,
		RouteStats:            routeStats,
		Uptime:                formatUptime(time.Since(g.startedAt)),
		Error:                 errText,
	}

	return data
}

func (g *Gateway) renderAdminError(w http.ResponseWriter, message string) {
	g.renderAdminPage(w, g.adminPageData(message, "gateway"), http.StatusBadRequest)
}

func (g *Gateway) renderAdminForm(w http.ResponseWriter, config Config, errText string) {
	data := g.adminPageData(errText, config.ActiveTab)
	data.AdminUsername = config.Admin.Username
	data.LogLimit = config.LogLimit
	data.LoadBalancerMode = config.LoadBalancer.Mode
	data.LoadBalancerHeader = config.LoadBalancer.ClientIPHeader
	data.LoadBalancerHeaders = strings.Join(clientIPHeaderChain(config.LoadBalancer), " → ")
	data.LoadBalancerStripPort = config.LoadBalancer.StripPort
	data.Policies = config.Policies
	data.Routes = config.Routes
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
		name := routeStatName(entry)
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

func routeStatName(entry requestLog) string {
	name := strings.TrimSpace(entry.Path)
	name = strings.TrimPrefix(name, "/")
	if name == "" {
		name = "root"
	}

	return name
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
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

func normalizeAdminTab(value string) string {
	switch value {
	case "policy", "logging", "settings":
		return value
	default:
		return "gateway"
	}
}
