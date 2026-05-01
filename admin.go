package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type adminPageData struct {
	CurrentUser           User
	IsAdmin               bool
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
	mux.HandleFunc("/admin", g.handleUsersAdminPage)
	mux.HandleFunc("/settings", g.handleSettingsPage)
	mux.HandleFunc("/api/", g.handleAPI)
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
	user, ok := g.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		g.handleAdminPost(w, r)
		return
	}

	errText := r.URL.Query().Get("error")
	activeTab := normalizeAdminTab(r.URL.Query().Get("tab"))
	g.renderAdminPage(w, g.adminPageData(user, errText, activeTab), http.StatusOK)
}

func (g *Gateway) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if _, ok := g.currentUser(r); ok && r.Method == http.MethodGet {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
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

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	user, err := g.store.GetUserByUsername(username)
	if err != nil || !checkPassword(password, user.PasswordHash) {
		g.renderLogin(w, "login failed")
		return
	}

	sessionID, err := newSessionID()
	if err != nil {
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	if err := g.store.AddUserSession(sessionID, user.ID); err != nil {
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "waiteway_session",
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

	if cookie, err := r.Cookie("waiteway_session"); err == nil {
		g.store.DeleteSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "waiteway_session",
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
		if !g.authorizeAdmin(r) {
			g.renderAdminError(w, "admin access required")
			return
		}
		g.handleAdminAddPolicy(w, r)
	case "update_policy":
		if !g.authorizeAdmin(r) {
			g.renderAdminError(w, "admin access required")
			return
		}
		g.handleAdminUpdatePolicy(w, r)
	case "delete_policy":
		if !g.authorizeAdmin(r) {
			g.renderAdminError(w, "admin access required")
			return
		}
		g.handleAdminDeletePolicy(w, r)
	case "save_logging":
		if !g.authorizeAdmin(r) {
			g.renderAdminError(w, "admin access required")
			return
		}
		g.handleAdminSaveLogging(w, r)
	case "save_load_balancer":
		if !g.authorizeAdmin(r) {
			g.renderAdminError(w, "admin access required")
			return
		}
		g.handleAdminSaveLoadBalancer(w, r)
	case "clear_logs":
		if !g.authorizeAdmin(r) {
			g.renderAdminError(w, "admin access required")
			return
		}
		g.handleAdminClearLogs(w, r)
	case "add_route":
		if !g.authorizeAdmin(r) {
			g.renderAdminError(w, "admin access required")
			return
		}
		g.handleAdminAddRoute(w, r)
	case "update_route":
		if !g.authorizeAdmin(r) {
			g.renderAdminError(w, "admin access required")
			return
		}
		g.handleAdminUpdateRoute(w, r)
	case "delete_route":
		if !g.authorizeAdmin(r) {
			g.renderAdminError(w, "admin access required")
			return
		}
		g.handleAdminDeleteRoute(w, r)
	default:
		g.renderAdminError(w, "unknown admin action")
	}
}

func (g *Gateway) authorizeAdmin(r *http.Request) bool {
	user, ok := g.currentUser(r)
	return ok && user.IsAdmin
}

func (g *Gateway) currentUser(r *http.Request) (User, bool) {
	cookie, err := r.Cookie("waiteway_session")
	if err != nil || cookie.Value == "" {
		return User{}, false
	}
	user, err := g.store.UserBySessionID(cookie.Value)
	if err != nil {
		return User{}, false
	}
	return user, true
}

func newSessionID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// saveConfig validates a Config, persists it, and applies the new config to
// the running gateway. If any step fails the gateway state is left unchanged.
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

// silentAdminRedirect sends the admin back to a clean GET URL. Client-side
// validation catches the common mistakes; the rare server-side failure (two
// tabs racing, JS disabled) just returns to the admin page without polluting
// the URL with state.
func silentAdminRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (g *Gateway) adminPageData(user User, errText, activeTab string) adminPageData {
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
		if route.PolicyName != "" {
			protectedRoutes++
		} else {
			openRoutes++
		}
	}

	data := adminPageData{
		CurrentUser:           user,
		IsAdmin:               user.IsAdmin,
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
	g.renderAdminPage(w, g.adminPageData(User{}, message, "gateway"), http.StatusBadRequest)
}

func (g *Gateway) renderAdminForm(w http.ResponseWriter, config Config, _ string, errText string) {
	data := g.adminPageData(User{IsAdmin: true}, errText, config.ActiveTab)
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

func (g *Gateway) renderLogin(w http.ResponseWriter, errText string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := g.loginTmpl.Execute(w, loginPageData{Error: errText}); err != nil {
		http.Error(w, "login render failed", http.StatusInternalServerError)
	}
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

func splitInts(value string) []int {
	items := splitLines(value)
	result := make([]int, 0, len(items))
	seen := map[int]struct{}{}
	for _, item := range items {
		parsed, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil || parsed <= 0 {
			continue
		}
		if _, ok := seen[parsed]; ok {
			continue
		}
		seen[parsed] = struct{}{}
		result = append(result, parsed)
	}
	return result
}

func joinInts(values []int) string {
	items := make([]string, 0, len(values))
	seen := map[int]struct{}{}
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		items = append(items, strconv.Itoa(value))
	}
	return strings.Join(items, "\n")
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
	case "policy", "logging", "settings", "config":
		if value == "settings" {
			return "config"
		}
		return value
	default:
		return "gateway"
	}
}
