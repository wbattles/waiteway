package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func (g *Gateway) handleAdminClearLogs(w http.ResponseWriter, r *http.Request) {
	g.store.ClearLogs()
	http.Redirect(w, r, "/?tab=config", http.StatusSeeOther)
}

func (g *Gateway) handleAdminSaveSettings(w http.ResponseWriter, r *http.Request) {
	config, err := settingsConfigFromForm(r, g.currentConfig())
	if err != nil {
		config.ActiveTab = "config"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	if err := g.saveConfig(config); err != nil {
		config.ActiveTab = "config"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	http.Redirect(w, r, "/?tab=config", http.StatusSeeOther)
}

func (g *Gateway) handleAdminChangePassword(w http.ResponseWriter, r *http.Request) {
	config := g.currentConfig()
	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")

	if currentPassword != config.Admin.Password {
		config.ActiveTab = "config"
		g.renderAdminForm(w, config, "", "current password is wrong")
		return
	}
	if strings.TrimSpace(newPassword) == "" {
		config.ActiveTab = "config"
		g.renderAdminForm(w, config, "", "new password is required")
		return
	}

	config.Admin.Password = newPassword
	if err := g.saveConfig(config); err != nil {
		config.ActiveTab = "config"
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
		config.ActiveTab = "config"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	if err := g.saveConfig(config); err != nil {
		config.ActiveTab = "config"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	http.Redirect(w, r, "/?tab=config", http.StatusSeeOther)
}

func (g *Gateway) handleAdminSaveLoadBalancer(w http.ResponseWriter, r *http.Request) {
	config, err := loadBalancerConfigFromForm(r, g.currentConfig())
	if err != nil {
		config.ActiveTab = "config"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	if err := g.saveConfig(config); err != nil {
		config.ActiveTab = "config"
		g.renderAdminForm(w, config, "", err.Error())
		return
	}

	tab := normalizeAdminTab(r.URL.Query().Get("tab"))
	http.Redirect(w, r, "/?tab="+tab, http.StatusSeeOther)
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
