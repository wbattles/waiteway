package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func (g *Gateway) handleAdminAddRoute(w http.ResponseWriter, r *http.Request) {
	config := g.currentConfig()
	config.ActiveTab = "gateway"
	route, err := routeFromForm(r)
	if err != nil {
		log.Printf("waiteway add route form error: %v", err)
		g.renderAdminRouteForm(w, config, route, "add route", "add_route", "", err.Error())
		return
	}

	if err := g.store.AddRoute(route); err != nil {
		log.Printf("waiteway add route store error: %v", err)
		g.renderAdminRouteForm(w, config, route, "add route", "add_route", "", err.Error())
		return
	}

	g.finishAdminAction(w, r, "/", "gateway")
}

func (g *Gateway) handleAdminUpdateRoute(w http.ResponseWriter, r *http.Request) {
	config := g.currentConfig()
	config.ActiveTab = "gateway"
	index, err := routeIndexFromForm(r, len(config.Routes))
	if err != nil {
		log.Printf("waiteway update route index error: %v", err)
		g.renderAdminForm(w, config, err.Error())
		return
	}

	route, err := routeFromForm(r)
	if err != nil {
		log.Printf("waiteway update route form error: %v", err)
		g.renderAdminRouteForm(w, config, route, "edit route", "update_route", strconv.Itoa(index), err.Error())
		return
	}

	if err := g.store.UpdateRoute(index, route); err != nil {
		log.Printf("waiteway update route store error: %v", err)
		g.renderAdminRouteForm(w, config, route, "edit route", "update_route", strconv.Itoa(index), err.Error())
		return
	}

	g.finishAdminAction(w, r, "/", "gateway")
}

func (g *Gateway) handleAdminDeleteRoute(w http.ResponseWriter, r *http.Request) {
	config := g.currentConfig()
	index, err := routeIndexFromForm(r, len(config.Routes))
	if err != nil {
		config.ActiveTab = "gateway"
		g.renderAdminForm(w, config, err.Error())
		return
	}

	if err := g.store.DeleteRoute(index); err != nil {
		config.ActiveTab = "gateway"
		g.renderAdminForm(w, config, err.Error())
		return
	}

	g.finishAdminAction(w, r, "/", "gateway")
}

func routeFromForm(r *http.Request) (Route, error) {
	r.ParseForm()
	route := Route{
		Name:        strings.TrimSpace(r.FormValue("route_name")),
		PathPrefix:  normalizePathPrefix(strings.TrimSpace(r.FormValue("route_path_prefix"))),
		Target:      strings.TrimSpace(r.FormValue("route_target")),
		PolicyName:  strings.TrimSpace(r.FormValue("route_policy_name")),
		StripPrefix: r.FormValue("route_strip_prefix") == "true",
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
