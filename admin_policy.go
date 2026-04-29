package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
)

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

func policyFromForm(r *http.Request) (Policy, error) {
	if err := r.ParseForm(); err != nil {
		return Policy{}, err
	}
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
		RequireUserAuth:            r.FormValue("policy_require_user_auth") == "true",
		ScrubPII:                   false,
		ScrubPIIRequestBody:        false,
		ScrubPIIQueryParams:        false,
		ScrubPIIHeaders:            r.FormValue("policy_scrub_pii_headers") == "true",
		ScrubPIIEmail:              r.FormValue("policy_scrub_pii_email") == "true",
		ScrubPIIPhone:              r.FormValue("policy_scrub_pii_phone") == "true",
		ScrubPIISSN:                r.FormValue("policy_scrub_pii_ssn") == "true",
		ScrubPIICreditCard:         r.FormValue("policy_scrub_pii_credit_card") == "true",
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
	hasPIITypes := policy.ScrubPIIEmail || policy.ScrubPIIPhone || policy.ScrubPIISSN || policy.ScrubPIICreditCard
	policy.ScrubPIIRequestBody = hasPIITypes
	policy.ScrubPIIQueryParams = hasPIITypes
	policy.ScrubPII = hasPIITypes || policy.ScrubPIIHeaders

	if policy.Name == "" {
		return Policy{}, errors.New("policy name is required")
	}
	if policy.ScrubPII {
		if !policy.ScrubPIIEmail && !policy.ScrubPIIPhone && !policy.ScrubPIISSN && !policy.ScrubPIICreditCard && !policy.ScrubPIIHeaders {
			return Policy{}, errors.New("pii scrubber needs at least one pii type or header scrub")
		}
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
