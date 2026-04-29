package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const piiRedactedValue = "[redacted]"

var (
	emailPIIPattern = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)
	phonePIIPattern = regexp.MustCompile(`(?i)(?:\+?1[\s\-.]?)?(?:\(?\d{3}\)?[\s\-.]?)\d{3}[\s\-.]?\d{4}`)
	ssnPIIPattern   = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	cardPIIPattern  = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
)

var piiRequestHeaders = []string{
	"Authorization",
	"Cookie",
	"Proxy-Authorization",
	"X-API-Key",
}

func shouldReadBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

func (g *Gateway) authorizePolicy(route compiledRoute, r *http.Request, apiKey string, requestUser User, hasRequestUser bool, clientIP netip.Addr, hasClientIP bool, now time.Time) (bool, int, string) {
	if route.policy == nil {
		return true, http.StatusOK, ""
	}

	if route.policy.circuitBreaker != nil && !route.policy.circuitBreaker.Allow(now) {
		return false, http.StatusServiceUnavailable, "circuit open"
	}

	if len(route.policy.allowedMethods) > 0 {
		if _, ok := route.policy.allowedMethods[r.Method]; !ok {
			return false, http.StatusMethodNotAllowed, "method not allowed"
		}
	}

	needsClientIP := len(route.policy.ipAllowList) > 0 || len(route.policy.ipBlockList) > 0 || route.policy.rateLimiter != nil
	if needsClientIP {
		if !hasClientIP {
			return false, http.StatusForbidden, "forbidden"
		}

		if route.policy.blocksIP(clientIP) {
			return false, http.StatusForbidden, "forbidden"
		}
		if !route.policy.allowsIP(clientIP) {
			return false, http.StatusForbidden, "forbidden"
		}
	}

	if err := processRequestBody(route.policy, r); err != nil {
		if err == errPayloadTooLarge {
			return false, http.StatusRequestEntityTooLarge, "payload too large"
		}
		return false, http.StatusBadRequest, "bad request"
	}

	if route.policy.RequireAPIKey && !g.authorizePolicyAPIKey(route, route.policy, apiKey, requestUser, hasRequestUser) {
		return false, http.StatusUnauthorized, "unauthorized"
	}

	if route.policy.RequireUserAuth {
		username, password, ok := requestBasicAuth(r)
		if !ok || !g.authorizePolicyUserAuth(route.policy, username, password) {
			return false, http.StatusUnauthorized, "unauthorized"
		}
	}

	if route.policy.rateLimiter != nil && !route.policy.rateLimiter.Allow(clientIP.String(), now) {
		return false, http.StatusTooManyRequests, "rate limit exceeded"
	}

	applyRequestHeaders(route.policy, r)
	scrubRequestPII(route.policy, r)

	return true, http.StatusOK, ""
}

func (g *Gateway) authorizePolicyAPIKey(route compiledRoute, policy *compiledPolicy, key string, requestUser User, hasRequestUser bool) bool {
	return hasRequestUser
}

func (g *Gateway) authorizePolicyUserAuth(policy *compiledPolicy, username, password string) bool {
	user, err := g.store.GetUserByUsername(strings.TrimSpace(username))
	if err != nil || !checkPassword(password, user.PasswordHash) {
		return false
	}
	return true
}

func (g *Gateway) authorizeRouteAPIKey(route compiledRoute, key string, _ User, hasRequestUser bool) bool {
	if len(route.apiKeys) == 0 {
		return hasRequestUser
	}
	_, ok := route.apiKeys[key]
	return ok
}

func (g *Gateway) cachedPolicyResponse(route compiledRoute, key string, now time.Time) (cachedResponse, bool) {
	if route.policy == nil || route.policy.cache == nil || key == "" || now.IsZero() {
		return cachedResponse{}, false
	}
	return route.policy.cache.Get(key, now)
}

func (g *Gateway) storeCachedPolicyResponse(route compiledRoute, key string, now time.Time, recorder *cacheRecorder) {
	if route.policy == nil || route.policy.cache == nil || key == "" || now.IsZero() || recorder.status != http.StatusOK {
		return
	}
	route.policy.cache.Set(key, recorder.status, recorder.header, recorder.body.Bytes(), now)
}

func applyRequestHeaders(policy *compiledPolicy, r *http.Request) {
	for key := range policy.removeRequestHeaders {
		r.Header.Del(key)
	}
	for key, value := range policy.addRequestHeaders {
		r.Header.Set(key, value)
	}
}

func policyHasPIIScrubber(policy *compiledPolicy) bool {
	if policy == nil || !policy.ScrubPII {
		return false
	}
	return policy.ScrubPIIRequestBody || policy.ScrubPIIQueryParams || policy.ScrubPIIHeaders
}

func scrubRequestPII(policy *compiledPolicy, r *http.Request) {
	if !policyHasPIIScrubber(policy) {
		return
	}
	if policy.ScrubPIIQueryParams {
		scrubQueryParams(policy, r.URL)
	}
	if policy.ScrubPIIHeaders {
		for _, key := range piiRequestHeaders {
			r.Header.Del(key)
		}
	}
}

func scrubRequestBodyPII(policy *compiledPolicy, r *http.Request, body []byte) []byte {
	if !policyHasPIIScrubber(policy) || !policy.ScrubPIIRequestBody {
		return body
	}
	if len(body) == 0 || !utf8.Valid(body) || !shouldScrubBodyContentType(r.Header.Get("Content-Type")) {
		return body
	}
	return []byte(scrubPIIText(policy, string(body)))
}

func scrubQueryParams(policy *compiledPolicy, requestURL *url.URL) {
	if requestURL == nil {
		return
	}
	query := requestURL.Query()
	changed := false
	for key, values := range query {
		for i, value := range values {
			scrubbed := scrubPIIText(policy, value)
			if scrubbed != value {
				values[i] = scrubbed
				changed = true
			}
		}
		query[key] = values
	}
	if changed {
		requestURL.RawQuery = query.Encode()
	}
}

func scrubPIIText(policy *compiledPolicy, value string) string {
	if policy == nil || !policy.ScrubPII {
		return value
	}
	if policy.ScrubPIIEmail {
		value = emailPIIPattern.ReplaceAllString(value, piiRedactedValue)
	}
	if policy.ScrubPIIPhone {
		value = phonePIIPattern.ReplaceAllString(value, piiRedactedValue)
	}
	if policy.ScrubPIISSN {
		value = ssnPIIPattern.ReplaceAllString(value, piiRedactedValue)
	}
	if policy.ScrubPIICreditCard {
		value = cardPIIPattern.ReplaceAllStringFunc(value, func(match string) string {
			if looksLikeCreditCard(match) {
				return piiRedactedValue
			}
			return match
		})
	}
	return value
}

func shouldScrubBodyContentType(contentType string) bool {
	contentType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if contentType == "" {
		return true
	}
	if strings.HasPrefix(contentType, "text/") {
		return true
	}
	switch contentType {
	case "application/json", "application/xml", "application/x-www-form-urlencoded", "application/graphql", "application/javascript":
		return true
	default:
		return false
	}
}

func looksLikeCreditCard(value string) bool {
	digits := make([]int, 0, len(value))
	for _, ch := range value {
		if ch >= '0' && ch <= '9' {
			digits = append(digits, int(ch-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		digit := digits[i]
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
	}
	return sum%10 == 0
}

var errPayloadTooLarge = fmt.Errorf("payload too large")

const defaultRequestBodyProcessLimit = int64(10 << 20)

func processRequestBody(policy *compiledPolicy, r *http.Request) error {
	if policy == nil || !shouldReadBody(r.Method) {
		return nil
	}
	if policy.MaxPayloadBytes > 0 && r.ContentLength > policy.MaxPayloadBytes {
		return errPayloadTooLarge
	}
	if policy.MaxPayloadBytes <= 0 && policy.RequestTransformFind == "" && !policyHasPIIScrubber(policy) {
		return nil
	}

	limit := defaultRequestBodyProcessLimit + 1
	if policy.MaxPayloadBytes > 0 {
		limit = policy.MaxPayloadBytes + 1
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, limit))
	if err != nil {
		return err
	}
	if policy.MaxPayloadBytes <= 0 && int64(len(body)) > defaultRequestBodyProcessLimit {
		return errPayloadTooLarge
	}
	if policy.MaxPayloadBytes > 0 && int64(len(body)) > policy.MaxPayloadBytes {
		return errPayloadTooLarge
	}
	if policy.RequestTransformFind != "" {
		body = bytes.ReplaceAll(body, []byte(policy.RequestTransformFind), []byte(policy.RequestTransformReplace))
	}
	body = scrubRequestBodyPII(policy, r, body)
	setRequestBody(r, body)
	return nil
}

func setRequestBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	r.ContentLength = int64(len(body))
}

func applyResponsePolicy(policy *compiledPolicy, resp *http.Response) error {
	if policy == nil {
		return nil
	}

	for key := range policy.removeResponseHeaders {
		resp.Header.Del(key)
	}
	for key, value := range policy.addResponseHeaders {
		resp.Header.Set(key, value)
	}

	if len(policy.CORSAllowOrigins) > 0 {
		origin := "*"
		if len(policy.CORSAllowOrigins) == 1 {
			origin = policy.CORSAllowOrigins[0]
		}
		resp.Header.Set("Access-Control-Allow-Origin", origin)
		if len(policy.CORSAllowMethods) > 0 {
			resp.Header.Set("Access-Control-Allow-Methods", strings.Join(policy.CORSAllowMethods, ", "))
		}
		if len(policy.CORSAllowHeaders) > 0 {
			resp.Header.Set("Access-Control-Allow-Headers", strings.Join(policy.CORSAllowHeaders, ", "))
		}
	}

	needsBody := policy.MaxResponseBytes > 0 || policy.ResponseTransformFind != ""
	if !needsBody || resp.Body == nil {
		return nil
	}

	limit := int64(0)
	if policy.MaxResponseBytes > 0 {
		limit = policy.MaxResponseBytes + 1
	} else {
		limit = 10 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if policy.MaxResponseBytes > 0 && int64(len(body)) > policy.MaxResponseBytes {
		return fmt.Errorf("response too large")
	}
	if policy.ResponseTransformFind != "" {
		body = []byte(strings.ReplaceAll(string(body), policy.ResponseTransformFind, policy.ResponseTransformReplace))
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return nil
}

func applyCORSPreflight(policy *compiledPolicy, w http.ResponseWriter, r *http.Request) bool {
	if policy == nil || len(policy.CORSAllowOrigins) == 0 {
		return false
	}
	if r.Method != http.MethodOptions || r.Header.Get("Origin") == "" {
		return false
	}
	origin := "*"
	if len(policy.CORSAllowOrigins) == 1 {
		origin = policy.CORSAllowOrigins[0]
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	if len(policy.CORSAllowMethods) > 0 {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(policy.CORSAllowMethods, ", "))
	}
	if len(policy.CORSAllowHeaders) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(policy.CORSAllowHeaders, ", "))
	}
	w.WriteHeader(http.StatusNoContent)
	return true
}

func requestWithPolicyContext(r *http.Request, policy *compiledPolicy) (*http.Request, context.CancelFunc) {
	if policy == nil || policy.requestTimeout <= 0 {
		return r, func() {}
	}
	ctx, cancel := context.WithTimeout(r.Context(), policy.requestTimeout)
	return r.WithContext(ctx), cancel
}
