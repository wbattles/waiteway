package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
	id                       INTEGER PRIMARY KEY AUTOINCREMENT,
	name                     TEXT NOT NULL UNIQUE,
	request_timeout_seconds  INTEGER NOT NULL DEFAULT 0,
	retry_count              INTEGER NOT NULL DEFAULT 0,
	require_api_key          INTEGER NOT NULL DEFAULT 0,
	api_keys                 TEXT NOT NULL DEFAULT '',
	require_user_auth        INTEGER NOT NULL DEFAULT 0,
	rate_limit_requests      INTEGER NOT NULL DEFAULT 0,
	rate_limit_window_seconds INTEGER NOT NULL DEFAULT 0,
	allowed_methods          TEXT NOT NULL DEFAULT '',
	rewrite_path_prefix      TEXT NOT NULL DEFAULT '',
	add_request_headers      TEXT NOT NULL DEFAULT '',
	remove_request_headers   TEXT NOT NULL DEFAULT '',
	max_payload_bytes        INTEGER NOT NULL DEFAULT 0,
	request_transform_find   TEXT NOT NULL DEFAULT '',
	request_transform_replace TEXT NOT NULL DEFAULT '',
	cache_ttl_seconds        INTEGER NOT NULL DEFAULT 0,
	add_response_headers     TEXT NOT NULL DEFAULT '',
	remove_response_headers  TEXT NOT NULL DEFAULT '',
	response_transform_find  TEXT NOT NULL DEFAULT '',
	response_transform_replace TEXT NOT NULL DEFAULT '',
	max_response_bytes       INTEGER NOT NULL DEFAULT 0,
	cors_allow_origins       TEXT NOT NULL DEFAULT '',
	cors_allow_methods       TEXT NOT NULL DEFAULT '',
	cors_allow_headers       TEXT NOT NULL DEFAULT '',
	ip_allow_list            TEXT NOT NULL DEFAULT '',
	ip_block_list            TEXT NOT NULL DEFAULT '',
	circuit_breaker_failures INTEGER NOT NULL DEFAULT 0,
	circuit_breaker_reset_seconds INTEGER NOT NULL DEFAULT 0,
	position                 INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS routes (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	name            TEXT NOT NULL,
	path_prefix     TEXT NOT NULL,
	target          TEXT NOT NULL,
	policy_name     TEXT NOT NULL DEFAULT '',
	require_api_key INTEGER NOT NULL DEFAULT 0,
	strip_prefix    INTEGER NOT NULL DEFAULT 0,
	position        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS route_api_keys (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	route_id INTEGER NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
	key      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS request_logs (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	time        TEXT NOT NULL,
	method      TEXT NOT NULL,
	path        TEXT NOT NULL,
	status      INTEGER NOT NULL,
	route       TEXT NOT NULL DEFAULT '',
	remote_addr TEXT NOT NULL DEFAULT '',
	duration_ns INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	is_admin      INTEGER NOT NULL DEFAULT 0,
	created_at    TEXT NOT NULL
	);

CREATE TABLE IF NOT EXISTS sessions (
	id         TEXT PRIMARY KEY,
	created_at TEXT NOT NULL,
	user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE
	);

CREATE TABLE IF NOT EXISTS api_keys (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	key        TEXT NOT NULL UNIQUE,
	key_prefix TEXT NOT NULL DEFAULT '',
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at TEXT NOT NULL
	);
`

func openStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	if err := runMigrations(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}

	return &Store{db: db}, nil
}

func runMigrations(db *sql.DB) error {
	columns := []string{
		"ALTER TABLE routes ADD COLUMN policy_name TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE sessions ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE",
		"ALTER TABLE api_keys ADD COLUMN key_prefix TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policies ADD COLUMN require_user_auth INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE policies ADD COLUMN request_timeout_seconds INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE policies ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE policies ADD COLUMN basic_auth_username TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policies ADD COLUMN basic_auth_password TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policies ADD COLUMN allowed_methods TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policies ADD COLUMN rewrite_path_prefix TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policies ADD COLUMN add_request_headers TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policies ADD COLUMN remove_request_headers TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policies ADD COLUMN request_transform_find TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policies ADD COLUMN request_transform_replace TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policies ADD COLUMN add_response_headers TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policies ADD COLUMN remove_response_headers TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policies ADD COLUMN response_transform_find TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policies ADD COLUMN response_transform_replace TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policies ADD COLUMN max_response_bytes INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE policies ADD COLUMN cors_allow_origins TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policies ADD COLUMN cors_allow_methods TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policies ADD COLUMN cors_allow_headers TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE policies ADD COLUMN circuit_breaker_failures INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE policies ADD COLUMN circuit_breaker_reset_seconds INTEGER NOT NULL DEFAULT 0",
	}
	for _, stmt := range columns {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
	}

	indexes := []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_routes_path_prefix ON routes(path_prefix)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_key ON api_keys(key)",
		"CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix)",
	}
	for _, stmt := range indexes {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}

	return nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// --- settings ---

func (s *Store) GetSetting(key, fallback string) string {
	var value string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if err != nil {
		return fallback
	}
	return value
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(
		"INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value,
	)
	return err
}

func (s *Store) LoadConfig() (Config, error) {
	config := Config{
		LogLimit: 100,
		Admin: AdminConfig{
			Username: s.GetSetting("admin_username", "admin"),
			Password: s.GetSetting("admin_password", "change-me"),
		},
		LoadBalancer: LoadBalancerConfig{
			Mode:           s.GetSetting("load_balancer_mode", "direct"),
			ClientIPHeader: s.GetSetting("load_balancer_client_ip_header", ""),
			StripPort:      s.GetSetting("load_balancer_strip_port", "true") != "false",
		},
	}

	if v := s.GetSetting("log_limit", "100"); v != "" {
		fmt.Sscanf(v, "%d", &config.LogLimit)
	}

	routes, err := s.ListRoutes()
	if err != nil {
		return Config{}, err
	}
	config.Routes = routes

	policies, err := s.ListPolicies()
	if err != nil {
		return Config{}, err
	}
	config.Policies = policies

	return config, nil
}

func (s *Store) SaveSettings(config Config) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, kv := range [][2]string{
		{"admin_username", config.Admin.Username},
		{"admin_password", config.Admin.Password},
		{"log_limit", fmt.Sprintf("%d", config.LogLimit)},
		{"load_balancer_mode", config.LoadBalancer.Mode},
		{"load_balancer_client_ip_header", config.LoadBalancer.ClientIPHeader},
		{"load_balancer_strip_port", fmt.Sprintf("%t", config.LoadBalancer.StripPort)},
	} {
		if _, err := tx.Exec(
			"INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
			kv[0], kv[1],
		); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// --- routes ---

func (s *Store) ListRoutes() ([]Route, error) {
	rows, err := s.db.Query("SELECT id, name, path_prefix, target, policy_name, require_api_key, strip_prefix FROM routes ORDER BY position, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keysByRouteID, err := s.listAllRouteAPIKeys()
	if err != nil {
		return nil, err
	}

	var routes []Route
	for rows.Next() {
		var r Route
		var id int
		var reqKey, strip int
		if err := rows.Scan(&id, &r.Name, &r.PathPrefix, &r.Target, &r.PolicyName, &reqKey, &strip); err != nil {
			return nil, err
		}
		r.RequireAPIKey = reqKey == 1
		r.StripPrefix = strip == 1
		r.APIKeys = keysByRouteID[id]
		routes = append(routes, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return routes, nil
}

func (s *Store) getRouteID(index int) (int, error) {
	var id int
	err := s.db.QueryRow("SELECT id FROM routes ORDER BY position, id LIMIT 1 OFFSET ?", index).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("route index %d not found", index)
	}
	return id, nil
}

func duplicateRoutePathPrefixError(prefix string) error {
	return fmt.Errorf("route path prefix %q is already in use", prefix)
}

func routePathPrefixExistsTx(tx *sql.Tx, prefix string, excludeID int) (bool, error) {
	query := "SELECT COUNT(*) FROM routes WHERE path_prefix = ?"
	args := []any{prefix}
	if excludeID > 0 {
		query += " AND id != ?"
		args = append(args, excludeID)
	}

	var count int
	if err := tx.QueryRow(query, args...).Scan(&count); err != nil {
		return false, err
	}

	return count > 0, nil
}

func (s *Store) AddRoute(r Route) error {
	r.PathPrefix = normalizePathPrefix(r.PathPrefix)

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	exists, err := routePathPrefixExistsTx(tx, r.PathPrefix, 0)
	if err != nil {
		return err
	}
	if exists {
		return duplicateRoutePathPrefixError(r.PathPrefix)
	}

	var maxPos int
	tx.QueryRow("SELECT COALESCE(MAX(position), 0) FROM routes").Scan(&maxPos)

	res, err := tx.Exec(
		"INSERT INTO routes (name, path_prefix, target, policy_name, require_api_key, strip_prefix, position) VALUES (?, ?, ?, ?, ?, ?, ?)",
		r.Name, r.PathPrefix, r.Target, r.PolicyName, boolToInt(r.RequireAPIKey), boolToInt(r.StripPrefix), maxPos+1,
	)
	if err != nil {
		return err
	}

	routeID, _ := res.LastInsertId()
	for _, key := range r.APIKeys {
		if key == "" {
			continue
		}
		if _, err := tx.Exec("INSERT INTO route_api_keys (route_id, key) VALUES (?, ?)", routeID, key); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) UpdateRoute(index int, r Route) error {
	r.PathPrefix = normalizePathPrefix(r.PathPrefix)

	id, err := s.getRouteID(index)
	if err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	exists, err := routePathPrefixExistsTx(tx, r.PathPrefix, id)
	if err != nil {
		return err
	}
	if exists {
		return duplicateRoutePathPrefixError(r.PathPrefix)
	}

	if _, err := tx.Exec(
		"UPDATE routes SET name = ?, path_prefix = ?, target = ?, policy_name = ?, require_api_key = ?, strip_prefix = ? WHERE id = ?",
		r.Name, r.PathPrefix, r.Target, r.PolicyName, boolToInt(r.RequireAPIKey), boolToInt(r.StripPrefix), id,
	); err != nil {
		return err
	}

	if _, err := tx.Exec("DELETE FROM route_api_keys WHERE route_id = ?", id); err != nil {
		return err
	}
	for _, key := range r.APIKeys {
		if key == "" {
			continue
		}
		if _, err := tx.Exec("INSERT INTO route_api_keys (route_id, key) VALUES (?, ?)", id, key); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) DeleteRoute(index int) error {
	id, err := s.getRouteID(index)
	if err != nil {
		return err
	}

	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM routes").Scan(&count)
	if count <= 1 {
		return fmt.Errorf("config needs at least one route")
	}

	_, err = s.db.Exec("DELETE FROM routes WHERE id = ?", id)
	return err
}

func (s *Store) listAllRouteAPIKeys() (map[int][]string, error) {
	rows, err := s.db.Query("SELECT route_id, key FROM route_api_keys ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keysByRouteID := map[int][]string{}
	for rows.Next() {
		var routeID int
		var key string
		if err := rows.Scan(&routeID, &key); err != nil {
			return nil, err
		}
		keysByRouteID[routeID] = append(keysByRouteID[routeID], key)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return keysByRouteID, nil
}

// --- request logs ---

func (s *Store) AddLog(entry requestLog) error {
	_, err := s.db.Exec(
		"INSERT INTO request_logs (time, method, path, status, route, remote_addr, duration_ns) VALUES (?, ?, ?, ?, ?, ?, ?)",
		entry.Time.Format(time.RFC3339Nano), entry.Method, entry.Path, entry.Status, entry.Route, entry.RemoteAddr, int64(entry.Duration),
	)
	return err
}

func (s *Store) ListLogs(limit int) ([]requestLog, error) {
	rows, err := s.db.Query("SELECT time, method, path, status, route, remote_addr, duration_ns FROM request_logs ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []requestLog
	for rows.Next() {
		var entry requestLog
		var timeStr string
		var durationNS int64
		if err := rows.Scan(&timeStr, &entry.Method, &entry.Path, &entry.Status, &entry.Route, &entry.RemoteAddr, &durationNS); err != nil {
			return nil, err
		}
		entry.Time, _ = time.Parse(time.RFC3339Nano, timeStr)
		entry.Duration = time.Duration(durationNS)
		logs = append(logs, entry)
	}
	return logs, nil
}

func (s *Store) ClearLogs() error {
	_, err := s.db.Exec("DELETE FROM request_logs")
	return err
}

func (s *Store) TrimLogs(limit int) error {
	_, err := s.db.Exec(`
		DELETE FROM request_logs WHERE id NOT IN (
			SELECT id FROM request_logs ORDER BY id DESC LIMIT ?
		)
	`, limit)
	return err
}

// --- sessions ---

func (s *Store) AddSession(id string) error {
	_, err := s.db.Exec(
		"INSERT INTO sessions (id, created_at) VALUES (?, ?)",
		id, time.Now().Format(time.RFC3339),
	)
	return err
}

func (s *Store) HasSession(id string) bool {
	var exists int
	err := s.db.QueryRow("SELECT 1 FROM sessions WHERE id = ? LIMIT 1", id).Scan(&exists)
	if err == nil {
		return true
	}
	if err == sql.ErrNoRows {
		return false
	}
	log.Printf("waiteway failed to check session: %v", err)
	return false
}

func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE id = ?", id)
	return err
}

func (s *Store) DeleteAllSessions() error {
	_, err := s.db.Exec("DELETE FROM sessions")
	return err
}

func (s *Store) HasRoutes() bool {
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM routes").Scan(&count)
	return count > 0
}

func (s *Store) HasSettings() bool {
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM settings").Scan(&count)
	return count > 0
}

// --- policies ---

func (s *Store) ListPolicies() ([]Policy, error) {
	rows, err := s.db.Query(`
		SELECT name, request_timeout_seconds, retry_count, require_api_key, api_keys, require_user_auth, rate_limit_requests, rate_limit_window_seconds, allowed_methods, rewrite_path_prefix, add_request_headers, remove_request_headers, max_payload_bytes, request_transform_find, request_transform_replace, cache_ttl_seconds, add_response_headers, remove_response_headers, response_transform_find, response_transform_replace, max_response_bytes, cors_allow_origins, cors_allow_methods, cors_allow_headers, ip_allow_list, ip_block_list, circuit_breaker_failures, circuit_breaker_reset_seconds
		FROM policies
		ORDER BY position, id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []Policy
	for rows.Next() {
		var policy Policy
		var requireAPIKey int
		var apiKeys string
		var requireUserAuth int
		var allowedMethods string
		var addRequestHeaders string
		var removeRequestHeaders string
		var addResponseHeaders string
		var removeResponseHeaders string
		var corsAllowOrigins string
		var corsAllowMethods string
		var corsAllowHeaders string
		var allowList string
		var blockList string
		if err := rows.Scan(
			&policy.Name,
			&policy.RequestTimeoutSeconds,
			&policy.RetryCount,
			&requireAPIKey,
			&apiKeys,
			&requireUserAuth,
			&policy.RateLimitRequests,
			&policy.RateLimitWindowSeconds,
			&allowedMethods,
			&policy.RewritePathPrefix,
			&addRequestHeaders,
			&removeRequestHeaders,
			&policy.MaxPayloadBytes,
			&policy.RequestTransformFind,
			&policy.RequestTransformReplace,
			&policy.CacheTTLSeconds,
			&addResponseHeaders,
			&removeResponseHeaders,
			&policy.ResponseTransformFind,
			&policy.ResponseTransformReplace,
			&policy.MaxResponseBytes,
			&corsAllowOrigins,
			&corsAllowMethods,
			&corsAllowHeaders,
			&allowList,
			&blockList,
			&policy.CircuitBreakerFailures,
			&policy.CircuitBreakerResetSeconds,
		); err != nil {
			return nil, err
		}
		policy.RequireAPIKey = requireAPIKey == 1
		policy.APIKeys = splitLines(apiKeys)
		policy.RequireUserAuth = requireUserAuth == 1
		policy.AllowedMethods = splitLines(allowedMethods)
		policy.AddRequestHeaders = splitLines(addRequestHeaders)
		policy.RemoveRequestHeaders = splitLines(removeRequestHeaders)
		policy.AddResponseHeaders = splitLines(addResponseHeaders)
		policy.RemoveResponseHeaders = splitLines(removeResponseHeaders)
		policy.CORSAllowOrigins = splitLines(corsAllowOrigins)
		policy.CORSAllowMethods = splitLines(corsAllowMethods)
		policy.CORSAllowHeaders = splitLines(corsAllowHeaders)
		policy.IPAllowList = splitLines(allowList)
		policy.IPBlockList = splitLines(blockList)
		policies = append(policies, policy)
	}

	return policies, nil
}

func (s *Store) getPolicyID(index int) (int, error) {
	var id int
	err := s.db.QueryRow("SELECT id FROM policies ORDER BY position, id LIMIT 1 OFFSET ?", index).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("policy index %d not found", index)
	}
	return id, nil
}

func duplicatePolicyNameError(name string) error {
	return fmt.Errorf("policy name %q is already in use", name)
}

func policyNameExistsTx(tx *sql.Tx, name string, excludeID int) (bool, error) {
	query := "SELECT COUNT(*) FROM policies WHERE name = ?"
	args := []any{name}
	if excludeID > 0 {
		query += " AND id != ?"
		args = append(args, excludeID)
	}

	var count int
	if err := tx.QueryRow(query, args...).Scan(&count); err != nil {
		return false, err
	}

	return count > 0, nil
}

func (s *Store) AddPolicy(policy Policy) error {
	policy.RewritePathPrefix = normalizePathPrefix(policy.RewritePathPrefix)

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	exists, err := policyNameExistsTx(tx, policy.Name, 0)
	if err != nil {
		return err
	}
	if exists {
		return duplicatePolicyNameError(policy.Name)
	}

	var maxPos int
	tx.QueryRow("SELECT COALESCE(MAX(position), 0) FROM policies").Scan(&maxPos)

	_, err = tx.Exec(
		`INSERT INTO policies (name, request_timeout_seconds, retry_count, require_api_key, api_keys, require_user_auth, rate_limit_requests, rate_limit_window_seconds, allowed_methods, rewrite_path_prefix, add_request_headers, remove_request_headers, max_payload_bytes, request_transform_find, request_transform_replace, cache_ttl_seconds, add_response_headers, remove_response_headers, response_transform_find, response_transform_replace, max_response_bytes, cors_allow_origins, cors_allow_methods, cors_allow_headers, ip_allow_list, ip_block_list, circuit_breaker_failures, circuit_breaker_reset_seconds, position)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		policy.Name,
		policy.RequestTimeoutSeconds,
		policy.RetryCount,
		boolToInt(policy.RequireAPIKey),
		joinLines(policy.APIKeys),
		boolToInt(policy.RequireUserAuth),
		policy.RateLimitRequests,
		policy.RateLimitWindowSeconds,
		joinLines(policy.AllowedMethods),
		policy.RewritePathPrefix,
		joinLines(policy.AddRequestHeaders),
		joinLines(policy.RemoveRequestHeaders),
		policy.MaxPayloadBytes,
		policy.RequestTransformFind,
		policy.RequestTransformReplace,
		policy.CacheTTLSeconds,
		joinLines(policy.AddResponseHeaders),
		joinLines(policy.RemoveResponseHeaders),
		policy.ResponseTransformFind,
		policy.ResponseTransformReplace,
		policy.MaxResponseBytes,
		joinLines(policy.CORSAllowOrigins),
		joinLines(policy.CORSAllowMethods),
		joinLines(policy.CORSAllowHeaders),
		joinLines(policy.IPAllowList),
		joinLines(policy.IPBlockList),
		policy.CircuitBreakerFailures,
		policy.CircuitBreakerResetSeconds,
		maxPos+1,
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) UpdatePolicy(index int, policy Policy) error {
	policy.RewritePathPrefix = normalizePathPrefix(policy.RewritePathPrefix)

	id, err := s.getPolicyID(index)
	if err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	exists, err := policyNameExistsTx(tx, policy.Name, id)
	if err != nil {
		return err
	}
	if exists {
		return duplicatePolicyNameError(policy.Name)
	}

	var oldName string
	if err := tx.QueryRow("SELECT name FROM policies WHERE id = ?", id).Scan(&oldName); err != nil {
		return err
	}

	_, err = tx.Exec(
		`UPDATE policies SET name = ?, request_timeout_seconds = ?, retry_count = ?, require_api_key = ?, api_keys = ?, require_user_auth = ?, rate_limit_requests = ?, rate_limit_window_seconds = ?, allowed_methods = ?, rewrite_path_prefix = ?, add_request_headers = ?, remove_request_headers = ?, max_payload_bytes = ?, request_transform_find = ?, request_transform_replace = ?, cache_ttl_seconds = ?, add_response_headers = ?, remove_response_headers = ?, response_transform_find = ?, response_transform_replace = ?, max_response_bytes = ?, cors_allow_origins = ?, cors_allow_methods = ?, cors_allow_headers = ?, ip_allow_list = ?, ip_block_list = ?, circuit_breaker_failures = ?, circuit_breaker_reset_seconds = ? WHERE id = ?`,
		policy.Name,
		policy.RequestTimeoutSeconds,
		policy.RetryCount,
		boolToInt(policy.RequireAPIKey),
		joinLines(policy.APIKeys),
		boolToInt(policy.RequireUserAuth),
		policy.RateLimitRequests,
		policy.RateLimitWindowSeconds,
		joinLines(policy.AllowedMethods),
		policy.RewritePathPrefix,
		joinLines(policy.AddRequestHeaders),
		joinLines(policy.RemoveRequestHeaders),
		policy.MaxPayloadBytes,
		policy.RequestTransformFind,
		policy.RequestTransformReplace,
		policy.CacheTTLSeconds,
		joinLines(policy.AddResponseHeaders),
		joinLines(policy.RemoveResponseHeaders),
		policy.ResponseTransformFind,
		policy.ResponseTransformReplace,
		policy.MaxResponseBytes,
		joinLines(policy.CORSAllowOrigins),
		joinLines(policy.CORSAllowMethods),
		joinLines(policy.CORSAllowHeaders),
		joinLines(policy.IPAllowList),
		joinLines(policy.IPBlockList),
		policy.CircuitBreakerFailures,
		policy.CircuitBreakerResetSeconds,
		id,
	)
	if err != nil {
		return err
	}

	if oldName != policy.Name {
		if _, err := tx.Exec("UPDATE routes SET policy_name = ? WHERE policy_name = ?", policy.Name, oldName); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) DeletePolicy(index int) error {
	id, err := s.getPolicyID(index)
	if err != nil {
		return err
	}

	var name string
	if err := s.db.QueryRow("SELECT name FROM policies WHERE id = ?", id).Scan(&name); err != nil {
		return err
	}

	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM routes WHERE policy_name = ?", name).Scan(&count)
	if count > 0 {
		return fmt.Errorf("policy is attached to %d route(s)", count)
	}

	_, err = s.db.Exec("DELETE FROM policies WHERE id = ?", id)
	return err
}

func joinLines(items []string) string {
	return strings.Join(items, "\n")
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
