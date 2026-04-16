package main

import (
	"database/sql"
	"fmt"
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
	require_api_key          INTEGER NOT NULL DEFAULT 0,
	api_keys                 TEXT NOT NULL DEFAULT '',
	rate_limit_requests      INTEGER NOT NULL DEFAULT 0,
	rate_limit_window_seconds INTEGER NOT NULL DEFAULT 0,
	max_payload_bytes        INTEGER NOT NULL DEFAULT 0,
	cache_ttl_seconds        INTEGER NOT NULL DEFAULT 0,
	ip_allow_list            TEXT NOT NULL DEFAULT '',
	ip_block_list            TEXT NOT NULL DEFAULT '',
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

CREATE TABLE IF NOT EXISTS sessions (
	id         TEXT PRIMARY KEY,
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
	if _, err := db.Exec("ALTER TABLE routes ADD COLUMN policy_name TEXT NOT NULL DEFAULT ''"); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
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

func (s *Store) SaveSettings(username, password string, logLimit int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, kv := range [][2]string{
		{"admin_username", username},
		{"admin_password", password},
		{"log_limit", fmt.Sprintf("%d", logLimit)},
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

		keys, err := s.listRouteAPIKeys(id)
		if err != nil {
			return nil, err
		}
		r.APIKeys = keys
		routes = append(routes, r)
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

func (s *Store) AddRoute(r Route) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var maxPos int
	tx.QueryRow("SELECT COALESCE(MAX(position), 0) FROM routes").Scan(&maxPos)

	reqKey := 0
	if r.RequireAPIKey {
		reqKey = 1
	}
	strip := 0
	if r.StripPrefix {
		strip = 1
	}

	res, err := tx.Exec(
		"INSERT INTO routes (name, path_prefix, target, policy_name, require_api_key, strip_prefix, position) VALUES (?, ?, ?, ?, ?, ?, ?)",
		r.Name, r.PathPrefix, r.Target, r.PolicyName, reqKey, strip, maxPos+1,
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
	id, err := s.getRouteID(index)
	if err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	reqKey := 0
	if r.RequireAPIKey {
		reqKey = 1
	}
	strip := 0
	if r.StripPrefix {
		strip = 1
	}

	if _, err := tx.Exec(
		"UPDATE routes SET name = ?, path_prefix = ?, target = ?, policy_name = ?, require_api_key = ?, strip_prefix = ? WHERE id = ?",
		r.Name, r.PathPrefix, r.Target, r.PolicyName, reqKey, strip, id,
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

func (s *Store) listRouteAPIKeys(routeID int) ([]string, error) {
	rows, err := s.db.Query("SELECT key FROM route_api_keys WHERE route_id = ?", routeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
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
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = ?", id).Scan(&count)
	return count > 0
}

func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE id = ?", id)
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
		SELECT name, require_api_key, api_keys, rate_limit_requests, rate_limit_window_seconds, max_payload_bytes, cache_ttl_seconds, ip_allow_list, ip_block_list
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
		var allowList string
		var blockList string
		if err := rows.Scan(
			&policy.Name,
			&requireAPIKey,
			&apiKeys,
			&policy.RateLimitRequests,
			&policy.RateLimitWindowSeconds,
			&policy.MaxPayloadBytes,
			&policy.CacheTTLSeconds,
			&allowList,
			&blockList,
		); err != nil {
			return nil, err
		}
		policy.RequireAPIKey = requireAPIKey == 1
		policy.APIKeys = splitLines(apiKeys)
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

func (s *Store) AddPolicy(policy Policy) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var maxPos int
	tx.QueryRow("SELECT COALESCE(MAX(position), 0) FROM policies").Scan(&maxPos)

	requireAPIKey := 0
	if policy.RequireAPIKey {
		requireAPIKey = 1
	}

	_, err = tx.Exec(
		`INSERT INTO policies (name, require_api_key, api_keys, rate_limit_requests, rate_limit_window_seconds, max_payload_bytes, cache_ttl_seconds, ip_allow_list, ip_block_list, position)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		policy.Name,
		requireAPIKey,
		joinLines(policy.APIKeys),
		policy.RateLimitRequests,
		policy.RateLimitWindowSeconds,
		policy.MaxPayloadBytes,
		policy.CacheTTLSeconds,
		joinLines(policy.IPAllowList),
		joinLines(policy.IPBlockList),
		maxPos+1,
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) UpdatePolicy(index int, policy Policy) error {
	id, err := s.getPolicyID(index)
	if err != nil {
		return err
	}

	requireAPIKey := 0
	if policy.RequireAPIKey {
		requireAPIKey = 1
	}

	_, err = s.db.Exec(
		`UPDATE policies SET name = ?, require_api_key = ?, api_keys = ?, rate_limit_requests = ?, rate_limit_window_seconds = ?, max_payload_bytes = ?, cache_ttl_seconds = ?, ip_allow_list = ?, ip_block_list = ? WHERE id = ?`,
		policy.Name,
		requireAPIKey,
		joinLines(policy.APIKeys),
		policy.RateLimitRequests,
		policy.RateLimitWindowSeconds,
		policy.MaxPayloadBytes,
		policy.CacheTTLSeconds,
		joinLines(policy.IPAllowList),
		joinLines(policy.IPBlockList),
		id,
	)
	return err
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
