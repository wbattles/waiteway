package main

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// sessionMaxAge is how long a login cookie is valid before it expires.
const sessionMaxAge = 30 * 24 * time.Hour

// maxAPIKeysPerUser keeps each account's key list small and manageable.
const maxAPIKeysPerUser = 10

// ErrUsernameTaken is returned when CreateUser hits the unique-username index.
var ErrUsernameTaken = errors.New("username already exists")

// ErrAPIKeyLimitReached is returned when a user already has too many keys.
var ErrAPIKeyLimitReached = errors.New("api key limit reached")

// EnsureFirstAdmin creates the first admin user if no users exist yet.
// It is a no-op once any user has been created.
func (s *Store) EnsureFirstAdmin(username, password string) error {
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	if strings.TrimSpace(username) == "" {
		username = "admin"
	}
	if password == "" {
		password = "change-me"
	}
	_, err := s.CreateUser(username, password, true)
	return err
}

func (s *Store) GetUserByUsername(username string) (User, error) {
	return s.getUserWhere("username = ?", username)
}

func (s *Store) GetUserByID(userID int) (User, error) {
	return s.getUserWhere("id = ?", userID)
}

func (s *Store) getUserWhere(where string, args ...any) (User, error) {
	row := s.db.QueryRow("SELECT id, username, password_hash, is_admin, created_at FROM users WHERE "+where+" LIMIT 1", args...)
	return scanUser(row)
}

func scanUser(scanner interface{ Scan(dest ...any) error }) (User, error) {
	var user User
	var isAdmin int
	var createdAt string
	if err := scanner.Scan(&user.ID, &user.Username, &user.PasswordHash, &isAdmin, &createdAt); err != nil {
		return User{}, err
	}
	user.IsAdmin = isAdmin == 1
	user.CreatedAt = parseDBTime(createdAt)
	return user, nil
}

func parseDBTime(value string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query("SELECT id, username, password_hash, is_admin, created_at FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Store) CreateUser(username, password string, isAdmin bool) (User, error) {
	var err error
	username, err = normalizeUsername(username)
	if err != nil {
		return User{}, err
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(
		"INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
		username, passwordHash, boolToInt(isAdmin), createdAt,
	)
	if err != nil {
		if isUniqueConstraintError(err) {
			return User{}, ErrUsernameTaken
		}
		return User{}, err
	}
	userID, _ := res.LastInsertId()
	return s.GetUserByID(int(userID))
}

func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func (s *Store) UpdateUserPassword(userID int, newPassword string) error {
	passwordHash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", passwordHash, userID)
	return err
}

func (s *Store) DeleteSessionsForUser(userID int) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE user_id = ?", userID)
	return err
}

func (s *Store) DeleteUser(userID int) error {
	_, err := s.db.Exec("DELETE FROM users WHERE id = ?", userID)
	return err
}

func (s *Store) AddUserSession(id string, userID int) error {
	_, err := s.db.Exec(
		"INSERT INTO sessions (id, created_at, user_id) VALUES (?, ?, ?)",
		id, time.Now().UTC().Format(time.RFC3339Nano), userID,
	)
	return err
}

func (s *Store) UserBySessionID(id string) (User, error) {
	cutoff := time.Now().UTC().Add(-sessionMaxAge).Format(time.RFC3339Nano)
	return s.getUserWhere(
		"id = (SELECT user_id FROM sessions WHERE id = ? AND created_at > ? LIMIT 1)",
		id, cutoff,
	)
}

// PurgeExpiredSessions removes sessions older than sessionMaxAge.
func (s *Store) PurgeExpiredSessions() error {
	cutoff := time.Now().UTC().Add(-sessionMaxAge).Format(time.RFC3339Nano)
	_, err := s.db.Exec("DELETE FROM sessions WHERE created_at <= ?", cutoff)
	return err
}

func (s *Store) FindUserByAPIKey(rawKey string) (User, error) {
	trimmed := strings.TrimSpace(rawKey)
	if trimmed == "" {
		return User{}, sql.ErrNoRows
	}
	hashed := hashAPIKey(trimmed)
	return s.getUserWhere("id = (SELECT user_id FROM api_keys WHERE key = ? LIMIT 1)", hashed)
}

func (s *Store) ListAPIKeysByUser(userID int) ([]APIKey, error) {
	rows, err := s.db.Query("SELECT id, key, key_prefix, user_id, created_at FROM api_keys WHERE user_id = ? ORDER BY id DESC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := []APIKey{}
	for rows.Next() {
		var key APIKey
		var createdAt string
		if err := rows.Scan(&key.ID, &key.Key, &key.KeyPrefix, &key.UserID, &createdAt); err != nil {
			return nil, err
		}
		key.CreatedAt = parseDBTime(createdAt)
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) CreateAPIKey(userID int, rawKey string) (APIKey, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return APIKey{}, err
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRow("SELECT COUNT(*) FROM api_keys WHERE user_id = ?", userID).Scan(&count); err != nil {
		return APIKey{}, err
	}
	if count >= maxAPIKeysPerUser {
		return APIKey{}, ErrAPIKeyLimitReached
	}

	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	hashed := hashAPIKey(rawKey)
	prefix := apiKeyPrefix(rawKey)
	res, err := tx.Exec("INSERT INTO api_keys (key, key_prefix, user_id, created_at) VALUES (?, ?, ?, ?)", hashed, prefix, userID, createdAt)
	if err != nil {
		return APIKey{}, err
	}
	if err := tx.Commit(); err != nil {
		return APIKey{}, err
	}
	keyID, _ := res.LastInsertId()
	return s.GetAPIKeyByID(int(keyID))
}

func (s *Store) GetAPIKeyByID(keyID int) (APIKey, error) {
	var key APIKey
	var createdAt string
	err := s.db.QueryRow("SELECT id, key, key_prefix, user_id, created_at FROM api_keys WHERE id = ? LIMIT 1", keyID).Scan(&key.ID, &key.Key, &key.KeyPrefix, &key.UserID, &createdAt)
	if err != nil {
		return APIKey{}, err
	}
	key.CreatedAt = parseDBTime(createdAt)
	return key, nil
}

func (s *Store) DeleteAPIKeyForUser(keyID, userID int) error {
	_, err := s.db.Exec("DELETE FROM api_keys WHERE id = ? AND user_id = ?", keyID, userID)
	return err
}
