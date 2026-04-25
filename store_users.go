package main

import (
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"
)

func (s *Store) EnsureLegacyAdmin(username, password string) error {
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
	username = strings.TrimSpace(username)
	if username == "" {
		return User{}, fmt.Errorf("username is required")
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
		return User{}, err
	}
	userID, _ := res.LastInsertId()
	return s.GetUserByID(int(userID))
}

func (s *Store) UpdateUserPassword(userID int, newPassword string) error {
	passwordHash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", passwordHash, userID)
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
	return s.getUserWhere("id = (SELECT user_id FROM sessions WHERE id = ? LIMIT 1)", id)
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
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	hashed := hashAPIKey(rawKey)
	prefix := apiKeyPrefix(rawKey)
	res, err := s.db.Exec("INSERT INTO api_keys (key, key_prefix, user_id, created_at) VALUES (?, ?, ?, ?)", hashed, prefix, userID, createdAt)
	if err != nil {
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

func (s *Store) ListTeamsForUser(user User) ([]Team, error) {
	query := `
		SELECT t.id, t.name, t.acronym, t.created_at, t.created_by_id,
			(SELECT COUNT(*) FROM team_users tu WHERE tu.team_id = t.id)
		FROM teams t
	`
	args := []any{}
	if !user.IsAdmin {
		query += " WHERE t.id IN (SELECT team_id FROM team_users WHERE user_id = ?)"
		args = append(args, user.ID)
	}
	query += " ORDER BY t.name"
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	teams := []Team{}
	for rows.Next() {
		var team Team
		var createdAt string
		if err := rows.Scan(&team.ID, &team.Name, &team.Acronym, &createdAt, &team.CreatedByID, &team.UserCount); err != nil {
			return nil, err
		}
		team.CreatedAt = parseDBTime(createdAt)
		teams = append(teams, team)
	}
	return teams, rows.Err()
}

func (s *Store) GetTeam(teamID int) (Team, error) {
	var team Team
	var createdAt string
	err := s.db.QueryRow(
		"SELECT id, name, acronym, created_at, created_by_id FROM teams WHERE id = ? LIMIT 1",
		teamID,
	).Scan(&team.ID, &team.Name, &team.Acronym, &createdAt, &team.CreatedByID)
	if err != nil {
		return Team{}, err
	}
	team.CreatedAt = parseDBTime(createdAt)
	users, err := s.ListTeamUsers(teamID)
	if err != nil {
		return Team{}, err
	}
	team.Users = users
	team.UserCount = len(users)
	team.UserIDs = make([]int, 0, len(users))
	for _, user := range users {
		team.UserIDs = append(team.UserIDs, user.ID)
	}
	return team, nil
}

func (s *Store) ListTeamUsers(teamID int) ([]User, error) {
	rows, err := s.db.Query(`
		SELECT u.id, u.username, u.password_hash, u.is_admin, u.created_at
		FROM users u
		JOIN team_users tu ON tu.user_id = u.id
		WHERE tu.team_id = ?
		ORDER BY u.username
	`, teamID)
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

func (s *Store) CreateTeam(name, acronym string, createdByID int, userIDs []int) (Team, error) {
	name = strings.TrimSpace(name)
	acronym = strings.ToUpper(strings.TrimSpace(acronym))
	if name == "" {
		return Team{}, fmt.Errorf("team name is required")
	}
	if len(acronym) != 3 {
		return Team{}, fmt.Errorf("team code must be exactly 3 characters")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return Team{}, err
	}
	defer tx.Rollback()

	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.Exec(
		"INSERT INTO teams (name, acronym, created_at, created_by_id) VALUES (?, ?, ?, ?)",
		name, acronym, createdAt, createdByID,
	)
	if err != nil {
		return Team{}, err
	}
	teamID64, _ := res.LastInsertId()
	teamID := int(teamID64)
	if err := saveTeamUsersTx(tx, teamID, createdByID, userIDs); err != nil {
		return Team{}, err
	}
	if err := tx.Commit(); err != nil {
		return Team{}, err
	}
	return s.GetTeam(teamID)
}

func (s *Store) UpdateTeam(teamID int, name, acronym *string, userIDs []int, replaceUsers bool, actorID int) (Team, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Team{}, err
	}
	defer tx.Rollback()

	if name != nil {
		value := strings.TrimSpace(*name)
		if value == "" {
			return Team{}, fmt.Errorf("team name is required")
		}
		if _, err := tx.Exec("UPDATE teams SET name = ? WHERE id = ?", value, teamID); err != nil {
			return Team{}, err
		}
	}
	if acronym != nil {
		value := strings.ToUpper(strings.TrimSpace(*acronym))
		if len(value) != 3 {
			return Team{}, fmt.Errorf("team code must be exactly 3 characters")
		}
		if _, err := tx.Exec("UPDATE teams SET acronym = ? WHERE id = ?", value, teamID); err != nil {
			return Team{}, err
		}
	}
	if replaceUsers {
		if err := saveTeamUsersTx(tx, teamID, actorID, userIDs); err != nil {
			return Team{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Team{}, err
	}
	return s.GetTeam(teamID)
}

func saveTeamUsersTx(tx *sql.Tx, teamID, requiredUserID int, userIDs []int) error {
	if _, err := tx.Exec("DELETE FROM team_users WHERE team_id = ?", teamID); err != nil {
		return err
	}
	uniqueUserIDs := []int{requiredUserID}
	adminUserIDs, err := listAdminUserIDsTx(tx)
	if err != nil {
		return err
	}
	for _, userID := range adminUserIDs {
		if userID <= 0 || slices.Contains(uniqueUserIDs, userID) {
			continue
		}
		uniqueUserIDs = append(uniqueUserIDs, userID)
	}
	for _, userID := range userIDs {
		if userID <= 0 || slices.Contains(uniqueUserIDs, userID) {
			continue
		}
		uniqueUserIDs = append(uniqueUserIDs, userID)
	}
	for _, userID := range uniqueUserIDs {
		if _, err := tx.Exec("INSERT INTO team_users (team_id, user_id) VALUES (?, ?)", teamID, userID); err != nil {
			return err
		}
	}
	return nil
}

func listAdminUserIDsTx(tx *sql.Tx) ([]int, error) {
	rows, err := tx.Query("SELECT id FROM users WHERE is_admin = 1 ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	userIDs := []int{}
	for rows.Next() {
		var userID int
		if err := rows.Scan(&userID); err != nil {
			return nil, err
		}
		userIDs = append(userIDs, userID)
	}
	return userIDs, rows.Err()
}

func (s *Store) DeleteTeam(teamID int) error {
	_, err := s.db.Exec("DELETE FROM teams WHERE id = ?", teamID)
	return err
}

func (s *Store) UserInAnyTeam(userID int, teamIDs []int) (bool, error) {
	if len(teamIDs) == 0 {
		return true, nil
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(teamIDs)), ",")
	args := []any{userID}
	for _, teamID := range teamIDs {
		args = append(args, teamID)
	}
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM team_users WHERE user_id = ? AND team_id IN ("+placeholders+")", args...).Scan(&count)
	return count > 0, err
}
