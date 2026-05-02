package main

import (
	"fmt"
	"strings"
	"unicode"
)

func normalizeUsername(username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("username is required")
	}
	if len(username) > 15 {
		return "", fmt.Errorf("username must be 15 characters or less")
	}
	for _, r := range username {
		if unicode.IsSpace(r) {
			return "", fmt.Errorf("username cannot contain spaces")
		}
	}
	return username, nil
}
