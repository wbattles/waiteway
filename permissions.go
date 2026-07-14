package main

import (
	"database/sql"
	"net/http"
	"strings"
	"sync"
	"time"
)

// apiKeyCacheTTL bounds how long a hashed-key lookup is trusted before
// re-checking the store. A revoked or rotated key can therefore remain
// valid for up to this long after deletion; kept short deliberately.
const apiKeyCacheTTL = 30 * time.Second

// maxAPIKeyCacheEntries bounds memory the same way responseCache does.
const maxAPIKeyCacheEntries = 4096

// apiKeyCache caches hashed-API-key -> user lookups so a proxied request
// with RequireAPIKey doesn't pay a SQLite round trip (capped at 2 open
// connections, see openStore) on every single request.
type apiKeyCache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[string]apiKeyCacheEntry
}

type apiKeyCacheEntry struct {
	user      User
	found     bool
	expiresAt time.Time
}

func newAPIKeyCache(ttl time.Duration) *apiKeyCache {
	return &apiKeyCache{ttl: ttl, entries: map[string]apiKeyCacheEntry{}}
}

func (c *apiKeyCache) get(hashedKey string, now time.Time) (User, bool, bool) {
	c.mu.RLock()
	entry, ok := c.entries[hashedKey]
	c.mu.RUnlock()
	if !ok || now.After(entry.expiresAt) {
		return User{}, false, false
	}
	return entry.user, entry.found, true
}

func (c *apiKeyCache) set(hashedKey string, user User, found bool, now time.Time) {
	c.mu.Lock()
	if _, exists := c.entries[hashedKey]; !exists && len(c.entries) >= maxAPIKeyCacheEntries {
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	c.entries[hashedKey] = apiKeyCacheEntry{user: user, found: found, expiresAt: now.Add(c.ttl)}
	c.mu.Unlock()
}

func (g *Gateway) requestUser(r *http.Request) (User, bool) {
	key := requestAPIKey(r)
	if key == "" {
		return User{}, false
	}

	hashed := hashAPIKey(strings.TrimSpace(key))
	now := time.Now()
	if user, found, ok := g.apiKeyCache.get(hashed, now); ok {
		return user, found
	}

	user, err := g.store.FindUserByAPIKey(key)
	if err != nil && err != sql.ErrNoRows {
		// Transient store error: don't cache it, just fail this request.
		return User{}, false
	}
	found := err == nil
	g.apiKeyCache.set(hashed, user, found, now)
	return user, found
}
