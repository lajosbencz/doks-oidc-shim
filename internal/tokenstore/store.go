// Package tokenstore resolves OIDC role names to short-lived Kubernetes bearer
// tokens using the TokenRequest API, with a pluggable cache backend.
package tokenstore

import (
	"context"
	"errors"
	"time"
)

// ErrNoSAFound is returned when no ServiceAccount carrying the requested role
// label exists in the configured namespace.
var ErrNoSAFound = errors.New("no ServiceAccount found for role")

// TokenEntry holds a short-lived bearer token together with its issuance and
// expiry metadata so the cache can decide when to proactively refresh.
type TokenEntry struct {
	Token     string    `json:"token"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Store resolves a role name to a valid bearer token.
// Implementations must be safe for concurrent use.
type Store interface {
	Get(ctx context.Context, role string) (string, error)
}

// needsRefresh reports whether the entry is absent or its remaining TTL is
// below 20 % of its total issued duration, triggering a proactive refresh.
func needsRefresh(entry *TokenEntry, now time.Time) bool {
	if entry == nil {
		return true
	}
	total := entry.ExpiresAt.Sub(entry.IssuedAt)
	remaining := entry.ExpiresAt.Sub(now)
	return remaining < total/5
}
