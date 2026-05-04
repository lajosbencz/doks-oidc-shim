package tokenstore

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	gocachelib "github.com/eko/gocache/lib/v4/cache"
	gocachestore "github.com/eko/gocache/lib/v4/store"
	oidcshimv1alpha1 "github.com/lajosbencz/doks-oidc-shim/api/v1alpha1"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// TokenRequestStore implements Store using the Kubernetes TokenRequest API.
// Tokens are cached and proactively refreshed before expiry.
type TokenRequestStore struct {
	client    kubernetes.Interface
	namespace string
	ttl       time.Duration
	audiences []string
	cache     *gocachelib.Cache[*TokenEntry]
}

// NewTokenRequestStore creates a store backed by the given cache backend.
// audiences is the audience list passed to TokenRequest; an empty slice causes
// the API server to issue a token for its default audience.
func NewTokenRequestStore(
	client kubernetes.Interface,
	namespace string,
	ttl time.Duration,
	audiences []string,
	backend gocachestore.StoreInterface,
) *TokenRequestStore {
	return &TokenRequestStore{
		client:    client,
		namespace: namespace,
		ttl:       ttl,
		audiences: audiences,
		cache:     gocachelib.New[*TokenEntry](backend),
	}
}

// Get returns a valid bearer token for the given role, fetching and caching
// a new one via TokenRequest when the cached entry is absent or near expiry.
func (s *TokenRequestStore) Get(ctx context.Context, role string) (string, error) {
	key := s.cacheKey(role)
	cached, err := s.cache.Get(ctx, key)
	if err == nil && !needsRefresh(cached, time.Now()) {
		return cached.Token, nil
	}

	entry, err := s.fetchToken(ctx, role)
	if err != nil {
		// Return stale token on refresh failure rather than failing the request.
		if cached != nil {
			slog.WarnContext(ctx, "token refresh failed; serving stale token", "role", role, "err", err)
			return cached.Token, nil
		}
		slog.ErrorContext(ctx, "token fetch failed and no cached fallback", "role", role, "err", err)
		return "", err
	}

	if err := s.cache.Set(ctx, key, entry, gocachestore.WithExpiration(s.ttl)); err != nil {
		return "", fmt.Errorf("caching token for role %q: %w", role, err)
	}
	slog.DebugContext(ctx, "issued and cached token", "role", role, "expires_at", entry.ExpiresAt)
	return entry.Token, nil
}

// fetchToken resolves the ServiceAccount for the role and issues a TokenRequest.
func (s *TokenRequestStore) fetchToken(ctx context.Context, role string) (*TokenEntry, error) {
	saList, err := s.client.CoreV1().ServiceAccounts(s.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: oidcshimv1alpha1.RoleLabel + "=" + role,
		Limit:         1,
	})
	if err != nil {
		return nil, fmt.Errorf("listing ServiceAccounts for role %q: %w", role, err)
	}
	if len(saList.Items) == 0 {
		return nil, fmt.Errorf("%w: role=%q namespace=%q", ErrNoSAFound, role, s.namespace)
	}

	saName := saList.Items[0].Name
	ttlSecs := int64(s.ttl.Seconds())
	now := time.Now()

	tr, err := s.client.CoreV1().ServiceAccounts(s.namespace).CreateToken(
		ctx,
		saName,
		&authv1.TokenRequest{
			Spec: authv1.TokenRequestSpec{
				Audiences:         s.audiences,
				ExpirationSeconds: &ttlSecs,
			},
		},
		metav1.CreateOptions{FieldManager: oidcshimv1alpha1.FieldManagerProxy},
	)
	if err != nil {
		return nil, fmt.Errorf("TokenRequest for SA %q: %w", saName, err)
	}

	return &TokenEntry{
		Token:     tr.Status.Token,
		IssuedAt:  now,
		ExpiresAt: tr.Status.ExpirationTimestamp.Time,
	}, nil
}

// cacheKey namespaces the cache entry so multiple proxy instances sharing one
// backend (e.g. Redis) cannot collide on identical role names from different
// Kubernetes namespaces.
func (s *TokenRequestStore) cacheKey(role string) string {
	return s.namespace + "/" + role
}
