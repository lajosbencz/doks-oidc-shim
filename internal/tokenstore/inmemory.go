package tokenstore

import (
	"time"

	"k8s.io/client-go/kubernetes"
)

// NewInMemoryStore returns a Store backed by an in-process cache.
// cleanupInterval controls how often expired entries are evicted from memory.
func NewInMemoryStore(client kubernetes.Interface, namespace string, ttl time.Duration, audiences []string, cleanupInterval time.Duration) *TokenRequestStore {
	backend := newGocacheStore(ttl, cleanupInterval)
	return NewTokenRequestStore(client, namespace, ttl, audiences, backend)
}
