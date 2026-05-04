package tokenstore

import (
	"time"

	gocachestore "github.com/eko/gocache/lib/v4/store"
	redistore "github.com/eko/gocache/store/redis/v4"
	"github.com/redis/go-redis/v9"
	"k8s.io/client-go/kubernetes"
)

// NewRedisStore returns a Store that persists token entries in Redis.
// addr is a "host:port" string. Useful when multiple proxy replicas need to
// share a single token cache to avoid thundering-herd on TokenRequest.
func NewRedisStore(client kubernetes.Interface, namespace string, ttl time.Duration, audiences []string, addr string) (*TokenRequestStore, error) {
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	backend := redistore.NewRedis(rdb, gocachestore.WithExpiration(ttl))
	return NewTokenRequestStore(client, namespace, ttl, audiences, backend), nil
}
