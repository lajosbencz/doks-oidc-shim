package tokenstore

import (
	"context"
	"errors"
	"time"

	gocachestore "github.com/eko/gocache/lib/v4/store"
	gocache "github.com/patrickmn/go-cache"
)

var errNotFound = errors.New("key not found")

// gocacheStore adapts patrickmn/go-cache to satisfy eko/gocache StoreInterface,
// giving us an in-process memory cache without the separate store module.
type gocacheStore struct {
	c *gocache.Cache
}

func newGocacheStore(defaultTTL, cleanupInterval time.Duration) *gocacheStore {
	return &gocacheStore{c: gocache.New(defaultTTL, cleanupInterval)}
}

func (s *gocacheStore) Get(_ context.Context, key any) (any, error) {
	v, ok := s.c.Get(key.(string)) //nolint:forcetypeassert
	if !ok {
		return nil, gocachestore.NotFoundWithCause(errNotFound) //nolint:wrapcheck // sentinel constructor
	}
	return v, nil
}

func (s *gocacheStore) GetWithTTL(_ context.Context, key any) (any, time.Duration, error) {
	v, exp, ok := s.c.GetWithExpiration(key.(string)) //nolint:forcetypeassert
	if !ok {
		return nil, 0, gocachestore.NotFoundWithCause(errNotFound) //nolint:wrapcheck // sentinel constructor
	}
	ttl := max(time.Until(exp), 0)
	return v, ttl, nil
}

func (s *gocacheStore) Set(_ context.Context, key any, value any, opts ...gocachestore.Option) error {
	o := gocachestore.ApplyOptionsWithDefault(&gocachestore.Options{}, opts...)
	s.c.Set(key.(string), value, o.Expiration) //nolint:forcetypeassert
	return nil
}

func (s *gocacheStore) Delete(_ context.Context, key any) error {
	s.c.Delete(key.(string)) //nolint:forcetypeassert
	return nil
}

func (s *gocacheStore) Invalidate(_ context.Context, opts ...gocachestore.InvalidateOption) error {
	o := gocachestore.ApplyInvalidateOptions(opts...)
	for _, tag := range o.Tags {
		s.c.Delete(tag)
	}
	return nil
}

func (s *gocacheStore) Clear(_ context.Context) error {
	s.c.Flush()
	return nil
}

func (s *gocacheStore) GetType() string { return "gocache" }
