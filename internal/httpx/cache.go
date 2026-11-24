package httpx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Cache is a TTL'd on-disk byte cache keyed by arbitrary strings. A nil
// *Cache is valid and caches nothing, so plugins never need nil checks.
type Cache struct {
	dir string
	ttl time.Duration
	now func() time.Time
}

// NewCache creates dir if needed.
func NewCache(dir string, ttl time.Duration) (*Cache, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	return &Cache{dir: dir, ttl: ttl, now: time.Now}, nil
}

func (c *Cache) path(key string) string {
	h := sha256.Sum256([]byte(key))
	s := hex.EncodeToString(h[:])
	return filepath.Join(c.dir, s[:2], s)
}

// Get returns a cached value younger than ttl (0 = the cache default).
func (c *Cache) Get(key string, ttl time.Duration) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	if ttl == 0 {
		ttl = c.ttl
	}
	p := c.path(key)
	st, err := os.Stat(p)
	if err != nil || c.now().Sub(st.ModTime()) > ttl {
		return nil, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return b, true
}

// Put stores value atomically.
func (c *Cache) Put(key string, value []byte) error {
	if c == nil {
		return nil
	}
	p := c.path(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(value); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// Fetch returns the cached value or calls fetch and caches its result.
// Errors are never cached.
func (c *Cache) Fetch(ctx context.Context, key string, ttl time.Duration, fetch func(context.Context) ([]byte, error)) ([]byte, error) {
	if b, ok := c.Get(key, ttl); ok {
		return b, nil
	}
	b, err := fetch(ctx)
	if err != nil {
		return nil, err
	}
	_ = c.Put(key, b) // a failed cache write must not fail the scan
	return b, nil
}
