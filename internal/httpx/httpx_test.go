package httpx

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient() (*Client, *[]time.Duration) {
	c := New(Options{MaxRetries: 3, BaseBackoff: time.Millisecond, MaxWait: time.Minute})
	var waits []time.Duration
	c.sleep = func(ctx context.Context, d time.Duration) error { waits = append(waits, d); return ctx.Err() }
	return c, &waits
}

func TestRetriesTransientThenSucceeds(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"q":1}` {
			t.Errorf("body not replayed: %q", body)
		}
		if n.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c, waits := newTestClient()
	var out struct{ OK bool }
	if err := c.PostJSON(context.Background(), srv.URL, nil, map[string]int{"q": 1}, &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK || n.Load() != 3 || len(*waits) != 2 {
		t.Fatalf("ok=%v calls=%d waits=%v", out.OK, n.Load(), *waits)
	}
}

func TestHonoursRetryAfterAndRateLimitReset(t *testing.T) {
	var n atomic.Int32
	reset := time.Now().Add(10 * time.Second).Unix()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch n.Add(1) {
		case 1:
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset, 10))
			w.WriteHeader(http.StatusForbidden)
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	c, waits := newTestClient()
	if err := c.GetJSON(context.Background(), srv.URL, nil, &struct{}{}); err != nil {
		t.Fatal(err)
	}
	if (*waits)[0] != 7*time.Second || (*waits)[1] < 5*time.Second {
		t.Fatalf("waits = %v", *waits)
	}
}

func TestRateLimitBeyondMaxWait(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c, _ := newTestClient()
	err := c.GetJSON(context.Background(), srv.URL, nil, nil)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
}

func TestNonRetryableStatus(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	c, _ := newTestClient()
	err := c.GetJSON(context.Background(), srv.URL, nil, nil)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 404 || n.Load() != 1 {
		t.Fatalf("err = %v calls=%d", err, n.Load())
	}
}

func TestPerHostLimitReleasedOnClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := New(Options{PerHost: 1})
	for i := 0; i < 3; i++ { // would deadlock if slots leaked
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		cancel()
	}
}

func TestCache(t *testing.T) {
	c, err := NewCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	fetch := func(context.Context) ([]byte, error) { calls++; return []byte("v"), nil }
	for i := 0; i < 2; i++ {
		b, err := c.Fetch(context.Background(), "k", 0, fetch)
		if err != nil || string(b) != "v" {
			t.Fatal(b, err)
		}
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
	c.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, ok := c.Get("k", 0); ok {
		t.Fatal("expired entry returned")
	}
	var nilCache *Cache
	if _, err := nilCache.Fetch(context.Background(), "k", 0, fetch); err != nil {
		t.Fatal(err)
	}
}
