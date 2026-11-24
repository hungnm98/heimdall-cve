// Package httpx is the shared HTTP client every plugin must use: retries with
// exponential backoff, rate-limit awareness (Retry-After, X-RateLimit-*),
// a per-host concurrency limit, plus JSON helpers and an on-disk cache.
package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ErrRateLimited is returned when the server asks us to wait longer than Options.MaxWait.
var ErrRateLimited = errors.New("rate limited")

// StatusError is a non-2xx response.
type StatusError struct {
	Method, URL string
	Code        int
	Body        string // first bytes of the body, for diagnostics
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.URL, e.Code, e.Body)
}

// Options configures a Client. Zero values get sensible defaults.
type Options struct {
	Timeout     time.Duration // per attempt; default 60s
	MaxRetries  int           // default 4
	BaseBackoff time.Duration // default 500ms
	MaxBackoff  time.Duration // default 30s
	MaxWait     time.Duration // longest rate-limit wait honoured; default 5m
	PerHost     int           // concurrent requests per host; default 4
	UserAgent   string        // default "heimdall"
	Logger      *slog.Logger
	Transport   http.RoundTripper // for tests
}

// Client is safe for concurrent use.
type Client struct {
	hc    *http.Client
	opts  Options
	mu    sync.Mutex
	hosts map[string]chan struct{}
	sleep func(ctx context.Context, d time.Duration) error
}

// New returns a Client with defaults applied.
func New(o Options) *Client {
	if o.Timeout == 0 {
		o.Timeout = 60 * time.Second
	}
	if o.MaxRetries == 0 {
		o.MaxRetries = 4
	}
	if o.BaseBackoff == 0 {
		o.BaseBackoff = 500 * time.Millisecond
	}
	if o.MaxBackoff == 0 {
		o.MaxBackoff = 30 * time.Second
	}
	if o.MaxWait == 0 {
		o.MaxWait = 5 * time.Minute
	}
	if o.PerHost == 0 {
		o.PerHost = 4
	}
	if o.UserAgent == "" {
		o.UserAgent = "heimdall"
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Client{
		hc:    &http.Client{Timeout: o.Timeout, Transport: o.Transport},
		opts:  o,
		hosts: map[string]chan struct{}{},
		sleep: sleepCtx,
	}
}

// Do sends req, retrying transient failures. A request with a body is only
// retried when req.GetBody is set (http.NewRequest sets it for common readers).
// The caller must close the response body.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.opts.UserAgent)
	}
	replayable := req.Body == nil || req.GetBody != nil
	ctx := req.Context()
	for attempt := 0; ; attempt++ {
		if attempt > 0 && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("replay body: %w", err)
			}
			req.Body = body
		}
		release, err := c.acquire(ctx, req.URL.Host)
		if err != nil {
			return nil, err
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			release()
			if ctx.Err() != nil || !replayable || attempt >= c.opts.MaxRetries {
				return nil, err
			}
			if err := c.wait(ctx, c.backoff(attempt), req); err != nil {
				return nil, err
			}
			continue
		}
		wait, retry := c.retryAfter(resp, attempt)
		if !retry || !replayable || attempt >= c.opts.MaxRetries {
			resp.Body = &releaseBody{ReadCloser: resp.Body, release: release}
			return resp, nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		release()
		if wait > c.opts.MaxWait {
			return nil, fmt.Errorf("%s %s: server asked to wait %s: %w", req.Method, req.URL.Redacted(), wait, ErrRateLimited)
		}
		c.opts.Logger.Debug("http retry", "url", req.URL.Redacted(), "status", resp.StatusCode, "wait", wait, "attempt", attempt+1)
		if err := c.wait(ctx, wait, req); err != nil {
			return nil, err
		}
	}
}

// retryAfter decides whether resp is transient and how long to wait.
func (c *Client) retryAfter(resp *http.Response, attempt int) (time.Duration, bool) {
	rateLimited := resp.StatusCode == http.StatusTooManyRequests ||
		(resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0")
	switch {
	case rateLimited:
	case resp.StatusCode == http.StatusBadGateway, resp.StatusCode == http.StatusServiceUnavailable,
		resp.StatusCode == http.StatusGatewayTimeout, resp.StatusCode == http.StatusInternalServerError:
	default:
		return 0, false
	}
	if d, ok := parseRetryAfter(resp.Header.Get("Retry-After")); ok {
		return d, true
	}
	if rateLimited {
		if reset, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			if d := time.Until(time.Unix(reset, 0)); d > 0 {
				return d + time.Second, true
			}
		}
	}
	return c.backoff(attempt), true
}

func parseRetryAfter(v string) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

// backoff is exponential with full jitter, capped at MaxBackoff.
func (c *Client) backoff(attempt int) time.Duration {
	d := c.opts.BaseBackoff << attempt
	if d <= 0 || d > c.opts.MaxBackoff {
		d = c.opts.MaxBackoff
	}
	return d/2 + rand.N(d/2+1)
}

func (c *Client) wait(ctx context.Context, d time.Duration, req *http.Request) error {
	if err := c.sleep(ctx, d); err != nil {
		return fmt.Errorf("%s %s: %w", req.Method, req.URL.Redacted(), err)
	}
	return nil
}

func (c *Client) acquire(ctx context.Context, host string) (func(), error) {
	c.mu.Lock()
	sem, ok := c.hosts[host]
	if !ok {
		sem = make(chan struct{}, c.opts.PerHost)
		c.hosts[host] = sem
	}
	c.mu.Unlock()
	select {
	case sem <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-sem }) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// releaseBody frees the host slot when the caller closes the body.
type releaseBody struct {
	io.ReadCloser
	release func()
}

func (b *releaseBody) Close() error {
	err := b.ReadCloser.Close()
	b.release()
	return err
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GetJSON GETs url and decodes a 2xx JSON body into out.
func (c *Client) GetJSON(ctx context.Context, url string, header http.Header, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	return c.doJSON(req, header, out)
}

// PostJSON POSTs in as JSON and decodes a 2xx JSON body into out (out may be nil).
func (c *Client) PostJSON(ctx context.Context, url string, header http.Header, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.doJSON(req, header, out)
}

func (c *Client) doJSON(req *http.Request, header http.Header, out any) error {
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &StatusError{Method: req.Method, URL: req.URL.Redacted(), Code: resp.StatusCode, Body: string(snippet)}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("%s %s: decode JSON: %w", req.Method, req.URL.Redacted(), err)
	}
	return nil
}
