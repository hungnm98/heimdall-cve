// Package inline is an in-process jobs.Backend: a buffered channel and a fixed
// worker pool. Used by the CLI (`heimdall scan`) and tests; jobs are lost when
// the process exits. It is the reference implementation of the jobs contract.
package inline

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/hungnm98/heimdall-cve/internal/jobs"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
)

func init() { jobs.Registry.Register("inline", New) }

// Config is the plugin's config block.
type Config struct {
	Concurrency int `mapstructure:"concurrency"`
	Buffer      int `mapstructure:"buffer"`
}

// Backend implements jobs.Backend.
type Backend struct {
	cfg     Config
	queue   chan int64
	mu      sync.Mutex
	pending map[int64]bool               // queued, not yet started
	running map[int64]context.CancelFunc // started
	closed  bool
}

var _ jobs.Backend = (*Backend)(nil)

// New is the registry factory.
func New(raw plugin.Config, _ plugin.Deps) (jobs.Backend, error) {
	cfg := Config{Concurrency: 2, Buffer: 1024}
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("inline jobs: %w", err)
	}
	if cfg.Concurrency <= 0 || cfg.Buffer <= 0 {
		return nil, errors.New("inline jobs: concurrency and buffer must be > 0")
	}
	return &Backend{cfg: cfg, queue: make(chan int64, cfg.Buffer), pending: map[int64]bool{}, running: map[int64]context.CancelFunc{}}, nil
}

func (b *Backend) Name() string { return "inline" }

func (b *Backend) Enqueue(ctx context.Context, jobID int64) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return errors.New("inline jobs: closed")
	}
	if b.pending[jobID] || b.running[jobID] != nil {
		b.mu.Unlock()
		return nil
	}
	b.pending[jobID] = true
	b.mu.Unlock()
	select {
	case b.queue <- jobID:
		return nil
	case <-ctx.Done():
		b.mu.Lock()
		delete(b.pending, jobID)
		b.mu.Unlock()
		return ctx.Err()
	}
}

func (b *Backend) Cancel(_ context.Context, jobID int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cancel := b.running[jobID]; cancel != nil {
		cancel()
		return nil
	}
	if b.pending[jobID] {
		delete(b.pending, jobID) // skipped when dequeued
		return nil
	}
	return jobs.ErrNotFound
}

func (b *Backend) Run(ctx context.Context, h jobs.Handler) error {
	var wg sync.WaitGroup
	for i := 0; i < b.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case id := <-b.queue:
					b.process(ctx, h, id)
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

func (b *Backend) process(parent context.Context, h jobs.Handler, id int64) {
	b.mu.Lock()
	if !b.pending[id] { // canceled while queued
		b.mu.Unlock()
		return
	}
	delete(b.pending, id)
	ctx, cancel := context.WithCancel(parent)
	b.running[id] = cancel
	b.mu.Unlock()
	defer func() {
		cancel()
		b.mu.Lock()
		delete(b.running, id)
		b.mu.Unlock()
	}()
	_ = h.HandleScan(ctx, id) // failures are recorded on the job by the handler
}

func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}
