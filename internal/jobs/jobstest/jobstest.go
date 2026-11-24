// Package jobstest is the contract test kit for jobs.Backend.
package jobstest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/jobs"
)

// Run executes the contract. newBackend must return a fresh backend whose
// queue is empty (e.g. a dedicated Valkey DB or key prefix per test).
func Run(t *testing.T, newBackend func(t *testing.T) jobs.Backend) {
	t.Helper()
	t.Run("DeliversOnceAndDedupes", func(t *testing.T) { testDelivers(t, newBackend(t)) })
	t.Run("CancelRunning", func(t *testing.T) { testCancelRunning(t, newBackend(t)) })
}

type recorder struct {
	mu    sync.Mutex
	seen  map[int64]int
	block map[int64]chan struct{} // jobs that wait until canceled
	start chan int64
}

func newRecorder() *recorder {
	return &recorder{seen: map[int64]int{}, block: map[int64]chan struct{}{}, start: make(chan int64, 64)}
}

func (r *recorder) HandleScan(ctx context.Context, id int64) error {
	r.mu.Lock()
	r.seen[id]++
	r.mu.Unlock()
	r.start <- id
	if id >= 1000 { // "long" job: wait for cancel
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (r *recorder) count(id int64) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen[id]
}

func runWorker(t *testing.T, b jobs.Backend, h jobs.Handler) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := b.Run(ctx, h); err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Run did not return after ctx cancel")
		}
		_ = b.Close()
	})
	return cancel
}

func waitStart(t *testing.T, r *recorder, want int64) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case id := <-r.start:
			if id == want {
				return
			}
		case <-deadline:
			t.Fatalf("job %d was not delivered", want)
		}
	}
}

func testDelivers(t *testing.T, b jobs.Backend) {
	ctx := context.Background()
	if b.Name() == "" {
		t.Fatal("Name() must not be empty")
	}
	// Enqueue twice before any worker runs: delivered once.
	for i := 0; i < 2; i++ {
		if err := b.Enqueue(ctx, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Enqueue(ctx, 2); err != nil {
		t.Fatal(err)
	}
	r := newRecorder()
	runWorker(t, b, r)
	waitStart(t, r, 1)
	waitStart(t, r, 2)
	time.Sleep(200 * time.Millisecond) // give a duplicate a chance to show up
	if r.count(1) != 1 || r.count(2) != 1 {
		t.Fatalf("deliveries: job1=%d job2=%d, want 1 each", r.count(1), r.count(2))
	}
}

func testCancelRunning(t *testing.T, b jobs.Backend) {
	ctx := context.Background()
	r := newRecorder()
	runWorker(t, b, r)
	if err := b.Enqueue(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	waitStart(t, r, 1000)
	if err := b.Cancel(ctx, 1000); err != nil {
		t.Fatalf("Cancel running job: %v", err)
	}
	// After cancel the handler returns; a new job still runs.
	if err := b.Enqueue(ctx, 3); err != nil {
		t.Fatal(err)
	}
	waitStart(t, r, 3)
}
