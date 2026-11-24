package asynq

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	hq "github.com/hibiken/asynq"
	"github.com/hungnm98/heimdall-cve/internal/jobs"
	"github.com/hungnm98/heimdall-cve/internal/jobs/jobstest"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/redis/go-redis/v9"
)

// Set HEIMDALL_TEST_VALKEY_ADDR (host:port) to run against a real server.
// Each backend uses its own queue, deleted when the test ends.
const addrEnv = "HEIMDALL_TEST_VALKEY_ADDR"

func newTestBackend(t *testing.T) *Backend {
	t.Helper()
	addr := os.Getenv(addrEnv)
	if addr == "" {
		t.Skipf("%s not set", addrEnv)
	}
	queue := fmt.Sprintf("heimdall-test-%d", rand.Uint32())
	b, err := New(plugin.Config{"addr": addr, "queue": queue, "concurrency": 4}, plugin.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		insp := hq.NewInspector(hq.RedisClientOpt{Addr: addr})
		defer insp.Close()
		_ = insp.DeleteQueue(queue, true)
		_ = b.Close()
	})
	return b.(*Backend)
}

func TestContract(t *testing.T) {
	jobstest.Run(t, func(t *testing.T) jobs.Backend { return newTestBackend(t) })
}

func TestCancelQueuedAndUnknown(t *testing.T) {
	b := newTestBackend(t)
	ctx := context.Background()
	if err := b.Cancel(ctx, 7); !errors.Is(err, jobs.ErrNotFound) {
		t.Fatalf("cancel unknown: %v", err)
	}
	if err := b.Enqueue(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if err := b.Cancel(ctx, 7); err != nil {
		t.Fatalf("cancel queued: %v", err)
	}
	var ran atomic.Int32
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- b.Run(runCtx, jobs.HandlerFunc(func(context.Context, int64) error { ran.Add(1); return nil }))
	}()
	time.Sleep(1500 * time.Millisecond)
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if ran.Load() != 0 {
		t.Fatal("a canceled queued job must not run")
	}
}

// Shutdown cancels the handler ctx and requeues the task without spending a
// retry; the next worker runs it again.
func TestShutdownRequeues(t *testing.T) {
	b := newTestBackend(t)
	ctx := context.Background()
	started := make(chan int, 4)
	var n atomic.Int32
	h := jobs.HandlerFunc(func(ctx context.Context, id int64) error {
		started <- int(n.Add(1))
		if n.Load() == 1 {
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	})
	if err := b.Enqueue(ctx, 9); err != nil {
		t.Fatal(err)
	}
	run := func() (context.CancelFunc, chan error) {
		c, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- b.Run(c, h) }()
		return cancel, done
	}
	stop, done := run()
	waitN(t, started, 1)
	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after shutdown")
	}
	stop2, done2 := run()
	defer func() { stop2(); <-done2 }()
	waitN(t, started, 2)
	info, err := b.insp.GetTaskInfo(b.cfg.Queue, taskID(9))
	if err == nil && info.Retried != 0 {
		t.Fatalf("shutdown spent a retry: retried=%d", info.Retried)
	}
}

func waitN(t *testing.T, ch chan int, want int) {
	t.Helper()
	deadline := time.After(15 * time.Second)
	for {
		select {
		case got := <-ch:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("delivery %d did not happen", want)
		}
	}
}

func TestTryLock(t *testing.T) {
	b := newTestBackend(t)
	ctx := context.Background()
	key := fmt.Sprintf("test-%d", rand.Uint32())
	release, ok, err := b.TryLock(ctx, key, time.Minute)
	if err != nil || !ok {
		t.Fatalf("first TryLock: ok=%v err=%v", ok, err)
	}
	if _, ok, err := b.TryLock(ctx, key, time.Minute); err != nil || ok {
		t.Fatalf("second TryLock must fail while held: ok=%v err=%v", ok, err)
	}
	// A holder whose lock expired must not delete the next holder's lock.
	b.rdb.Set(ctx, "heimdall:lock:"+key, "someone-else", time.Minute)
	release()
	if v, _ := b.rdb.Get(ctx, "heimdall:lock:"+key).Result(); v != "someone-else" {
		t.Fatalf("release deleted another holder's lock: %q", v)
	}
	b.rdb.Del(ctx, "heimdall:lock:"+key)
	release2, ok, err := b.TryLock(ctx, key, time.Minute)
	if err != nil || !ok {
		t.Fatalf("TryLock after release: ok=%v err=%v", ok, err)
	}
	release2()
	if _, err := b.rdb.Get(ctx, "heimdall:lock:"+key).Result(); !errors.Is(err, redis.Nil) {
		t.Fatalf("lock not released: %v", err)
	}
}

func TestConfig(t *testing.T) {
	t.Setenv("HEIMDALL_VALKEY_ADDR", "")
	if _, err := New(plugin.Config{}, plugin.Deps{}); err == nil || !strings.Contains(err.Error(), "HEIMDALL_VALKEY_ADDR") {
		t.Fatalf("missing addr: %v", err)
	}
	for _, bad := range []plugin.Config{
		{"addr": "x:1", "concurrency": 0},
		{"addr": "x:1", "queue": ""},
		{"addr": "x:1", "timeout": "0s"},
		{"addr": "x:1", "nope": 1},
	} {
		if _, err := New(bad, plugin.Deps{}); err == nil {
			t.Fatalf("config %v must be rejected", bad)
		}
	}
	t.Setenv("HEIMDALL_TEST_VALKEY_PW", "s3cret")
	b, err := New(plugin.Config{"addr": "127.0.0.1:1", "password_env": "HEIMDALL_TEST_VALKEY_PW"}, plugin.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.Enqueue(context.Background(), 1); err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("unreachable server must fail without leaking the password: %v", err)
	}
}
