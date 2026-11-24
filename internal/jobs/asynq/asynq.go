// Package asynq is the production jobs.Backend: asynq (github.com/hibiken/asynq)
// on Valkey (or any Redis-protocol server). The queue only carries job IDs;
// the job record lives in the store.
//
// Config:
//
//	jobs:
//	  type: asynq
//	  addr_env: HEIMDALL_VALKEY_ADDR          # host:port (or addr: host:port)
//	  password_env: HEIMDALL_VALKEY_PASSWORD  # optional
//	  db: 0
//	  concurrency: 4
//	  queue: heimdall
//	  max_retry: 3
//	  timeout: 2h
//
// Each job is task "scan" with TaskID "job-<id>", so enqueueing a job twice is
// a no-op. Canceling a queued task deletes it; canceling an active one signals
// the worker (Inspector.CancelProcessing) and leaves a short-lived marker so
// the canceled task is not run again when asynq retries it. On shutdown the
// handlers' ctx is canceled and their tasks go back to the queue without
// counting as a failed attempt.
package asynq

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	hq "github.com/hibiken/asynq"
	"github.com/hungnm98/heimdall-cve/internal/jobs"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/redis/go-redis/v9"
)

// TaskType is the asynq task type of a scan job.
const TaskType = "scan"

// retention keeps finished tasks (and so their TaskID) for this long, and is
// the lifetime of a cancel marker.
const retention = 24 * time.Hour

func init() { jobs.Registry.Register("asynq", New) }

// Config is the plugin's config block.
type Config struct {
	Addr        string        `mapstructure:"addr"`
	AddrEnv     string        `mapstructure:"addr_env"`
	PasswordEnv string        `mapstructure:"password_env"`
	DB          int           `mapstructure:"db"`
	Concurrency int           `mapstructure:"concurrency"`
	Queue       string        `mapstructure:"queue"`
	MaxRetry    int           `mapstructure:"max_retry"`
	Timeout     time.Duration `mapstructure:"timeout"`
}

// Validate checks the config.
func (c *Config) Validate() error {
	switch {
	case c.Addr == "" && c.AddrEnv == "":
		return errors.New("addr or addr_env is required")
	case c.DB < 0:
		return errors.New("db must be >= 0")
	case c.Concurrency <= 0:
		return errors.New("concurrency must be > 0")
	case c.Queue == "":
		return errors.New("queue must not be empty")
	case c.MaxRetry < 0:
		return errors.New("max_retry must be >= 0")
	case c.Timeout <= 0:
		return errors.New("timeout must be > 0")
	}
	return nil
}

// Backend implements jobs.Backend on asynq.
type Backend struct {
	cfg    Config
	rdb    *redis.Client
	client *hq.Client
	insp   *hq.Inspector
	logger *slog.Logger
}

var _ jobs.Backend = (*Backend)(nil)

// New is the registry factory. It does not connect: the first command does.
func New(raw plugin.Config, deps plugin.Deps) (jobs.Backend, error) {
	cfg := Config{AddrEnv: "HEIMDALL_VALKEY_ADDR", Concurrency: 4, Queue: "heimdall", MaxRetry: 3, Timeout: 2 * time.Hour}
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("asynq jobs: %w", err)
	}
	addr := cfg.Addr
	if addr == "" {
		addr = os.Getenv(cfg.AddrEnv)
		if addr == "" {
			return nil, fmt.Errorf("asynq jobs: env %s (addr_env) is not set", cfg.AddrEnv)
		}
	}
	var password string
	if cfg.PasswordEnv != "" {
		// An unset password env means "no password"; a wrong setup then fails
		// with NOAUTH on the first command.
		p, err := secret.Resolve(cfg.PasswordEnv, "")
		if err != nil && !errors.Is(err, secret.ErrMissing) {
			return nil, fmt.Errorf("asynq jobs: password: %w", err)
		}
		password = p
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: password, DB: cfg.DB})
	return &Backend{
		cfg:    cfg,
		rdb:    rdb,
		client: hq.NewClientFromRedisClient(rdb),
		insp:   hq.NewInspectorFromRedisClient(rdb),
		logger: logger.With("component", "jobs.asynq"),
	}, nil
}

func (b *Backend) Name() string { return "asynq" }

func taskID(jobID int64) string { return "job-" + strconv.FormatInt(jobID, 10) }

func (b *Backend) cancelKey(jobID int64) string {
	return "heimdall:jobs:" + b.cfg.Queue + ":canceled:" + strconv.FormatInt(jobID, 10)
}

type payload struct {
	JobID int64 `json:"job_id"`
}

// Enqueue adds jobID to the queue; an existing task with the same ID
// (queued, running, retrying or recently finished) makes it a no-op.
func (b *Backend) Enqueue(ctx context.Context, jobID int64) error {
	body, err := json.Marshal(payload{JobID: jobID})
	if err != nil {
		return err
	}
	task := hq.NewTask(TaskType, body,
		hq.TaskID(taskID(jobID)), hq.Queue(b.cfg.Queue), hq.MaxRetry(b.cfg.MaxRetry),
		hq.Timeout(b.cfg.Timeout), hq.Retention(retention))
	_, err = b.client.EnqueueContext(ctx, task)
	if errors.Is(err, hq.ErrTaskIDConflict) || errors.Is(err, hq.ErrDuplicateTask) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("asynq enqueue job %d: %w", jobID, err)
	}
	return nil
}

// Cancel deletes a waiting task or signals an active one.
func (b *Backend) Cancel(ctx context.Context, jobID int64) error {
	id := taskID(jobID)
	info, err := b.insp.GetTaskInfo(b.cfg.Queue, id)
	if errors.Is(err, hq.ErrTaskNotFound) || errors.Is(err, hq.ErrQueueNotFound) {
		return jobs.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("asynq cancel job %d: %w", jobID, err)
	}
	switch info.State {
	case hq.TaskStatePending, hq.TaskStateScheduled, hq.TaskStateRetry, hq.TaskStateAggregating:
		err := b.insp.DeleteTask(b.cfg.Queue, id)
		if errors.Is(err, hq.ErrTaskNotFound) {
			return jobs.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("asynq cancel job %d: %w", jobID, err)
		}
		return nil
	case hq.TaskStateActive:
		// asynq retries a task whose handler was canceled; the marker makes
		// that retry a no-op.
		if err := b.rdb.Set(ctx, b.cancelKey(jobID), "1", retention).Err(); err != nil {
			return fmt.Errorf("asynq cancel job %d: %w", jobID, err)
		}
		if err := b.insp.CancelProcessing(id); err != nil {
			return fmt.Errorf("asynq cancel job %d: %w", jobID, err)
		}
		return nil
	}
	return jobs.ErrNotFound // completed or archived: nothing to stop
}

// Run serves the queue with h until ctx is done, then stops fetching, cancels
// the handlers' ctx and waits for them to return.
func (b *Backend) Run(ctx context.Context, h jobs.Handler) error {
	handlerCtx, stopHandlers := context.WithCancel(context.Background())
	defer stopHandlers()
	srv := hq.NewServerFromRedisClient(b.rdb, hq.Config{
		Concurrency: b.cfg.Concurrency,
		Queues:      map[string]int{b.cfg.Queue: 1},
		BaseContext: func() context.Context { return handlerCtx },
		// A canceled handler (worker shutdown or Cancel) is not a failed
		// attempt: requeue it quickly without spending a retry.
		IsFailure: func(err error) bool { return !errors.Is(err, context.Canceled) },
		RetryDelayFunc: func(n int, err error, t *hq.Task) time.Duration {
			if errors.Is(err, context.Canceled) {
				return time.Second
			}
			return hq.DefaultRetryDelayFunc(n, err, t)
		},
		Logger:   logAdapter{b.logger},
		LogLevel: hq.WarnLevel,
	})
	mux := hq.NewServeMux()
	mux.HandleFunc(TaskType, func(tctx context.Context, t *hq.Task) error {
		var p payload
		if err := json.Unmarshal(t.Payload(), &p); err != nil || p.JobID <= 0 {
			return fmt.Errorf("bad scan payload %q: %w", t.Payload(), hq.SkipRetry)
		}
		if n, err := b.rdb.Exists(tctx, b.cancelKey(p.JobID)).Result(); err == nil && n > 0 {
			b.logger.Info("skipping canceled job", "job_id", p.JobID)
			return nil
		}
		return h.HandleScan(tctx, p.JobID)
	})
	if err := srv.Start(mux); err != nil {
		return fmt.Errorf("asynq start: %w", err)
	}
	<-ctx.Done()
	srv.Stop()     // no new tasks
	stopHandlers() // in-flight handlers see ctx canceled and return
	srv.Shutdown()
	return nil
}

// Close releases the connection.
func (b *Backend) Close() error { return b.rdb.Close() }

// ---- leader lock (service.Locker) ----

var unlockScript = redis.NewScript(`if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end`)

// TryLock takes key for ttl (SET NX PX with a random token). release deletes
// the lock only while this holder still owns it. ok is false when another
// holder has it.
func (b *Backend) TryLock(ctx context.Context, key string, ttl time.Duration) (func(), bool, error) {
	tok := make([]byte, 16)
	if _, err := rand.Read(tok); err != nil {
		return nil, false, err
	}
	token, k := hex.EncodeToString(tok), "heimdall:lock:"+key
	ok, err := b.rdb.SetNX(ctx, k, token, ttl).Result()
	if err != nil {
		return nil, false, fmt.Errorf("lock %s: %w", key, err)
	}
	if !ok {
		return nil, false, nil
	}
	release := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := unlockScript.Run(ctx, b.rdb, []string{k}, token).Err(); err != nil {
			b.logger.Warn("release lock", "key", key, "err", err)
		}
	}
	return release, true, nil
}

// logAdapter sends asynq's logs to slog.
type logAdapter struct{ l *slog.Logger }

func (a logAdapter) Debug(args ...any) { a.l.Debug(fmt.Sprint(args...)) }
func (a logAdapter) Info(args ...any)  { a.l.Info(fmt.Sprint(args...)) }
func (a logAdapter) Warn(args ...any)  { a.l.Warn(fmt.Sprint(args...)) }
func (a logAdapter) Error(args ...any) { a.l.Error(fmt.Sprint(args...)) }
func (a logAdapter) Fatal(args ...any) {
	a.l.Error(fmt.Sprint(args...))
	os.Exit(1)
}
