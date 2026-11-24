package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/jobs"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/hungnm98/heimdall-cve/internal/store/memstore"
	"github.com/hungnm98/heimdall-cve/internal/store/storetest"
)

// fakeQueue records enqueued job IDs and can fail.
type fakeQueue struct {
	mu   sync.Mutex
	ids  []int64
	fail error
}

func (q *fakeQueue) Name() string { return "fake" }
func (q *fakeQueue) Enqueue(_ context.Context, id int64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.fail != nil {
		return q.fail
	}
	q.ids = append(q.ids, id)
	return nil
}
func (q *fakeQueue) Cancel(context.Context, int64) error           { return jobs.ErrNotFound }
func (q *fakeQueue) Run(ctx context.Context, _ jobs.Handler) error { <-ctx.Done(); return nil }
func (q *fakeQueue) Close() error                                  { return nil }
func (q *fakeQueue) enqueued() []int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]int64(nil), q.ids...)
}

// lockingQueue adds the Locker capability.
type lockingQueue struct {
	fakeQueue
	mu       sync.Mutex
	held     bool
	released int
}

func (q *lockingQueue) TryLock(context.Context, string, time.Duration) (func(), bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.held {
		return nil, false, nil
	}
	q.held = true
	return func() { q.mu.Lock(); q.held = false; q.released++; q.mu.Unlock() }, true, nil
}

type schedEnv struct {
	cat   *memstore.Store
	queue *fakeQueue
	now   time.Time
	s     *Scheduler
}

func newSchedEnv(t *testing.T) *schedEnv {
	t.Helper()
	cat := memstore.New()
	if err := cat.SaveAuthProfile(context.Background(), &model.AuthProfile{Name: "pat", Type: "token", Origin: model.OriginUI}); err != nil {
		t.Fatal(err)
	}
	e := &schedEnv{cat: cat, queue: &fakeQueue{}, now: testNow}
	e.s = NewScheduler(Deps{Store: cat, Catalog: cat, Jobs: e.queue, Now: func() time.Time { return e.now }})
	return e
}

func (e *schedEnv) target(t *testing.T, owner, schedule string, next *time.Time) *model.TargetSpec {
	t.Helper()
	tg := &model.TargetSpec{Target: model.Target{Kind: model.TargetOrg, Provider: "github", Owner: owner, Auth: "pat", ListAuth: "pat"},
		Schedule: schedule, Enabled: true, Origin: model.OriginUI, NextRunAt: next}
	if err := e.cat.SaveTarget(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	return tg
}

func ptr(t time.Time) *time.Time { return &t }

func TestNextRun(t *testing.T) {
	after := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		sched string
		want  time.Time
	}{
		{"0 2 * * *", time.Date(2026, 3, 2, 2, 0, 0, 0, time.UTC)},
		{"@daily", time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)},
		{"@every 72h", after.Add(72 * time.Hour)},
		{"CRON_TZ=Asia/Ho_Chi_Minh 0 9 * * *", time.Date(2026, 3, 2, 2, 0, 0, 0, time.UTC)},
	} {
		got, err := NextRun(c.sched, after)
		if err != nil || got == nil || !got.Equal(c.want) {
			t.Errorf("NextRun(%q) = %v, %v; want %v", c.sched, got, err, c.want)
		}
	}
	if got, err := NextRun("", after); got != nil || err != nil {
		t.Errorf("empty schedule = %v, %v", got, err)
	}
	if _, err := NextRun("every day", after); err == nil {
		t.Error("bad schedule must fail")
	}
}

func TestSchedulerTriggersDueTargets(t *testing.T) {
	e := newSchedEnv(t)
	ctx := context.Background()
	due := e.target(t, "due", "0 2 * * *", ptr(e.now.Add(-time.Minute)))
	later := e.target(t, "later", "0 2 * * *", ptr(e.now.Add(time.Hour)))
	bad := e.target(t, "bad", "whenever", ptr(e.now.Add(-time.Hour)))

	if err := e.s.tick(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	jl, _ := e.cat.ListJobs(ctx, store.JobFilter{})
	if len(jl) != 2 {
		t.Fatalf("jobs = %d, want 2 (due + bad)", len(jl))
	}
	byTarget := map[int64]model.Job{}
	for _, j := range jl {
		byTarget[*j.TargetID] = j
		if j.Trigger != model.TriggerSchedule || j.Status != model.JobQueued || j.RequestedBy != "scheduler" {
			t.Fatalf("job = %+v", j)
		}
	}
	if _, ok := byTarget[later.ID]; ok {
		t.Fatal("a target not due yet must not run")
	}
	if got := e.queue.enqueued(); len(got) != 2 {
		t.Fatalf("enqueued = %v", got)
	}
	if got, _ := e.cat.GetTarget(ctx, due.ID); got.NextRunAt == nil || !got.NextRunAt.Equal(time.Date(2026, 3, 2, 2, 0, 0, 0, time.UTC)) {
		t.Fatalf("next run = %v", got.NextRunAt)
	}
	if got, _ := e.cat.GetTarget(ctx, bad.ID); got.NextRunAt != nil {
		t.Fatalf("an invalid schedule must stop scheduling, next run = %v", got.NextRunAt)
	}
	if a, _ := e.cat.ListAudit(ctx, 0, 0); len(a) != 2 || a[0].Action != "job.trigger" || a[0].Actor != "scheduler" {
		t.Fatalf("audit = %+v", a)
	}

	// Same minute again: nothing is due any more.
	if err := e.s.tick(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	if jl, _ := e.cat.ListJobs(ctx, store.JobFilter{}); len(jl) != 2 {
		t.Fatalf("second tick created jobs: %d", len(jl))
	}
}

func TestSchedulerDedupAndEnqueueRetry(t *testing.T) {
	e := newSchedEnv(t)
	ctx := context.Background()
	tg := e.target(t, "acme", "@hourly", ptr(e.now.Add(-time.Minute)))
	manual := &model.Job{TargetID: &tg.ID, Trigger: model.TriggerManual}
	if _, err := e.cat.CreateJob(ctx, manual); err != nil {
		t.Fatal(err)
	}

	e.queue.fail = errors.New("valkey down")
	if err := e.s.tick(ctx, time.Minute); err == nil {
		t.Fatal("enqueue failure must be reported")
	}
	if got, _ := e.cat.GetTarget(ctx, tg.ID); !got.NextRunAt.Equal(e.now.Add(-time.Minute)) {
		t.Fatal("next run must not move when the job could not be enqueued")
	}

	e.queue.fail = nil
	if err := e.s.tick(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	if jl, _ := e.cat.ListJobs(ctx, store.JobFilter{}); len(jl) != 1 {
		t.Fatalf("an active job for the target already exists: jobs = %d, want 1", len(jl))
	}
	if got := e.queue.enqueued(); len(got) != 1 || got[0] != manual.ID {
		t.Fatalf("the active job must be (re-)enqueued: %v", got)
	}
	if got, _ := e.cat.GetTarget(ctx, tg.ID); !got.NextRunAt.After(e.now) {
		t.Fatalf("next run = %v", got.NextRunAt)
	}
}

func TestSchedulerExpiresSuppressions(t *testing.T) {
	e := newSchedEnv(t)
	ctx := context.Background()
	f := storetest.F("acme/api", "example.com/a", "v1.0.0", "GO-1", model.SeverityHigh)
	g := storetest.F("acme/api", "example.com/b", "v1.0.0", "GO-2", model.SeverityHigh)
	run := &model.ScanRun{StartedAt: e.now.Add(-time.Hour)}
	if err := e.cat.StartRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	if _, err := e.cat.RecordFindings(ctx, run.ID, []string{"acme/api"}, []model.Finding{f, g}, run.StartedAt); err != nil {
		t.Fatal(err)
	}
	for id, exp := range map[string]time.Time{f.ID: e.now.Add(-time.Second), g.ID: e.now.Add(time.Hour)} {
		if err := e.cat.SaveSuppression(ctx, &model.Suppression{FindingID: id, Reason: "not reachable", ExpiresAt: exp, Actor: "alice"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.s.tick(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := e.cat.GetSuppression(ctx, f.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired suppression still there: %v", err)
	}
	if got, _ := e.cat.GetFinding(ctx, f.ID); got.Status != model.StatusOpen {
		t.Fatalf("finding status = %s, want open", got.Status)
	}
	if _, err := e.cat.GetSuppression(ctx, g.ID); err != nil {
		t.Fatalf("unexpired suppression lifted: %v", err)
	}
	a, _ := e.cat.ListAudit(ctx, 0, 0)
	if len(a) != 1 || a[0].Action != "finding.unsuppress" || a[0].Actor != "scheduler" || a[0].ObjectID != f.ID {
		t.Fatalf("audit = %+v", a)
	}
}

func TestSchedulerLock(t *testing.T) {
	cat := memstore.New()
	q := &lockingQueue{}
	s := NewScheduler(Deps{Catalog: cat, Jobs: q, Now: func() time.Time { return testNow }})
	if s.Locker == nil {
		t.Fatal("NewScheduler must detect the backend's Locker")
	}
	if err := cat.SaveAuthProfile(context.Background(), &model.AuthProfile{Name: "pat", Type: "token", Origin: model.OriginUI}); err != nil {
		t.Fatal(err)
	}
	tg := &model.TargetSpec{Target: model.Target{Kind: model.TargetOrg, Provider: "github", Owner: "acme", Auth: "pat", ListAuth: "pat"},
		Schedule: "@hourly", Enabled: true, Origin: model.OriginUI, NextRunAt: ptr(testNow.Add(-time.Minute))}
	if err := cat.SaveTarget(context.Background(), tg); err != nil {
		t.Fatal(err)
	}

	q.held = true // another replica holds it
	if err := s.tick(context.Background(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(q.enqueued()) != 0 {
		t.Fatal("a replica without the lock must not work")
	}
	q.held = false
	if err := s.tick(context.Background(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(q.enqueued()) != 1 || q.released != 1 || q.held {
		t.Fatalf("enqueued=%v released=%d held=%v", q.enqueued(), q.released, q.held)
	}
}

func TestSchedulerRun(t *testing.T) {
	e := newSchedEnv(t)
	e.target(t, "acme", "@hourly", ptr(e.now.Add(-time.Minute)))
	e.s.Interval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.s.Run(ctx) }()
	deadline := time.After(5 * time.Second)
	for len(e.queue.enqueued()) == 0 {
		select {
		case <-deadline:
			t.Fatal("Run did not trigger the due target")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := NewScheduler(Deps{}).Run(context.Background()); err == nil {
		t.Fatal("Run without catalog/jobs must fail")
	}
}
