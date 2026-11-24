package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/core"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/hungnm98/heimdall-cve/internal/store/memstore"
)

var testNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

type fakeScanner struct {
	mu   sync.Mutex
	reqs []core.ScanRequest
	fn   func(ctx context.Context, req core.ScanRequest, p core.Progress) (*model.ScanRun, error)
}

func (f *fakeScanner) Scan(ctx context.Context, req core.ScanRequest, p core.Progress) (*model.ScanRun, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	if f.fn == nil {
		return &model.ScanRun{ID: 7}, nil
	}
	return f.fn(ctx, req, p)
}

func (f *fakeScanner) calls() []core.ScanRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]core.ScanRequest(nil), f.reqs...)
}

type workerEnv struct {
	deps Deps
	cat  store.Catalog
	scan *fakeScanner
	tgt  *model.TargetSpec
}

func newWorkerEnv(t *testing.T) *workerEnv {
	t.Helper()
	ctx := context.Background()
	s := memstore.New()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.SaveAuthProfile(ctx, &model.AuthProfile{Name: "pat", Type: "token", Origin: model.OriginUI}))
	tgt := &model.TargetSpec{Target: model.Target{Kind: model.TargetOrg, Provider: "github", Owner: "acme", Auth: "pat", ListAuth: "pat"},
		Enabled: true, Origin: model.OriginUI}
	must(s.SaveTarget(ctx, tgt))
	off := &model.TargetSpec{Target: model.Target{Kind: model.TargetOrg, Provider: "github", Owner: "off", Auth: "pat", ListAuth: "pat"},
		Enabled: false, Origin: model.OriginUI}
	must(s.SaveTarget(ctx, off))
	fs := &fakeScanner{}
	return &workerEnv{
		deps: Deps{Store: s, Catalog: s, Scanner: fs, Now: func() time.Time { return testNow }},
		cat:  s, scan: fs, tgt: tgt,
	}
}

func (e *workerEnv) job(t *testing.T, j *model.Job) *model.Job {
	t.Helper()
	if j.Trigger == "" {
		j.Trigger = model.TriggerManual
	}
	if _, err := e.cat.CreateJob(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	return j
}

func (e *workerEnv) get(t *testing.T, id int64) *model.Job {
	t.Helper()
	j, err := e.cat.GetJob(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func (e *workerEnv) messages(t *testing.T, id int64) []string {
	t.Helper()
	evs, err := e.cat.ListJobEvents(context.Background(), id, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(evs))
	for _, ev := range evs {
		out = append(out, ev.Level+": "+ev.Message)
	}
	return out
}

func TestJobHandlerTargetJob(t *testing.T) {
	e := newWorkerEnv(t)
	j := e.job(t, &model.Job{TargetID: &e.tgt.ID, Repo: "acme/api", Branch: "develop"})
	if err := NewJobHandler(e.deps).HandleScan(context.Background(), j.ID); err != nil {
		t.Fatal(err)
	}
	got := e.get(t, j.ID)
	if got.Status != model.JobSucceeded || got.RunID == nil || *got.RunID != 7 || got.Attempts != 1 ||
		got.StartedAt == nil || got.FinishedAt == nil || got.Error != "" {
		t.Fatalf("job = %+v", got)
	}
	calls := e.scan.calls()
	if len(calls) != 1 {
		t.Fatalf("scanner calls = %d", len(calls))
	}
	req := calls[0]
	if len(req.Targets) != 1 || req.Targets[0].Owner != "acme" || req.Targets[0].Branch != "develop" ||
		req.Repo != "acme/api" || req.Trigger != model.TriggerManual || req.TargetIDs[req.Targets[0].String()] != e.tgt.ID {
		t.Fatalf("request = %+v", req)
	}
	msgs := e.messages(t, j.ID)
	if len(msgs) < 2 || !strings.Contains(msgs[0], "started") || !strings.Contains(msgs[len(msgs)-1], "succeeded") {
		t.Fatalf("events = %v", msgs)
	}

	// Redelivery of a finished job is a no-op.
	if err := NewJobHandler(e.deps).HandleScan(context.Background(), j.ID); err != nil {
		t.Fatal(err)
	}
	if len(e.scan.calls()) != 1 {
		t.Fatal("a finished job must not be scanned again")
	}
}

func TestJobHandlerScopes(t *testing.T) {
	e := newWorkerEnv(t)
	h := NewJobHandler(e.deps)
	all := e.job(t, &model.Job{})
	adhoc := e.job(t, &model.Job{Repo: "git@github.com:acme/secret-repo.git", AuthProfile: "pat", Branch: "main"})
	for _, j := range []*model.Job{all, adhoc} {
		if err := h.HandleScan(context.Background(), j.ID); err != nil {
			t.Fatal(err)
		}
	}
	calls := e.scan.calls()
	if len(calls) != 2 {
		t.Fatalf("scanner calls = %d", len(calls))
	}
	if len(calls[0].Targets) != 1 || calls[0].Targets[0].Owner != "acme" || calls[0].TargetIDs["org:acme"] != e.tgt.ID {
		t.Fatalf("all-targets request must hold enabled targets only: %+v", calls[0])
	}
	want := model.Target{Kind: model.TargetRepo, Provider: "github", Owner: "acme", Name: "secret-repo", Branch: "main", Auth: "pat", ListAuth: "pat"}
	if got := calls[1].Targets; len(got) != 1 || fmt.Sprint(got[0]) != fmt.Sprint(want) || got[0].Branch != "main" || got[0].Auth != "pat" {
		t.Fatalf("ad-hoc target = %+v", got)
	}

	bad := e.job(t, &model.Job{Repo: "not a url"})
	if err := h.HandleScan(context.Background(), bad.ID); err != nil {
		t.Fatal(err)
	}
	if got := e.get(t, bad.ID); got.Status != model.JobFailed || got.Error == "" {
		t.Fatalf("bad ad-hoc repo job = %+v", got)
	}
}

func TestJobHandlerFailures(t *testing.T) {
	e := newWorkerEnv(t)
	e.deps.Scanner = nil
	j := e.job(t, &model.Job{TargetID: &e.tgt.ID})
	if err := NewJobHandler(e.deps).HandleScan(context.Background(), j.ID); err != nil {
		t.Fatal(err)
	}
	if got := e.get(t, j.ID); got.Status != model.JobFailed || got.Error != "scanner not wired yet" || got.FinishedAt == nil {
		t.Fatalf("no scanner: %+v", got)
	}

	e = newWorkerEnv(t)
	e.scan.fn = func(context.Context, core.ScanRequest, core.Progress) (*model.ScanRun, error) {
		return nil, errors.New("listing failed")
	}
	j = e.job(t, &model.Job{TargetID: &e.tgt.ID})
	if err := NewJobHandler(e.deps).HandleScan(context.Background(), j.ID); err != nil {
		t.Fatalf("a scan failure is recorded, not retried: %v", err)
	}
	if got := e.get(t, j.ID); got.Status != model.JobFailed || got.Error != "listing failed" {
		t.Fatalf("scan error: %+v", got)
	}

	if err := NewJobHandler(e.deps).HandleScan(context.Background(), 9999); err != nil {
		t.Fatalf("unknown job: %v", err)
	}
}

// blockingScanner waits for ctx, signalling when it started.
func blockingScanner(e *workerEnv) chan struct{} {
	started := make(chan struct{}, 1)
	e.scan.fn = func(ctx context.Context, _ core.ScanRequest, _ core.Progress) (*model.ScanRun, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, fmt.Errorf("scan: %w", ctx.Err())
	}
	return started
}

func TestJobHandlerUserCancel(t *testing.T) {
	e := newWorkerEnv(t)
	started := blockingScanner(e)
	j := e.job(t, &model.Job{TargetID: &e.tgt.ID})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- NewJobHandler(e.deps).HandleScan(ctx, j.ID) }()
	<-started
	// What the Jobs service does: mark canceled, then cancel in the backend.
	cur := e.get(t, j.ID)
	cur.Status = model.JobCanceled
	if err := e.cat.UpdateJob(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("a canceled job must not be retried: %v", err)
	}
	if got := e.get(t, j.ID); got.Status != model.JobCanceled || got.FinishedAt == nil {
		t.Fatalf("job = %+v", got)
	}
}

func TestJobHandlerShutdownRetries(t *testing.T) {
	e := newWorkerEnv(t)
	started := blockingScanner(e)
	j := e.job(t, &model.Job{TargetID: &e.tgt.ID})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- NewJobHandler(e.deps).HandleScan(ctx, j.ID) }()
	<-started
	cancel() // worker shutdown: nothing changed in the catalog
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown must return the ctx error so the backend retries, got %v", err)
	}
	if got := e.get(t, j.ID); got.Status != model.JobRunning || got.Error != "" || got.FinishedAt != nil {
		t.Fatalf("job after shutdown = %+v, want still running", got)
	}

	e.scan.fn = nil // redelivered to a healthy worker
	if err := NewJobHandler(e.deps).HandleScan(context.Background(), j.ID); err != nil {
		t.Fatal(err)
	}
	if got := e.get(t, j.ID); got.Status != model.JobSucceeded || got.Attempts != 2 {
		t.Fatalf("job after retry = %+v", got)
	}
}

func TestJobHandlerTimeout(t *testing.T) {
	e := newWorkerEnv(t)
	blockingScanner(e)
	j := e.job(t, &model.Job{TargetID: &e.tgt.ID})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := NewJobHandler(e.deps).HandleScan(ctx, j.ID); err != nil {
		t.Fatal(err)
	}
	if got := e.get(t, j.ID); got.Status != model.JobFailed || !strings.Contains(got.Error, "timed out") {
		t.Fatalf("job = %+v", got)
	}
}

func TestJobHandlerProgressThrottle(t *testing.T) {
	e := newWorkerEnv(t)
	e.scan.fn = func(_ context.Context, _ core.ScanRequest, p core.Progress) (*model.ScanRun, error) {
		for i := 0; i < 100; i++ {
			p.Event("info", "acme/api", fmt.Sprintf("step %d", i))
		}
		p.Event("warn", "acme/web", "manifest unreadable")
		return &model.ScanRun{ID: 1}, nil
	}
	j := e.job(t, &model.Job{TargetID: &e.tgt.ID})
	if err := NewJobHandler(e.deps).HandleScan(context.Background(), j.ID); err != nil {
		t.Fatal(err)
	}
	msgs := strings.Join(e.messages(t, j.ID), "\n")
	if n := strings.Count(msgs, "step "); n == 0 || n > 10 {
		t.Fatalf("%d step lines written, want throttled:\n%s", n, msgs)
	}
	if !strings.Contains(msgs, "warn: manifest unreadable") || !strings.Contains(msgs, "skipped") {
		t.Fatalf("warnings must not be dropped and skipped lines counted:\n%s", msgs)
	}
}
