package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/core"
	"github.com/hungnm98/heimdall-cve/internal/jobs"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// writeTimeout bounds job record writes, which use a ctx detached from the
// job's own (they must land even when the job was canceled).
const writeTimeout = 10 * time.Second

// progressMinGap throttles info progress lines: at most one per gap reaches
// job_events; the skipped ones are counted in the next line. Warnings and
// errors are never dropped.
var progressMinGap = 250 * time.Millisecond

// errJobCanceled means the job was canceled in the catalog meanwhile.
var errJobCanceled = errors.New("job canceled")

// NewJobHandler returns the handler the worker pool runs for each job ID.
//
// It is idempotent: it re-reads the job and does nothing unless it is queued
// or running (a running job is a retry after a crash or shutdown). It marks
// the job running, resolves its scope into a core.ScanRequest, runs the
// scanner with progress streamed to job events and records the outcome.
// A scan error fails the job (no backend retry). A canceled ctx is either a
// user cancel (the job is already canceled in the catalog) or a worker
// shutdown: then the job is left running and the error returned so the
// backend redelivers it.
func NewJobHandler(d Deps) jobs.Handler { return &jobHandler{d: d} }

type jobHandler struct{ d Deps }

func (h *jobHandler) now() time.Time {
	if h.d.Now != nil {
		return h.d.Now()
	}
	return time.Now()
}

func (h *jobHandler) logger() *slog.Logger {
	if h.d.Logger != nil {
		return h.d.Logger
	}
	return slog.Default()
}

func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
}

func (h *jobHandler) HandleScan(ctx context.Context, jobID int64) error {
	cat := h.d.Catalog
	if cat == nil {
		return errors.New("job handler: the store has no catalog")
	}
	j, err := cat.GetJob(ctx, jobID)
	if errors.Is(err, store.ErrNotFound) {
		h.logger().Warn("job not found, dropping it", "job_id", jobID)
		return nil
	}
	if err != nil {
		return fmt.Errorf("load job %d: %w", jobID, err)
	}
	if !j.Status.Active() {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	now := h.now()
	j.Status, j.Attempts, j.Error = model.JobRunning, j.Attempts+1, ""
	if j.StartedAt == nil {
		j.StartedAt = &now
	}
	if err := h.save(ctx, j); err != nil {
		if errors.Is(err, errJobCanceled) {
			return nil
		}
		return err
	}
	h.event(ctx, j.ID, "info", "", fmt.Sprintf("job started (attempt %d)", j.Attempts))

	req, err := h.request(ctx, j)
	switch {
	case err != nil:
		return h.finish(ctx, j, nil, err)
	case len(req.Targets) == 0:
		h.event(ctx, j.ID, "info", "", "no enabled targets: nothing to scan")
		return h.finish(ctx, j, nil, nil)
	case h.d.Scanner == nil:
		return h.finish(ctx, j, nil, errors.New("scanner not wired yet"))
	}

	p := &jobProgress{h: h, ctx: ctx, jobID: j.ID}
	run, err := h.d.Scanner.Scan(ctx, *req, p)
	p.flush()
	if err != nil && ctx.Err() != nil {
		return h.interrupted(ctx, j)
	}
	if errors.Is(err, core.ErrNoChanges) { // a poll with nothing to do succeeds without a run
		err = nil
	}
	return h.finish(ctx, j, run, err)
}

// request resolves the job scope: one target (optionally one repo of it), an
// ad-hoc repo URL, or every enabled target.
func (h *jobHandler) request(ctx context.Context, j *model.Job) (*core.ScanRequest, error) {
	req := &core.ScanRequest{Trigger: j.Trigger, TargetIDs: map[string]int64{}, Force: j.Force,
		OnlyChanged: j.Trigger == model.TriggerPoll}
	switch {
	case j.TargetID != nil:
		t, err := h.d.Catalog.GetTarget(ctx, *j.TargetID)
		if err != nil {
			return nil, fmt.Errorf("target %d: %w", *j.TargetID, err)
		}
		tg := t.Target
		if j.Branch != "" {
			// A one-off branch is scanned as an extra branch: the primary
			// branch keeps its findings, the configured extras stay.
			tg.Branches = append(append([]string(nil), tg.Branches...), j.Branch)
		}
		req.Targets, req.Repo = []model.Target{tg}, j.Repo
		req.TargetIDs[tg.String()] = t.ID
	case j.Repo != "":
		// Ad-hoc repo: Repo is "owner/name" (Jobs.Trigger), BaseURL the API of
		// its host ("" = github.com).
		owner, name, ok := strings.Cut(j.Repo, "/")
		if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
			return nil, fmt.Errorf("ad-hoc repo job: repo %q is not owner/name", j.Repo)
		}
		req.Targets = []model.Target{{
			Kind: model.TargetRepo, Provider: "github", BaseURL: j.BaseURL, Owner: owner, Name: name,
			Branch: j.Branch, Auth: j.AuthProfile, ListAuth: j.AuthProfile,
		}}
	default:
		enabled := true
		ts, err := h.d.Catalog.ListTargets(ctx, store.TargetFilter{Enabled: &enabled})
		if err != nil {
			return nil, fmt.Errorf("list targets: %w", err)
		}
		for _, t := range ts {
			req.Targets = append(req.Targets, t.Target)
			req.TargetIDs[t.Target.String()] = t.ID
		}
	}
	return req, nil
}

// interrupted handles a scan stopped by its ctx.
func (h *jobHandler) interrupted(ctx context.Context, j *model.Job) error {
	wctx, cancel := detached(ctx)
	defer cancel()
	cur, err := h.d.Catalog.GetJob(wctx, j.ID)
	if err == nil && cur.Status == model.JobCanceled {
		h.event(ctx, j.ID, "warn", "", "job canceled")
		if cur.FinishedAt == nil {
			now := h.now()
			cur.FinishedAt = &now
			if err := h.d.Catalog.UpdateJob(wctx, cur); err != nil {
				return fmt.Errorf("record cancel of job %d: %w", j.ID, err)
			}
		}
		return nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return h.finish(ctx, j, nil, errors.New("job timed out"))
	}
	// Worker shutdown: keep the job running and let the backend redeliver it.
	h.event(ctx, j.ID, "warn", "", "worker stopped: the job will be retried")
	return ctx.Err()
}

// finish records the outcome. The event goes first so a client following
// events until the job is terminal sees it.
func (h *jobHandler) finish(ctx context.Context, j *model.Job, run *model.ScanRun, scanErr error) error {
	now := h.now()
	j.FinishedAt = &now
	if scanErr != nil {
		j.Status, j.Error = model.JobFailed, scanErr.Error()
		h.event(ctx, j.ID, "error", "", "job failed: "+j.Error)
	} else {
		j.Status = model.JobSucceeded
		msg := "job succeeded"
		if run != nil {
			j.RunID = &run.ID
			msg = fmt.Sprintf("job succeeded: run %d", run.ID)
		}
		h.event(ctx, j.ID, "info", "", msg)
	}
	if err := h.save(ctx, j); err != nil && !errors.Is(err, errJobCanceled) {
		return err
	}
	return nil
}

// save writes j unless the job was canceled in the catalog meanwhile (the
// catalog has no conditional update; this narrows the race to one round trip).
func (h *jobHandler) save(ctx context.Context, j *model.Job) error {
	wctx, cancel := detached(ctx)
	defer cancel()
	cur, err := h.d.Catalog.GetJob(wctx, j.ID)
	if err != nil {
		return fmt.Errorf("save job %d: %w", j.ID, err)
	}
	if cur.Status == model.JobCanceled && j.Status != model.JobCanceled {
		return errJobCanceled
	}
	if err := h.d.Catalog.UpdateJob(wctx, j); err != nil {
		return fmt.Errorf("save job %d: %w", j.ID, err)
	}
	return nil
}

// event appends a job event; failures are logged, never fatal to the job.
func (h *jobHandler) event(ctx context.Context, jobID int64, level, repo, msg string) {
	wctx, cancel := detached(ctx)
	defer cancel()
	e := &model.JobEvent{JobID: jobID, At: h.now(), Level: level, Repo: repo, Message: msg}
	if err := h.d.Catalog.AppendJobEvent(wctx, e); err != nil {
		h.logger().Warn("append job event", "job_id", jobID, "err", err)
	}
}

// jobProgress turns scanner progress into job events, throttling info lines.
type jobProgress struct {
	h       *jobHandler
	ctx     context.Context
	jobID   int64
	mu      sync.Mutex
	last    time.Time
	skipped int
}

func (p *jobProgress) Event(level, repo, msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if level == "info" && now.Sub(p.last) < progressMinGap {
		p.skipped++
		return
	}
	if p.skipped > 0 {
		msg = fmt.Sprintf("%s (+%d progress lines skipped)", msg, p.skipped)
		p.skipped = 0
	}
	p.last = now
	p.h.event(p.ctx, p.jobID, level, repo, msg)
}

func (p *jobProgress) flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.skipped > 0 {
		p.h.event(p.ctx, p.jobID, "info", "", fmt.Sprintf("%d progress lines skipped", p.skipped))
		p.skipped = 0
	}
}
