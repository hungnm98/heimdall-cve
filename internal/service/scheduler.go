package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/robfig/cron/v3"
)

// Locker is an optional capability of the jobs backend (detected with a type
// assertion on Deps.Jobs): a cluster-wide lock so that one replica at a time
// runs the scheduler. release must be safe to call after the lock expired.
type Locker interface {
	TryLock(ctx context.Context, key string, ttl time.Duration) (release func(), ok bool, err error)
}

// schedulerActor is the audit actor of scheduler writes.
const schedulerActor = "scheduler"

// Scheduler triggers scheduled scans and lifts expired suppressions. Every
// Interval it:
//   - creates and enqueues a job (trigger "schedule") for each due target,
//     then stores the target's next run computed from its cron schedule;
//   - deletes expired suppressions (reopening their findings) and audits it.
//
// Several replicas may run it: with a Locker only one works per tick, and
// without one Catalog.CreateJob still deduplicates jobs.
type Scheduler struct {
	d Deps
	// Interval between ticks (default 1 minute).
	Interval time.Duration
	// Locker elects the replica that works on a tick; nil = no lock.
	Locker Locker
}

// NewScheduler builds a scheduler; Deps.Jobs provides the Locker when it
// implements it.
func NewScheduler(d Deps) *Scheduler {
	s := &Scheduler{d: d, Interval: time.Minute}
	if l, ok := d.Jobs.(Locker); ok {
		s.Locker = l
	}
	return s
}

// NextRun returns the first time after `after` matching a standard cron
// expression (5 fields, descriptors such as @daily or "@every 72h", optional
// CRON_TZ= prefix; UTC otherwise). An empty schedule means manual only: nil.
func NextRun(schedule string, after time.Time) (*time.Time, error) {
	if schedule == "" {
		return nil, nil
	}
	sched, err := cron.ParseStandard(schedule)
	if err != nil {
		return nil, fmt.Errorf("schedule %q: %w", schedule, err)
	}
	next := sched.Next(after.UTC())
	return &next, nil
}

func (s *Scheduler) now() time.Time {
	if s.d.Now != nil {
		return s.d.Now()
	}
	return time.Now()
}

func (s *Scheduler) logger() *slog.Logger {
	if s.d.Logger != nil {
		return s.d.Logger
	}
	return slog.Default()
}

// Run ticks immediately, then every Interval, until ctx is done.
func (s *Scheduler) Run(ctx context.Context) error {
	if s.d.Catalog == nil || s.d.Jobs == nil {
		return errors.New("scheduler needs a catalog store and a jobs backend")
	}
	interval := s.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := s.tick(ctx, interval); err != nil && ctx.Err() == nil {
			s.logger().Warn("scheduler tick", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// tick does one pass. Item failures do not stop the pass; they are joined.
func (s *Scheduler) tick(ctx context.Context, interval time.Duration) error {
	if s.Locker != nil {
		// The TTL outlives a normal pass; if a holder dies, another replica
		// takes over after it.
		release, ok, err := s.Locker.TryLock(ctx, "scheduler", 2*interval)
		if err != nil {
			return fmt.Errorf("scheduler lock: %w", err)
		}
		if !ok {
			return nil // another replica is on it
		}
		defer release()
	}
	now := s.now()
	return errors.Join(s.triggerDue(ctx, now), s.expireSuppressions(ctx, now))
}

func (s *Scheduler) triggerDue(ctx context.Context, now time.Time) error {
	due, err := s.d.Catalog.DueTargets(ctx, now)
	if err != nil {
		return fmt.Errorf("due targets: %w", err)
	}
	var errs []error
	for _, t := range due {
		if err := s.trigger(ctx, t, now); err != nil {
			errs = append(errs, fmt.Errorf("target %d: %w", t.ID, err))
		}
	}
	return errors.Join(errs...)
}

// trigger queues a scan of t and moves its next run forward. If enqueueing
// fails, next_run_at is left alone so the next tick retries: CreateJob then
// returns the same queued job and Enqueue is idempotent by job ID.
func (s *Scheduler) trigger(ctx context.Context, t model.TargetSpec, now time.Time) error {
	id := t.ID
	j := &model.Job{TargetID: &id, Trigger: model.TriggerSchedule, RequestedBy: schedulerActor}
	created, err := s.d.Catalog.CreateJob(ctx, j)
	if err != nil {
		return fmt.Errorf("create job: %w", err)
	}
	if created {
		s.audit(ctx, &model.AuditEntry{Actor: schedulerActor, Action: "job.trigger", ObjectType: "job",
			ObjectID: fmt.Sprint(j.ID), Details: map[string]any{"target_id": t.ID, "trigger": string(model.TriggerSchedule)}})
	}
	if err := s.d.Jobs.Enqueue(ctx, j.ID); err != nil {
		return fmt.Errorf("enqueue job %d: %w", j.ID, err)
	}

	// Re-read so a concurrent edit of the target is not overwritten.
	cur, err := s.d.Catalog.GetTarget(ctx, t.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	next, err := NextRun(cur.Schedule, now)
	if err != nil {
		s.logger().Warn("invalid target schedule: no further scheduled runs", "target_id", t.ID, "err", err)
	}
	cur.NextRunAt = next
	if err := s.d.Catalog.SaveTarget(ctx, cur); err != nil {
		return fmt.Errorf("save next run: %w", err)
	}
	return nil
}

func (s *Scheduler) expireSuppressions(ctx context.Context, now time.Time) error {
	expired, err := s.d.Catalog.ExpiredSuppressions(ctx, now)
	if err != nil {
		return fmt.Errorf("expired suppressions: %w", err)
	}
	var errs []error
	for _, sp := range expired {
		err := s.d.Catalog.DeleteSuppression(ctx, sp.FindingID)
		if errors.Is(err, store.ErrNotFound) {
			continue // lifted meanwhile
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("unsuppress %s: %w", sp.FindingID, err))
			continue
		}
		s.audit(ctx, &model.AuditEntry{Actor: schedulerActor, Action: "finding.unsuppress", ObjectType: "finding",
			ObjectID: sp.FindingID, Details: map[string]any{"cause": "expired", "expires_at": sp.ExpiresAt.UTC().Format(time.RFC3339)}})
	}
	return errors.Join(errs...)
}

// audit records e; a failure is logged (the action itself already happened).
func (s *Scheduler) audit(ctx context.Context, e *model.AuditEntry) {
	if e.At.IsZero() {
		e.At = s.now()
	}
	if err := s.d.Catalog.AppendAudit(ctx, e); err != nil {
		s.logger().Warn("append audit", "action", e.Action, "object", e.ObjectID, "err", err)
	}
}
