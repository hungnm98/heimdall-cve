package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/jobs"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

type jobsSvc struct{ *base }

func (s *jobsSvc) Trigger(ctx context.Context, actor Actor, req JobRequest) (*model.Job, bool, error) {
	if s.d.Jobs == nil {
		return nil, false, fmt.Errorf("no job backend: %w", ErrUnavailable)
	}
	j := &model.Job{
		Branch: strings.TrimSpace(req.Branch), Trigger: req.Trigger,
		Status: model.JobQueued, RequestedBy: actorName(actor),
	}
	if j.Trigger == "" {
		j.Trigger = model.TriggerManual
	}
	repo := strings.TrimSpace(req.Repo)
	switch {
	case req.TargetID != nil && req.RepoURL != "":
		return nil, false, invalid("repo_url", "give either target_id or repo_url, not both")
	case req.TargetID != nil:
		if repo != "" && !repoNamePattern.MatchString(repo) {
			return nil, false, invalid("repo", "must be owner/name")
		}
		if _, err := s.d.Catalog.GetTarget(ctx, *req.TargetID); err != nil {
			return nil, false, err
		}
		id := *req.TargetID
		j.TargetID, j.Repo = &id, repo
	case req.RepoURL != "":
		fe := fieldErrors{}
		u, err := model.ParseRepoURL(req.RepoURL)
		if err != nil {
			fe.add("repo_url", err.Error())
		}
		if req.AuthProfile == "" {
			fe.add("auth_profile", "required with repo_url")
		} else if _, err := s.d.Catalog.GetAuthProfile(ctx, req.AuthProfile); err != nil {
			if !errors.Is(err, ErrNotFound) {
				return nil, false, err
			}
			fe.add("auth_profile", "unknown auth profile")
		}
		if err := fe.err(); err != nil {
			return nil, false, err
		}
		j.Repo, j.AuthProfile = u.Owner+"/"+u.Name, req.AuthProfile
	default:
		if repo != "" {
			return nil, false, invalid("repo", "repo needs target_id")
		}
	}
	created, err := s.d.Catalog.CreateJob(ctx, j)
	if err != nil {
		return nil, false, err
	}
	if !created {
		return j, false, nil
	}
	details := map[string]any{"repo": j.Repo, "branch": j.Branch, "trigger": string(j.Trigger), "force": req.Force}
	if j.TargetID != nil {
		details["target_id"] = *j.TargetID
	}
	if j.AuthProfile != "" {
		details["auth_profile"] = j.AuthProfile
	}
	s.audit(ctx, actor, "job.trigger", "job", itoa(j.ID), details)
	if err := s.d.Jobs.Enqueue(ctx, j.ID); err != nil {
		// Do not leave an active job nobody will run: it would block the scope.
		now := s.now()
		j.Status, j.Error, j.FinishedAt = model.JobFailed, "enqueue failed: "+err.Error(), &now
		if uerr := s.d.Catalog.UpdateJob(context.WithoutCancel(ctx), j); uerr != nil {
			s.d.Logger.Error("mark job failed", "job_id", j.ID, "err", uerr)
		}
		return nil, false, fmt.Errorf("enqueue job %d: %w", j.ID, err)
	}
	return j, true, nil
}

func (s *jobsSvc) List(ctx context.Context, f store.JobFilter) (*Page[model.Job], error) {
	limit := ClampLimit(f.Limit)
	f.Limit = limit + 1
	items, err := s.d.Catalog.ListJobs(ctx, f)
	if err != nil {
		return nil, err
	}
	page := &Page[model.Job]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = itoa(items[limit-1].ID)
	}
	return page, nil
}

func (s *jobsSvc) Get(ctx context.Context, id int64) (*model.Job, error) {
	return s.d.Catalog.GetJob(ctx, id)
}

func (s *jobsSvc) Cancel(ctx context.Context, actor Actor, id int64) error {
	j, err := s.d.Catalog.GetJob(ctx, id)
	if err != nil {
		return err
	}
	if !j.Status.Active() {
		return fmt.Errorf("job %d already %s: %w", id, j.Status, ErrConflict)
	}
	now := s.now()
	j.Status, j.FinishedAt = model.JobCanceled, &now
	if err := s.d.Catalog.UpdateJob(ctx, j); err != nil {
		return err
	}
	if s.d.Jobs != nil {
		if err := s.d.Jobs.Cancel(ctx, id); err != nil && !errors.Is(err, jobs.ErrNotFound) {
			s.d.Logger.Warn("cancel job in backend", "job_id", id, "err", err)
		}
	}
	ev := &model.JobEvent{JobID: id, At: now, Level: "warn", Message: "canceled by " + actorName(actor)}
	if err := s.d.Catalog.AppendJobEvent(ctx, ev); err != nil {
		s.d.Logger.Warn("append cancel event", "job_id", id, "err", err)
	}
	s.audit(ctx, actor, "job.cancel", "job", itoa(id), nil)
	return nil
}

func (s *jobsSvc) Events(ctx context.Context, id, afterID int64, limit int) ([]model.JobEvent, error) {
	if _, err := s.d.Catalog.GetJob(ctx, id); err != nil {
		return nil, err
	}
	return s.d.Catalog.ListJobEvents(ctx, id, afterID, ClampLimit(limit))
}
