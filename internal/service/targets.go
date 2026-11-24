package service

import (
	"context"
	"errors"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/robfig/cron/v3"
)

// loginPattern is a GitHub-style org/user login.
var loginPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$`)

// repoNamePattern is "owner/name".
var repoNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)

// nextRunFor is NextRun (scheduler.go) for a target: nil when it is disabled
// or manual. Schedules are parsed the same way here and in the scheduler.
func nextRunFor(schedule string, enabled bool, now time.Time) (*time.Time, error) {
	if !enabled {
		return nil, nil
	}
	return NextRun(schedule, now)
}

// scheduleTarget sets the next scheduled scan and the next poll of t.
func scheduleTarget(t *model.TargetSpec, now time.Time) error {
	var err error
	if t.NextRunAt, err = nextRunFor(t.Schedule, t.Enabled, now); err != nil {
		return invalid("schedule", err.Error())
	}
	if t.NextPollAt, err = nextRunFor(t.Poll, t.Enabled, now); err != nil {
		return invalid("poll", err.Error())
	}
	return nil
}

type targetsSvc struct{ *base }

func (s *targetsSvc) List(ctx context.Context) ([]model.TargetSpec, error) {
	return s.d.Catalog.ListTargets(ctx, store.TargetFilter{})
}

func (s *targetsSvc) Get(ctx context.Context, id int64) (*model.TargetSpec, error) {
	return s.d.Catalog.GetTarget(ctx, id)
}

func (s *targetsSvc) Create(ctx context.Context, actor Actor, in TargetInput) (*model.TargetSpec, error) {
	t, err := s.validate(ctx, in)
	if err != nil {
		return nil, err
	}
	spec := &model.TargetSpec{Target: t, Schedule: in.Schedule, Poll: in.Poll, Enabled: in.Enabled, Origin: model.OriginUI}
	if err := scheduleTarget(spec, s.now()); err != nil {
		return nil, err
	}
	if err := s.d.Catalog.SaveTarget(ctx, spec); err != nil {
		return nil, err
	}
	s.audit(ctx, actor, "target.create", "target", itoa(spec.ID), targetDetails(spec))
	return spec, nil
}

func (s *targetsSvc) Update(ctx context.Context, actor Actor, id int64, in TargetInput) (*model.TargetSpec, error) {
	spec, err := s.d.Catalog.GetTarget(ctx, id)
	if err != nil {
		return nil, err
	}
	if spec.Origin == model.OriginConfig {
		return nil, ErrReadOnly
	}
	t, err := s.validate(ctx, in)
	if err != nil {
		return nil, err
	}
	spec.Target, spec.Schedule, spec.Poll, spec.Enabled = t, in.Schedule, in.Poll, in.Enabled
	if err := scheduleTarget(spec, s.now()); err != nil {
		return nil, err
	}
	if err := s.d.Catalog.SaveTarget(ctx, spec); err != nil {
		return nil, err
	}
	s.audit(ctx, actor, "target.update", "target", itoa(spec.ID), targetDetails(spec))
	return spec, nil
}

func (s *targetsSvc) Delete(ctx context.Context, actor Actor, id int64) error {
	spec, err := s.d.Catalog.GetTarget(ctx, id)
	if err != nil {
		return err
	}
	if spec.Origin == model.OriginConfig {
		return ErrReadOnly
	}
	if err := s.d.Catalog.DeleteTarget(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, actor, "target.delete", "target", itoa(id), map[string]any{"label": spec.String()})
	return nil
}

func (s *targetsSvc) Preview(ctx context.Context, in TargetInput) ([]model.Repo, error) {
	t, err := s.validate(ctx, in)
	if err != nil {
		return nil, err
	}
	if s.d.ProviderFor == nil {
		return nil, ErrUnavailable
	}
	p, err := s.d.ProviderFor(ctx, t)
	if err != nil {
		return nil, &UpstreamError{Err: err}
	}
	repos, err := p.ListRepos(ctx, t)
	if err != nil {
		return nil, &UpstreamError{Err: err}
	}
	return repos, nil
}

// validate checks in and turns it into a model.Target.
func (s *targetsSvc) validate(ctx context.Context, in TargetInput) (model.Target, error) {
	fe := fieldErrors{}
	t := model.Target{
		Kind:        in.Kind,
		Provider:    strings.TrimSpace(in.Provider),
		BaseURL:     strings.TrimSpace(in.BaseURL),
		Branch:      strings.TrimSpace(in.Branch),
		Auth:        strings.TrimSpace(in.Auth),
		ListAuth:    strings.TrimSpace(in.ListAuth),
		Repos:       in.Repos,
		Filter:      in.Filter,
		MaxBranches: in.MaxBranches,
	}
	for _, b := range in.Branches {
		if b = strings.TrimSpace(b); b != "" {
			t.Branches = append(t.Branches, b)
		}
	}
	if t.Provider == "" {
		t.Provider = "github"
	}
	switch in.Kind {
	case model.TargetOrg, model.TargetUser:
		t.Owner = strings.TrimSpace(in.Owner)
		if !loginPattern.MatchString(t.Owner) {
			fe.add("owner", "a valid org or user login is required")
		}
		for _, r := range t.Repos {
			if strings.TrimSpace(r) == "" || strings.Contains(r, "/") {
				fe.add("repos", "static repos are plain repo names of the owner")
			}
		}
	case model.TargetRepo:
		u, err := model.ParseRepoURL(in.URL)
		if err != nil {
			fe.add("url", err.Error())
			break
		}
		t.Owner, t.Name, t.Repos = u.Owner, u.Name, nil
		if !strings.EqualFold(u.Host, "github.com") && t.BaseURL == "" {
			fe.add("base_url", "base_url is required for hosts other than github.com")
		}
	default:
		fe.add("kind", "must be org, user or repo")
	}
	for _, g := range append(append([]string{}, t.Filter.Include...), t.Filter.Exclude...) {
		if _, err := path.Match(g, ""); err != nil {
			fe.add("filter", "invalid glob "+g)
		}
	}
	for _, g := range t.Branches {
		if _, err := path.Match(g, ""); err != nil {
			fe.add("branches", "invalid glob "+g)
		}
	}
	if t.MaxBranches < 0 {
		fe.add("max_branches", "must be >= 0")
	}
	if in.Poll != "" {
		if _, err := cron.ParseStandard(in.Poll); err != nil {
			fe.add("poll", "invalid cron expression: "+err.Error())
		}
	}
	if t.Filter.MaxRepos < 0 {
		fe.add("filter", "max_repos must be >= 0")
	}
	if in.Schedule != "" {
		if _, err := cron.ParseStandard(in.Schedule); err != nil {
			fe.add("schedule", "invalid cron expression: "+err.Error())
		}
	}
	var authType string
	if t.Auth == "" {
		fe.add("auth", "an auth profile is required")
	} else if p, err := s.d.Catalog.GetAuthProfile(ctx, t.Auth); err != nil {
		if !errors.Is(err, ErrNotFound) {
			return model.Target{}, err
		}
		fe.add("auth", "unknown auth profile")
	} else {
		authType = p.Type
	}
	if t.ListAuth != "" && t.ListAuth != t.Auth {
		if _, err := s.d.Catalog.GetAuthProfile(ctx, t.ListAuth); err != nil {
			if !errors.Is(err, ErrNotFound) {
				return model.Target{}, err
			}
			fe.add("list_auth", "unknown auth profile")
		}
	}
	if t.ListAuth == "" {
		if authType == "ssh" && t.Kind != model.TargetRepo && len(t.Repos) == 0 {
			fe.add("list_auth", "required when auth is ssh: SSH cannot list repos (or set static repos)")
		}
		t.ListAuth = t.Auth
	}
	return t, fe.err()
}

func targetDetails(t *model.TargetSpec) map[string]any {
	return map[string]any{
		"label": t.String(), "provider": t.Provider, "auth": t.Auth, "list_auth": t.ListAuth,
		"branch": t.Branch, "branches": t.Branches, "max_branches": t.MaxBranches,
		"schedule": t.Schedule, "poll": t.Poll, "enabled": t.Enabled,
	}
}
