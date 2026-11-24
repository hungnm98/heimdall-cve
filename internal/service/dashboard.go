package service

import (
	"context"
	"errors"
	"sort"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// TopFindings is how many open findings the dashboard lists.
const TopFindings = 10

type dashboardSvc struct{ *base }

// Summary walks open findings page by page. The store port has no aggregate
// query, so this is O(open findings) per call; a store-side count would make it O(1).
func (s *dashboardSvc) Summary(ctx context.Context, trendRuns int) (*DashboardSummary, error) {
	switch {
	case trendRuns <= 0:
		trendRuns = 30
	case trendRuns > 90:
		trendRuns = 90
	}
	sum := &DashboardSummary{OpenBySeverity: map[model.Severity]int{}}
	for _, sev := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityUnknown} {
		sum.OpenBySeverity[sev] = 0
	}
	err := eachFinding(ctx, s.d.Store, store.FindingFilter{Status: model.StatusOpen, DefaultBranchOnly: true}, func(f model.Finding) {
		sev := f.Severity
		if sev == "" {
			sev = model.SeverityUnknown
		}
		sum.OpenBySeverity[sev]++
		if f.InKEV {
			sum.OpenKEV++
		}
		if f.Malicious {
			sum.OpenMalicious++
		}
		if f.Kind == model.KindRuntime && f.Runtime != nil &&
			(f.Runtime.Status == model.SupportEOL || f.Runtime.Status == model.SupportEOLSoon) {
			sum.EOLRuntimes = append(sum.EOLRuntimes, *f.Runtime)
		}
		sum.TopFindings = pushTop(sum.TopFindings, f)
	})
	if err != nil {
		return nil, err
	}

	if sum.Repos, err = s.countRepos(ctx); err != nil {
		return nil, err
	}

	runs, err := s.d.Store.ListRuns(ctx, trendRuns)
	if err != nil {
		return nil, err
	}
	for i := len(runs) - 1; i >= 0; i-- { // oldest first
		if runs[i].Status != model.RunRunning {
			sum.Trend = append(sum.Trend, runs[i])
		}
	}
	last, err := s.d.Store.LatestRun(ctx, 0)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if last != nil {
		sum.LastRun = last
		for _, h := range last.Sources {
			if !h.Healthy {
				sum.UnhealthySources = append(sum.UnhealthySources, h)
			}
		}
	}

	for _, st := range []model.JobStatus{model.JobRunning, model.JobQueued} {
		js, err := s.d.Catalog.ListJobs(ctx, store.JobFilter{Status: st, Limit: 50})
		if err != nil {
			return nil, err
		}
		sum.ActiveJobs = append(sum.ActiveJobs, js...)
	}
	return sum, nil
}

func (s *dashboardSvc) countRepos(ctx context.Context) (int, error) {
	const pageSize = 1000
	n, after := 0, ""
	for {
		rs, err := s.d.Catalog.ListRepos(ctx, store.RepoFilter{After: after, Limit: pageSize})
		if err != nil {
			return 0, err
		}
		n += len(rs)
		if len(rs) < pageSize {
			return n, nil
		}
		after = rs[len(rs)-1].FullName()
	}
}

// pushTop keeps the TopFindings highest-priority findings (priority, then severity).
func pushTop(top []model.Finding, f model.Finding) []model.Finding {
	less := func(a, b model.Finding) bool { // a ranks above b
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		return a.Severity.Rank() > b.Severity.Rank()
	}
	if len(top) == TopFindings && !less(f, top[len(top)-1]) {
		return top
	}
	i := sort.Search(len(top), func(i int) bool { return less(f, top[i]) })
	top = append(top, model.Finding{})
	copy(top[i+1:], top[i:])
	top[i] = f
	if len(top) > TopFindings {
		top = top[:TopFindings]
	}
	return top
}
