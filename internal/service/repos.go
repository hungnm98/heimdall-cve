package service

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

type reposSvc struct{ *base }

func (s *reposSvc) List(ctx context.Context, f store.RepoFilter) (*Page[model.RepoRecord], error) {
	limit := ClampLimit(f.Limit)
	f.Limit = limit + 1
	items, err := s.d.Catalog.ListRepos(ctx, f)
	if err != nil {
		return nil, err
	}
	page := &Page[model.RepoRecord]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = items[limit-1].FullName()
	}
	return page, nil
}

func (s *reposSvc) Get(ctx context.Context, fullName string) (*RepoDetail, error) {
	rec, err := s.d.Catalog.GetRepo(ctx, fullName)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	var open []model.Finding
	err2 := eachFinding(ctx, s.d.Store, store.FindingFilter{Repo: fullName, Status: model.StatusOpen}, func(f model.Finding) {
		open = append(open, f)
	})
	if err2 != nil {
		return nil, err2
	}
	if rec == nil {
		// Not in the cached listing (e.g. an ad-hoc repo scan): show it if it has findings.
		if len(open) == 0 {
			return nil, err
		}
		owner, name, _ := strings.Cut(fullName, "/")
		rec = &model.RepoRecord{Repo: model.Repo{Owner: owner, Name: name, Provider: open[0].Provider}}
	}
	d := &RepoDetail{Record: *rec, Findings: open}
	for _, f := range open {
		if f.Kind == model.KindRuntime && f.Runtime != nil {
			d.Runtimes = append(d.Runtimes, *f.Runtime)
		}
	}
	d.UpgradePlan = upgradePlan(open)
	return d, nil
}

// upgradePlan folds dependency findings into one line per manifest+package,
// worst severity first.
func upgradePlan(findings []model.Finding) []model.UpgradeItem {
	idx := map[string]int{}
	var out []model.UpgradeItem
	for _, f := range findings {
		if f.Kind != model.KindDependency {
			continue
		}
		key := f.ManifestPath + "\x00" + f.Package.Key()
		i, ok := idx[key]
		if !ok {
			idx[key] = len(out)
			out = append(out, model.UpgradeItem{
				Package: f.Package, Manifest: f.ManifestPath, Direct: f.Direct, Severity: f.Severity,
				Recommended: f.RecommendedVersion, Bump: f.Bump, Advice: f.Advice,
			})
			i = len(out) - 1
		}
		it := &out[i]
		if f.AdvisoryID != "" {
			it.Advisories = append(it.Advisories, f.AdvisoryID)
		}
		if f.Severity.Rank() > it.Severity.Rank() {
			it.Severity = f.Severity
		}
		if it.Recommended == "" && f.RecommendedVersion != "" {
			it.Recommended, it.Bump, it.Advice = f.RecommendedVersion, f.Bump, f.Advice
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity.Rank() > out[j].Severity.Rank() })
	return out
}
