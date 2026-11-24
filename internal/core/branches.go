package core

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
)

// plan resolves the targets into repo branches and the commit each points
// to. branchSets maps a repo to its extra branches when the full set is
// known (listing succeeded): findings of other extra branches are closed.
func (p *Pipeline) plan(ctx context.Context, req ScanRequest, prog Progress, run *model.ScanRun) (results []*repoResult, branchSets map[string][]string) {
	branchSets = map[string][]string{}
	for _, r := range p.resolve(ctx, req, prog, run) {
		results = append(results, r)
		extras, complete := p.extraBranches(ctx, r, prog)
		for _, b := range extras {
			repo := r.repo
			repo.Ref = b
			results = append(results, &repoResult{repo: repo, branch: b, target: r.target, prov: r.prov, targetID: r.targetID})
		}
		if complete {
			branchSets[r.repo.FullName()] = extras
		}
	}
	p.parallel(results, func(r *repoResult) {
		sha, err := r.prov.ResolveRef(ctx, r.repo, r.repo.Ref)
		switch {
		case err == nil:
			r.sha = sha
		case r.branch != "" && errors.Is(err, vcs.ErrNotFound):
			r.missing = true
		default:
			r.fail(prog, "resolve %s: %v", r.repo.Ref, err)
		}
	})
	out := results[:0]
	for _, r := range results {
		if !r.missing {
			out = append(out, r)
			continue
		}
		prog.Event("info", r.repo.FullName(), fmt.Sprintf("branch %s does not exist: skipped", r.branch))
		if keep, ok := branchSets[r.repo.FullName()]; ok {
			branchSets[r.repo.FullName()] = without(keep, r.branch)
		}
	}
	if extra := len(out) - countPrimary(out); extra > 0 {
		prog.Event("info", "", fmt.Sprintf("%d extra branches to scan", extra))
	}
	return out, branchSets
}

func countPrimary(rs []*repoResult) int {
	n := 0
	for _, r := range rs {
		if r.branch == "" {
			n++
		}
	}
	return n
}

// extraBranches expands the target's branch names and globs for r, without
// its primary branch, sorted and capped. complete is false when a listing
// needed for a glob failed (the set of branches is then unknown).
func (p *Pipeline) extraBranches(ctx context.Context, r *repoResult, prog Progress) (extras []string, complete bool) {
	pats := r.target.Branches
	if len(pats) == 0 {
		return nil, true
	}
	complete = true
	var listed []string
	if slicesAny(pats, isGlob) {
		bl, ok := r.prov.(vcs.BranchLister)
		var err error
		switch {
		case !ok:
			err = fmt.Errorf("provider %s cannot list branches", r.prov.Name())
		default:
			listed, err = bl.ListBranches(ctx, r.repo)
		}
		if err != nil {
			prog.Event("warn", r.repo.FullName(), fmt.Sprintf("list branches: %v (branch globs skipped)", err))
			complete = false
		}
	}
	set := map[string]bool{}
	for _, pat := range pats {
		if !isGlob(pat) {
			set[pat] = true
			continue
		}
		for _, name := range listed {
			if ok, _ := path.Match(pat, name); ok {
				set[name] = true
			}
		}
	}
	delete(set, r.repo.Ref)
	for b := range set {
		extras = append(extras, b)
	}
	sort.Strings(extras)
	if limit := r.target.BranchCap(); len(extras) > limit {
		prog.Event("warn", r.repo.FullName(), fmt.Sprintf("%d branches match, scanning the first %d (max_branches)", len(extras), limit))
		extras = extras[:limit]
	}
	return extras, complete
}

// changedOnly keeps the branches whose commit differs from their last
// successful scan. Failures are left to full scans (a poll stays quiet).
func (p *Pipeline) changedOnly(ctx context.Context, rs []*repoResult, prog Progress) []*repoResult {
	var out []*repoResult
	for _, r := range rs {
		if r.failed {
			continue
		}
		st, err := p.Store.GetRepoState(ctx, r.repo.FullName(), r.repo.Ref)
		if err == nil && st.HeadSHA == r.sha {
			continue
		}
		prog.Event("info", r.scope(), fmt.Sprintf("%s moved to %.7s", r.repo.Ref, r.sha))
		out = append(out, r)
	}
	return out
}

func isGlob(s string) bool { return strings.ContainsAny(s, "*?[") }

func slicesAny(s []string, f func(string) bool) bool {
	for _, v := range s {
		if f(v) {
			return true
		}
	}
	return false
}

func without(s []string, v string) []string {
	out := make([]string, 0, len(s))
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}
