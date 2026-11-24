package github

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/vcs"
)

const (
	// usedMarker in a mirror is touched whenever the mirror is opened.
	usedMarker = "heimdall-last-used"
	// pruneMarker at the workspace root records the last prune.
	pruneMarker = ".last-prune"
	// pruneEvery rate-limits Prune: walking every mirror and git gc are not free.
	pruneEvery = 24 * time.Hour
)

var _ vcs.Pruner = (*Provider)(nil)

// Prune implements vcs.Pruner, at most once per pruneEvery per workspace:
//   - mirrors not opened since unusedSince are deleted (a later scan clones
//     them again);
//   - in the others, fetched commits and branches whose commit is older than
//     unusedSince are dropped and `git gc` reclaims their objects. Commits
//     still needed are fetched again (shallow, without blobs) when read.
func (p *Provider) Prune(ctx context.Context, unusedSince time.Time) (vcs.PruneResult, error) {
	var res vcs.PruneResult
	marker := filepath.Join(p.ws, pruneMarker)
	if fi, err := os.Stat(marker); err == nil && time.Since(fi.ModTime()) < pruneEvery {
		return res, nil
	}
	if err := os.MkdirAll(p.ws, 0o700); err != nil {
		return res, fmt.Errorf("github: %w", err)
	}
	touch(marker)
	var mirrors []string
	// Layout: <ws>/<host>/<owner>/<name>.git
	err := filepath.WalkDir(p.ws, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() || path == p.ws {
			return err
		}
		rel, _ := filepath.Rel(p.ws, path)
		depth := strings.Count(rel, string(filepath.Separator)) + 1
		switch {
		case strings.HasPrefix(d.Name(), "."): // .tmp (auth configs)
			return filepath.SkipDir
		case depth == 3 && (strings.HasSuffix(path, ".git") || strings.HasSuffix(path, ".git.init")):
			mirrors = append(mirrors, path)
			return filepath.SkipDir
		case depth >= 3:
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return res, fmt.Errorf("github: prune %s: %w", p.ws, err)
	}
	var errs []string
	for _, dir := range mirrors {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		removed, refs, err := p.pruneMirror(ctx, dir, unusedSince)
		if err != nil {
			errs = append(errs, err.Error())
		}
		if removed {
			res.Mirrors++
		}
		res.Refs += refs
	}
	if len(errs) > 0 {
		return res, fmt.Errorf("github: prune: %s", strings.Join(errs, "; "))
	}
	return res, nil
}

func (p *Provider) pruneMirror(ctx context.Context, dir string, unusedSince time.Time) (removed bool, refs int, err error) {
	unlock := p.lock(dir)
	defer unlock()
	if strings.HasSuffix(dir, ".init") { // an interrupted clone
		return false, 0, os.RemoveAll(dir)
	}
	last := lastUsed(dir)
	if last.Before(unusedSince) {
		if err := os.RemoveAll(dir); err != nil {
			return false, 0, fmt.Errorf("remove %s: %w", dir, err)
		}
		return true, 0, nil
	}
	out, err := p.git.Run(ctx, dir, nil, "for-each-ref", "--format=%(committerdate:unix) %(refname)", commitRefPrefix, "refs/heads/")
	if err != nil {
		return false, 0, err
	}
	var del strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		ts, ref, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		if sec, err := strconv.ParseInt(ts, 10, 64); err == nil && time.Unix(sec, 0).Before(unusedSince) {
			fmt.Fprintf(&del, "delete %s\n", ref)
			refs++
		}
	}
	if refs == 0 {
		return false, 0, nil
	}
	if _, err := p.git.RunInput(ctx, dir, nil, strings.NewReader(del.String()), "update-ref", "--stdin"); err != nil {
		return false, 0, err
	}
	// Objects younger than an hour are kept: another process may be
	// fetching into this mirror right now.
	if _, err := p.git.Run(ctx, dir, nil, "gc", "--quiet", "--prune=1.hour.ago"); err != nil {
		return false, refs, err
	}
	return false, refs, nil
}

// lastUsed is when the mirror was last opened (its creation for mirrors that
// predate the marker).
func lastUsed(dir string) time.Time {
	for _, f := range []string{usedMarker, "HEAD"} {
		if fi, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return fi.ModTime()
		}
	}
	return time.Time{}
}

// touch creates f or bumps its mtime; failures only make pruning earlier.
func touch(f string) {
	now := time.Now()
	if err := os.Chtimes(f, now, now); err != nil {
		_ = os.WriteFile(f, nil, 0o600)
	}
}
