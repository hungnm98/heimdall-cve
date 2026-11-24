package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/core"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// branchGitHub serves one repo (acme/web) with several branches; each
// branch points to a commit whose files live in commits.
type branchGitHub struct {
	mu       sync.Mutex
	branches map[string]string            // branch → sha
	commits  map[string]map[string]string // sha → path → content
	trees    atomic.Int32                 // tree listings (one per commit actually read)
}

func (g *branchGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := strings.Trim(r.URL.EscapedPath(), "/")
	switch {
	case p == "orgs/acme/repos":
		_ = json.NewEncoder(w).Encode([]map[string]any{{"name": "web", "owner": map[string]string{"login": "acme"},
			"default_branch": "main", "size": 10, "html_url": "https://github.com/acme/web"}})
	case p == "repos/acme/web/branches":
		var out []map[string]string
		for b := range g.branches {
			out = append(out, map[string]string{"name": b})
		}
		sort.Slice(out, func(i, j int) bool { return out[i]["name"] < out[j]["name"] })
		_ = json.NewEncoder(w).Encode(out)
	case strings.HasPrefix(p, "repos/acme/web/commits/"):
		ref, _ := url.PathUnescape(strings.TrimPrefix(p, "repos/acme/web/commits/"))
		sha, ok := g.branches[ref]
		if !ok {
			http.Error(w, `{"message":"No commit found"}`, http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, sha)
	case strings.HasPrefix(p, "repos/acme/web/git/trees/"):
		g.trees.Add(1)
		var tree []map[string]string
		for path := range g.commits[strings.TrimPrefix(p, "repos/acme/web/git/trees/")] {
			tree = append(tree, map[string]string{"path": path, "type": "blob"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tree": tree, "truncated": false})
	case strings.HasPrefix(p, "repos/acme/web/contents/"):
		path, _ := url.PathUnescape(strings.TrimPrefix(p, "repos/acme/web/contents/"))
		c, ok := g.commits[r.URL.Query().Get("ref")][path]
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, c)
	default:
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	}
}

func npmFiles(lodash string) map[string]string {
	return map[string]string{
		"package.json": `{"name":"web","dependencies":{"lodash":"` + lodash + `"}}`,
		"package-lock.json": `{"name":"web","lockfileVersion":3,"requires":true,"packages":{
			"":{"name":"web","dependencies":{"lodash":"` + lodash + `"}},
			"node_modules/lodash":{"version":"` + lodash + `"}}}`,
	}
}

// TestEndToEndBranches: extra branches (names and globs) are scanned with
// their own findings, the primary branch keeps its finding IDs, unchanged
// commits are not read again, removed branches close their findings, and a
// poll only scans what moved.
func TestEndToEndBranches(t *testing.T) {
	sha := func(c byte) string { return strings.Repeat(string(c), 40) }
	gh := &branchGitHub{
		branches: map[string]string{"main": sha('a'), "release/1.0": sha('a'), "develop": sha('d'), "feature/x": sha('f')},
		commits:  map[string]map[string]string{sha('a'): npmFiles("4.17.15"), sha('d'): npmFiles("4.17.15"), sha('f'): npmFiles("4.17.15")},
	}
	ghSrv := httptest.NewServer(gh)
	defer ghSrv.Close()
	osvSrv := httptest.NewServer(fakeOSV(t))
	defer osvSrv.Close()
	t.Setenv("TEST_GH_TOKEN", "test-token")
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "heimdall.yaml")
	if err := os.WriteFile(cfgFile, []byte(fmt.Sprintf(`
auth_profiles: { pat: { type: token, token_env: TEST_GH_TOKEN } }
targets: [ { kind: org, name: acme, auth: pat, base_url: %q, branches: ["release/*", develop, gone] } ]
sources: { osv: { base_url: %q } }
store: { type: memory }
report: { formats: [] }
cache: { dir: %q }
workspace: { dir: %q }
`, ghSrv.URL, osvSrv.URL, filepath.Join(dir, "cache"), filepath.Join(dir, "ws"))), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx := context.Background()
	p := a.Pipeline(nil, a.ConfigProviderFor)
	scan := func(req core.ScanRequest) (*model.ScanRun, error) {
		t.Helper()
		req.Targets = a.Targets
		return p.Scan(ctx, req, nil)
	}
	open := func() map[string]model.Finding {
		t.Helper()
		fs, err := a.Store.ListFindings(ctx, store.FindingFilter{Status: model.StatusOpen, Kind: model.KindDependency})
		if err != nil {
			t.Fatal(err)
		}
		by := map[string]model.Finding{}
		for _, f := range fs {
			if f.Package.Name == "lodash" {
				by[f.Branch] = f // one lodash advisory group per branch is enough here
			}
		}
		return by
	}

	run, err := scan(core.ScanRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(run.ReposScanned, ","); got != "acme/web,acme/web@develop,acme/web@release/1.0" {
		t.Fatalf("scanned %s; want the primary branch, develop and release/1.0 (missing 'gone' and unmatched feature/x skipped)", got)
	}
	byBranch := open()
	if len(byBranch) != 3 {
		t.Fatalf("lodash findings per branch = %v; want primary, develop, release/1.0", branchKeys(byBranch))
	}
	primary := byBranch[""]
	base := primary
	base.ComputeID()
	if primary.ID != base.ID || byBranch["develop"].ID == primary.ID {
		t.Fatalf("primary-branch IDs must not change and branch IDs must differ: %s %s", primary.ID, byBranch["develop"].ID)
	}
	treesAfterFirst := gh.trees.Load()

	// Unchanged commits: manifests come from the snapshots.
	if _, err := scan(core.ScanRequest{}); err != nil {
		t.Fatal(err)
	}
	if gh.trees.Load() != treesAfterFirst {
		t.Fatalf("unchanged commits were listed again: %d → %d tree calls", treesAfterFirst, gh.trees.Load())
	}
	// Force re-reads.
	if _, err := scan(core.ScanRequest{Force: true}); err != nil {
		t.Fatal(err)
	}
	if gh.trees.Load() == treesAfterFirst {
		t.Fatal("Force must bypass commit snapshots")
	}

	// A poll with nothing moved records no run.
	if _, err := scan(core.ScanRequest{OnlyChanged: true}); !errors.Is(err, core.ErrNoChanges) {
		t.Fatalf("poll without changes: err = %v, want ErrNoChanges", err)
	}
	// develop moves and fixes lodash: the poll scans only develop.
	gh.mu.Lock()
	gh.commits[sha('e')] = npmFiles("4.17.21")
	gh.branches["develop"] = sha('e')
	gh.mu.Unlock()
	run, err = scan(core.ScanRequest{OnlyChanged: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(run.ReposScanned, ","); got != "acme/web@develop" {
		t.Fatalf("poll scanned %s; want only acme/web@develop", got)
	}
	if byBranch = open(); len(byBranch) != 2 || byBranch["develop"].ID != "" {
		t.Fatalf("develop is fixed, others stay open: %v", branchKeys(byBranch))
	}

	// release/1.0 is deleted: its findings are closed as removed, not fixed.
	gh.mu.Lock()
	delete(gh.branches, "release/1.0")
	gh.mu.Unlock()
	if _, err := scan(core.ScanRequest{}); err != nil {
		t.Fatal(err)
	}
	if byBranch = open(); len(byBranch) != 1 || byBranch[""].ID == "" {
		t.Fatalf("only the primary branch stays open: %v", branchKeys(byBranch))
	}
	removed, _ := a.Store.ListFindings(ctx, store.FindingFilter{Status: model.StatusRemoved})
	if len(removed) == 0 || removed[0].Branch != "release/1.0" {
		t.Fatalf("release/1.0 findings must be removed: %+v", removed)
	}
}

func branchKeys(m map[string]model.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
