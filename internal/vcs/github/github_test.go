package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/gitx"
	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
	"github.com/hungnm98/heimdall-cve/internal/vcs/vcstest"
)

const testToken = "tok-secret-123"

type tokenCreds struct{ method string }

func (c tokenCreds) Method() string { return c.method }
func (tokenCreds) Token(context.Context, string) (string, error) {
	return testToken, nil
}

type sshCreds struct{}

func (sshCreds) Method() string { return "ssh" }
func (sshCreds) SSH() gitx.SSH  { return gitx.SSH{} }

var wantFiles = map[string]string{
	"go.mod":    "module example.com/api\n\ngo 1.22\n",
	"sub/a.txt": "two\n",
}

func needGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	args = append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)
	out, err := gitx.Runner{}.Run(context.Background(), dir, nil, args...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// makeRepo creates a repo at dir: main (2 commits, annotated tag v1) and dev.
// It allows partial clone and fetching by SHA, like GitHub.
func makeRepo(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "init", "-q", "-b", "main")
	git(t, dir, "config", "uploadpack.allowFilter", "true")
	git(t, dir, "config", "uploadpack.allowAnySHA1InWant", "true")
	write(t, dir, "go.mod", wantFiles["go.mod"])
	write(t, dir, "sub/a.txt", "one\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "one")
	write(t, dir, "sub/a.txt", wantFiles["sub/a.txt"])
	git(t, dir, "commit", "-q", "-am", "two")
	git(t, dir, "tag", "-a", "v1", "-m", "v1")
	git(t, dir, "checkout", "-q", "-b", "dev")
	write(t, dir, "dev.txt", "dev\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "dev")
	git(t, dir, "checkout", "-q", "main")
}

// fakeAPI is a minimal GitHub REST API. Repo content comes from a real git
// repo (src), so the API and git modes see the same data.
type fakeAPI struct {
	t         *testing.T
	srv       *httptest.Server
	src       string // backing repo for acme/api
	pageSize  int
	truncated atomic.Bool
	mu        sync.Mutex
	hits      map[string]int // path → count
	repos     map[string][]map[string]any
}

func repoJSON(owner, name string, size int, extra map[string]any) map[string]any {
	m := map[string]any{
		"name": name, "owner": map[string]any{"login": owner},
		"html_url": "https://example/" + owner + "/" + name, "ssh_url": "git@example:" + owner + "/" + name + ".git",
		"clone_url":      "https://example/" + owner + "/" + name + ".git",
		"default_branch": "main", "size": size, "topics": []string{},
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func newFakeAPI(t *testing.T, src string) *fakeAPI {
	f := &fakeAPI{t: t, src: src, pageSize: 3, hits: map[string]int{}}
	f.repos = map[string][]map[string]any{
		"orgs/acme": {
			repoJSON("acme", "api", 10, map[string]any{"topics": []string{"go"}, "clone_url": "file://" + src}),
			repoJSON("acme", "web", 5, map[string]any{"topics": []string{"js"}}),
			repoJSON("acme", "sandbox-x", 1, nil),
			repoJSON("acme", "old", 4, map[string]any{"archived": true}),
			repoJSON("acme", "forked", 4, map[string]any{"fork": true}),
			repoJSON("acme", "empty", 0, nil),
			repoJSON("acme", "Lib", 3, map[string]any{"topics": []string{"Go"}}),
		},
		"users/bob": {repoJSON("bob", "public", 1, nil)},
		"user":      {repoJSON("bob", "public", 1, nil), repoJSON("bob", "private", 1, map[string]any{"private": true})},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) hit(p string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[p]
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
		return
	}
	if r.Header.Get("X-GitHub-Api-Version") != apiVersion {
		http.Error(w, "missing api version", http.StatusBadRequest)
		return
	}
	p := strings.TrimPrefix(r.URL.EscapedPath(), "/")
	f.mu.Lock()
	f.hits[p]++
	f.mu.Unlock()

	switch {
	case p == "user":
		fmt.Fprint(w, `{"login":"Bob"}`)
	case strings.HasSuffix(p, "/repos") || p == "user/repos":
		key := strings.TrimSuffix(p, "/repos")
		all, ok := f.repos[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		lo, hi := (page-1)*f.pageSize, page*f.pageSize
		if hi < len(all) {
			q := r.URL.Query()
			q.Set("page", strconv.Itoa(page+1))
			w.Header().Set("Link", fmt.Sprintf(`<%s/%s?%s>; rel="next", <%s/x?page=99>; rel="last"`, f.srv.URL, p, q.Encode(), f.srv.URL))
		} else {
			hi = len(all)
		}
		_ = json.NewEncoder(w).Encode(all[min(lo, hi):hi])
	case strings.HasPrefix(p, "repos/acme/"):
		f.serveRepo(w, r, strings.TrimPrefix(p, "repos/acme/"))
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeAPI) serveRepo(w http.ResponseWriter, r *http.Request, p string) {
	name, rest, _ := strings.Cut(p, "/")
	if name != "api" {
		http.NotFound(w, r)
		return
	}
	gitOut := func(args ...string) (string, bool) {
		out, err := gitx.Runner{}.Run(r.Context(), f.src, nil, args...)
		return string(out), err == nil
	}
	switch {
	case rest == "":
		_ = json.NewEncoder(w).Encode(f.repos["orgs/acme"][0])
	case rest == "branches":
		out, _ := gitOut("for-each-ref", "--format=%(refname:short)", "refs/heads/")
		var bs []map[string]string
		for _, n := range strings.Fields(out) {
			bs = append(bs, map[string]string{"name": n})
		}
		_ = json.NewEncoder(w).Encode(bs)
	case strings.HasPrefix(rest, "commits/"):
		ref := urlUnescape(strings.TrimPrefix(rest, "commits/"))
		if r.Header.Get("Accept") != "application/vnd.github.sha" {
			http.Error(w, "want sha media type", http.StatusBadRequest)
			return
		}
		sha, ok := gitOut("rev-parse", "--verify", "-q", ref+"^{commit}")
		if !ok {
			http.Error(w, `{"message":"No commit found for SHA: x"}`, http.StatusUnprocessableEntity)
			return
		}
		fmt.Fprint(w, strings.TrimSpace(sha))
	case strings.HasPrefix(rest, "git/trees/"):
		sha := strings.TrimPrefix(rest, "git/trees/")
		if r.URL.Query().Get("recursive") != "1" {
			http.Error(w, "want recursive", http.StatusBadRequest)
			return
		}
		out, ok := gitOut("ls-tree", "-r", "-t", "-z", sha)
		if !ok {
			http.NotFound(w, r)
			return
		}
		var tree []map[string]string
		for _, e := range parseTree([]byte(out)) {
			tree = append(tree, map[string]string{"path": e.path, "type": e.typ})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sha": sha, "tree": tree, "truncated": f.truncated.Load()})
	case strings.HasPrefix(rest, "contents/"):
		path := urlUnescape(strings.TrimPrefix(rest, "contents/"))
		if r.Header.Get("Accept") != "application/vnd.github.raw" {
			http.Error(w, "want raw media type", http.StatusBadRequest)
			return
		}
		out, ok := gitOut("cat-file", "blob", r.URL.Query().Get("ref")+":"+path)
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		fmt.Fprint(w, out)
	default:
		http.NotFound(w, r)
	}
}

func urlUnescape(s string) string {
	return strings.NewReplacer("%2F", "/", "%2f", "/").Replace(s)
}

func newProvider(t *testing.T, cfg plugin.Config, creds vcs.Credentials) *Provider {
	t.Helper()
	p, err := New(cfg, creds, plugin.Deps{
		HTTP:         httpx.New(httpx.Options{MaxRetries: 1}),
		WorkspaceDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return p.(*Provider)
}

func orgTarget() model.Target {
	return model.Target{
		Kind: model.TargetOrg, Provider: "github", Owner: "acme", Auth: "pat", ListAuth: "pat",
		Filter: model.RepoFilter{Include: []string{"*"}, Exclude: []string{"sandbox-*"}, SkipArchived: true, SkipForks: true, SkipEmpty: true},
	}
}

func setupAPI(t *testing.T) (*fakeAPI, *Provider) {
	needGit(t)
	src := filepath.Join(t.TempDir(), "api")
	makeRepo(t, src)
	f := newFakeAPI(t, src)
	creds := tokenCreds{"token"}
	return f, newProvider(t, plugin.Config{"base_url": f.srv.URL}, vcs.Credentials{Read: creds, List: creds})
}

func TestRegistered(t *testing.T) {
	t.Parallel()
	if _, err := vcs.Registry.Get("github"); err != nil {
		t.Fatal(err)
	}
}

func TestContractTokenOrg(t *testing.T) {
	t.Parallel()
	f, p := setupAPI(t)
	vcstest.Run(t, p, vcstest.Fixture{
		Target:    orgTarget(),
		WantRepos: []string{"acme/api", "acme/web", "acme/Lib"},
		Repo:      "acme/api",
		WantRef:   "main",
		WantFiles: wantFiles,
	})
	if n := f.hit("orgs/acme/repos"); n < 3 {
		t.Errorf("expected paginated listing, got %d page requests", n)
	}
}

func TestContractTokenSingleRepo(t *testing.T) {
	t.Parallel()
	_, p := setupAPI(t)
	vcstest.Run(t, p, vcstest.Fixture{
		Target:    model.Target{Kind: model.TargetRepo, Owner: "acme", Name: "api", Branch: "dev", Auth: "pat"},
		WantRepos: []string{"acme/api"},
		Repo:      "acme/api",
		WantRef:   "dev",
		WantFiles: map[string]string{"dev.txt": "dev\n", "go.mod": wantFiles["go.mod"]},
	})
}

func TestFilters(t *testing.T) {
	t.Parallel()
	_, p := setupAPI(t)
	ctx := context.Background()
	names := func(rs []model.Repo) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.Name)
		}
		slices.Sort(out)
		return out
	}
	tg := orgTarget()
	tg.Filter.Topics = []string{"go"}
	rs, err := p.ListRepos(ctx, tg)
	if err != nil || !slices.Equal(names(rs), []string{"Lib", "api"}) {
		t.Fatalf("topics filter = %v, %v", names(rs), err)
	}
	tg = orgTarget()
	tg.Filter.Include = []string{"a*", "w*"}
	tg.Filter.MaxRepos = 1
	rs, err = p.ListRepos(ctx, tg)
	if err != nil || !slices.Equal(names(rs), []string{"api"}) {
		t.Fatalf("include+max = %v, %v", names(rs), err)
	}
	tg = orgTarget()
	tg.Filter = model.RepoFilter{}
	tg.Branch = "release"
	rs, err = p.ListRepos(ctx, tg)
	if err != nil || len(rs) != 7 {
		t.Fatalf("no filter = %v, %v", names(rs), err)
	}
	for _, r := range rs {
		if r.Ref != "release" || r.Auth != "pat" || r.Provider != "github" || r.Host == "" {
			t.Errorf("repo %+v: Ref/Auth/Provider/Host not set", r)
		}
		if r.Name == "empty" && !r.Empty {
			t.Error("size 0 repo must be Empty")
		}
	}
}

func TestUserTargets(t *testing.T) {
	t.Parallel()
	f, p := setupAPI(t)
	ctx := context.Background()
	rs, err := p.ListRepos(ctx, model.Target{Kind: model.TargetUser, Owner: "bob"})
	if err != nil || len(rs) != 2 || f.hit("user/repos") != 1 {
		t.Fatalf("own user: %d repos, %v, /user/repos hits %d", len(rs), err, f.hit("user/repos"))
	}
	if _, err := p.ListRepos(ctx, model.Target{Kind: model.TargetUser, Owner: "carol"}); !errors.Is(err, vcs.ErrNotFound) {
		t.Fatalf("unknown user err = %v", err)
	}
	if f.hit("users/carol/repos") != 1 {
		t.Fatal("other users must be listed through /users/{u}/repos")
	}
	// app credentials never call /user
	creds := tokenCreds{"app"}
	pa := newProvider(t, plugin.Config{"base_url": f.srv.URL}, vcs.Credentials{Read: creds, List: creds})
	before := f.hit("user")
	rs, err = pa.ListRepos(ctx, model.Target{Kind: model.TargetUser, Owner: "bob"})
	if err != nil || len(rs) != 1 || f.hit("user") != before {
		t.Fatalf("app user listing: %d repos, %v", len(rs), err)
	}
}

func TestManifestCache(t *testing.T) {
	t.Parallel()
	f, p := setupAPI(t)
	ctx := context.Background()
	r := model.Repo{Provider: "github", Owner: "acme", Name: "api"}
	sha, err := p.ResolveRef(ctx, r, "main")
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		b, err := p.ReadFile(ctx, r, sha, "go.mod")
		if err != nil || string(b) != wantFiles["go.mod"] {
			t.Fatalf("ReadFile = %q, %v", b, err)
		}
	}
	if n := f.hit("repos/acme/api/contents/go.mod"); n != 1 {
		t.Fatalf("contents API hits = %d, want 1 (cached by sha)", n)
	}
	cached := filepath.Join(p.ws, strings.ReplaceAll(p.host, ":", "_"), "acme", "api", sha, "go.mod")
	if _, err := os.Stat(cached); err != nil {
		t.Fatalf("cache file: %v", err)
	}
	if _, err := p.ReadFile(ctx, r, sha, "../../etc/passwd"); err == nil {
		t.Fatal("path traversal must be rejected")
	}
}

func TestTruncatedTreeFallsBackToGit(t *testing.T) {
	t.Parallel()
	f, p := setupAPI(t)
	f.truncated.Store(true)
	ctx := context.Background()
	rs, err := p.ListRepos(ctx, model.Target{Kind: model.TargetRepo, Owner: "acme", Name: "api"})
	if err != nil {
		t.Fatal(err)
	}
	sha, err := p.ResolveRef(ctx, rs[0], "main")
	if err != nil {
		t.Fatal(err)
	}
	files, err := p.ListFiles(ctx, rs[0], sha)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	if !slices.Equal(files, []string{"go.mod", "sub/a.txt"}) {
		t.Fatalf("files = %v", files)
	}
	assertNoTokenOnDisk(t, p.ws)
}

func TestCheckoutTokenMode(t *testing.T) {
	t.Parallel()
	_, p := setupAPI(t)
	ctx := context.Background()
	rs, err := p.ListRepos(ctx, model.Target{Kind: model.TargetRepo, Owner: "acme", Name: "api"})
	if err != nil {
		t.Fatal(err)
	}
	sha, err := p.ResolveRef(ctx, rs[0], "dev")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "co")
	if err := p.Checkout(ctx, rs[0], sha, dir); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "dev.txt")); err != nil || string(b) != "dev\n" {
		t.Fatalf("dev.txt = %q, %v", b, err)
	}
	assertNoTokenOnDisk(t, p.ws)
}

func TestAuthConfigNeverOnCommandLine(t *testing.T) {
	t.Parallel()
	needGit(t)
	p := newProvider(t, plugin.Config{}, vcs.Credentials{Read: tokenCreds{"token"}})
	rm := remote{url: "https://github.com/acme/api.git", token: testToken}
	f, err := p.authConfig(rm)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f)
	st, _ := os.Stat(f)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("auth config mode = %v", st.Mode().Perm())
	}
	out, err := gitx.Runner{}.Run(context.Background(), "", nil, "-c", "include.path="+f, "config", "--get-urlmatch", "http.extraheader", "https://github.com/acme/api.git")
	if err != nil || !strings.HasPrefix(string(out), "AUTHORIZATION: basic ") {
		t.Fatalf("include.path not honoured: %q, %v", out, err)
	}
	if out, _ := (gitx.Runner{}).Run(context.Background(), "", nil, "-c", "include.path="+f, "config", "--get-urlmatch", "http.extraheader", "https://evil.example/x.git"); len(out) != 0 {
		t.Fatalf("header must be scoped to the remote origin, got %q", out)
	}
}

func assertNoTokenOnDisk(t *testing.T, root string) {
	t.Helper()
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.Contains(path, string(filepath.Separator)+"objects"+string(filepath.Separator)) {
			return nil
		}
		b, _ := os.ReadFile(path)
		if strings.Contains(string(b), testToken) || strings.Contains(string(b), "eC1hY2Nlc3MtdG9rZW46") {
			t.Errorf("token found on disk in %s", path)
		}
		return nil
	})
}

// --- SSH mode -------------------------------------------------------------

func setupSSH(t *testing.T) *Provider {
	needGit(t)
	root := t.TempDir()
	makeRepo(t, filepath.Join(root, "acme", "api.git"))
	p := newProvider(t, plugin.Config{}, vcs.Credentials{Read: sshCreds{}, List: sshCreds{}})
	p.sshBase = "file://" + root + "/"
	return p
}

func TestContractSSHRepo(t *testing.T) {
	t.Parallel()
	p := setupSSH(t)
	vcstest.Run(t, p, vcstest.Fixture{
		Target:    model.Target{Kind: model.TargetRepo, Owner: "acme", Name: "api", Auth: "ssh", ListAuth: "ssh"},
		WantRepos: []string{"acme/api"},
		Repo:      "acme/api",
		WantRef:   "main",
		WantFiles: wantFiles,
	})
	if _, err := os.Stat(filepath.Join(p.ws, "github.com", "acme", "api.git", "HEAD")); err != nil {
		t.Fatalf("bare mirror not created: %v", err)
	}
}

func TestContractSSHStaticList(t *testing.T) {
	t.Parallel()
	p := setupSSH(t)
	vcstest.Run(t, p, vcstest.Fixture{
		Target:    model.Target{Kind: model.TargetOrg, Owner: "acme", Repos: []string{"api"}, Branch: "dev", Auth: "ssh", ListAuth: "ssh"},
		WantRepos: []string{"acme/api"},
		Repo:      "acme/api",
		WantRef:   "dev",
		WantFiles: map[string]string{"dev.txt": "dev\n"},
	})
}

func TestSSHListingUnsupported(t *testing.T) {
	t.Parallel()
	p := setupSSH(t)
	_, err := p.ListRepos(context.Background(), model.Target{Kind: model.TargetOrg, Owner: "acme"})
	if !errors.Is(err, vcs.ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

func TestSSHIncrementalAndCheckout(t *testing.T) {
	t.Parallel()
	p := setupSSH(t)
	ctx := context.Background()
	r := model.Repo{Provider: "github", Host: "github.com", Owner: "acme", Name: "api", Ref: "main"}
	src := strings.TrimPrefix(p.sshBase, "file://") + "acme/api.git"

	sha1, err := p.ResolveRef(ctx, r, "main")
	if err != nil {
		t.Fatal(err)
	}
	// blob-less mirror: blobs are fetched only when read
	missing := git(t, p.mirrorDir(r), "rev-list", "--objects", "--missing=print", sha1)
	if !strings.Contains(missing, "\n?") {
		t.Fatalf("mirror should miss blobs after ResolveRef:\n%s", missing)
	}
	if again, err := p.ResolveRef(ctx, r, "main"); err != nil || again != sha1 {
		t.Fatalf("second ResolveRef = %s, %v", again, err)
	}
	// tag (annotated) resolves to the commit
	if tag, err := p.ResolveRef(ctx, r, "v1"); err != nil || tag != sha1 {
		t.Fatalf("ResolveRef(v1) = %s, %v; want %s", tag, err, sha1)
	}

	write(t, src, "go.mod", "module example.com/api\n\ngo 1.23\n")
	git(t, src, "commit", "-q", "-am", "bump")
	sha2, err := p.ResolveRef(ctx, r, "main")
	if err != nil || sha2 == sha1 {
		t.Fatalf("ResolveRef after push = %s, %v", sha2, err)
	}
	if b, err := p.ReadFile(ctx, r, sha2, "go.mod"); err != nil || !strings.Contains(string(b), "go 1.23") {
		t.Fatalf("ReadFile(new) = %q, %v", b, err)
	}
	// the old commit stays readable
	if b, err := p.ReadFile(ctx, r, sha1, "go.mod"); err != nil || string(b) != wantFiles["go.mod"] {
		t.Fatalf("ReadFile(old) = %q, %v", b, err)
	}
	// directories are not files
	if _, err := p.ReadFile(ctx, r, sha1, "sub"); !errors.Is(err, vcs.ErrNotFound) {
		t.Fatalf("ReadFile(dir) err = %v", err)
	}
	// unknown sha
	if _, err := p.ListFiles(ctx, r, strings.Repeat("ab", 20)); !errors.Is(err, vcs.ErrNotFound) {
		t.Fatalf("ListFiles(unknown sha) err = %v", err)
	}

	dir := t.TempDir() // exists and is empty
	if err := p.Checkout(ctx, r, sha1, dir); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "sub", "a.txt")); err != nil || string(b) != "two\n" {
		t.Fatalf("checkout sub/a.txt = %q, %v", b, err)
	}
	// a second checkout after the first one was removed
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := p.Checkout(ctx, r, sha2, filepath.Join(t.TempDir(), "co2")); err != nil {
		t.Fatal(err)
	}
}

func TestSSHConcurrentReads(t *testing.T) {
	t.Parallel()
	p := setupSSH(t)
	ctx := context.Background()
	r := model.Repo{Provider: "github", Owner: "acme", Name: "api"}
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			sha, err := p.ResolveRef(ctx, r, "main")
			if err != nil {
				t.Error(err)
				return
			}
			if b, err := p.ReadFile(ctx, r, sha, "go.mod"); err != nil || string(b) != wantFiles["go.mod"] {
				t.Errorf("ReadFile = %q, %v", b, err)
			}
		})
	}
	wg.Wait()
}

func TestConfig(t *testing.T) {
	t.Parallel()
	creds := vcs.Credentials{Read: tokenCreds{"token"}}
	deps := plugin.Deps{HTTP: httpx.New(httpx.Options{})}
	p, err := New(plugin.Config{"base_url": "https://ghe.example.com/api/v3/"}, creds, deps)
	if err != nil {
		t.Fatal(err)
	}
	gp := p.(*Provider)
	if gp.host != "ghe.example.com" || gp.api != "https://ghe.example.com/api/v3" || gp.web != "https://ghe.example.com" {
		t.Fatalf("GHES: host %q api %q web %q", gp.host, gp.api, gp.web)
	}
	p, _ = New(nil, creds, deps)
	if gp := p.(*Provider); gp.host != "github.com" || gp.web != "https://github.com" {
		t.Fatalf("default: host %q web %q", gp.host, gp.web)
	}
	for _, bad := range []plugin.Config{{"base_url": "not a url"}, {"token": "x"}} {
		if _, err := New(bad, creds, deps); err == nil {
			t.Errorf("New(%v) must fail", bad)
		}
	}
	if _, err := New(nil, vcs.Credentials{}, deps); err == nil {
		t.Error("missing credentials must fail")
	}
}

func TestNextLink(t *testing.T) {
	t.Parallel()
	h := `<https://api.github.com/orgs/a/repos?page=2>; rel="next", <https://api.github.com/orgs/a/repos?page=5>; rel="last"`
	if got := nextLink(h); got != "https://api.github.com/orgs/a/repos?page=2" {
		t.Fatalf("nextLink = %q", got)
	}
	if nextLink(`<https://x>; rel="prev"`) != "" || nextLink("") != "" {
		t.Fatal("no next expected")
	}
}

func TestListBranches(t *testing.T) {
	t.Parallel()
	_, api := setupAPI(t)
	ssh := setupSSH(t)
	r := model.Repo{Provider: "github", Host: "github.com", Owner: "acme", Name: "api"}
	for name, p := range map[string]*Provider{"api": api, "ssh": ssh} {
		got, err := p.ListBranches(context.Background(), r)
		if err != nil || strings.Join(got, ",") != "dev,main" {
			t.Errorf("%s: ListBranches = %v, %v; want dev,main", name, got, err)
		}
	}
}
