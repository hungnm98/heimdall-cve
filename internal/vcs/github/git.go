package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hungnm98/heimdall-cve/internal/gitx"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
)

// Git mode keeps one bare mirror per repo at <workspace>/<host>/<owner>/<name>.git.
// The mirror is a blob-less partial clone: commits and trees are fetched with
// --depth 1 per scanned commit, blobs only when a file is read (lazily, from
// the promisor remote). Every commit fetched is pinned by a ref
// refs/heimdall/commits/<sha>, so presence is checked without reading objects
// (which in a partial clone would trigger a deep lazy fetch).

const commitRefPrefix = "refs/heimdall/commits/"

// remote says how to reach a repo with git.
type remote struct {
	url   string
	ssh   *gitx.SSH
	token string // HTTPS: sent as an http.extraheader from a temp config file
}

func (p *Provider) remoteFor(ctx context.Context, r model.Repo) (remote, error) {
	var rm remote
	if p.readSSH != nil {
		rm = remote{url: r.SSHURL, ssh: p.readSSH}
		switch {
		case p.sshBase != "":
			rm.url = p.sshBase + r.Owner + "/" + r.Name + ".git"
		case rm.url == "":
			rm.url = "git@" + p.host + ":" + r.Owner + "/" + r.Name + ".git"
		}
	} else {
		tok, err := p.readToken.Token(ctx, r.Owner)
		if err != nil {
			return remote{}, fmt.Errorf("github: %w", err)
		}
		rm = remote{url: r.CloneURL, token: tok}
		if rm.url == "" {
			rm.url = p.web + "/" + r.Owner + "/" + r.Name + ".git"
		}
	}
	if strings.HasPrefix(rm.url, "-") {
		return remote{}, fmt.Errorf("github: invalid remote url for %s", r.FullName())
	}
	return rm, nil
}

// run runs git in dir authenticated as rm. A token never appears on the
// command line: it goes into a 0600 config file that is included with -c
// (inherited by git's own sub-processes such as lazy fetches) and deleted
// right after.
func (p *Provider) run(ctx context.Context, dir string, rm remote, args ...string) ([]byte, error) {
	if rm.token != "" {
		f, err := p.authConfig(rm)
		if err != nil {
			return nil, err
		}
		defer os.Remove(f)
		args = append([]string{"-c", "include.path=" + f}, args...)
	}
	return p.git.Run(ctx, dir, rm.ssh, args...)
}

func (p *Provider) authConfig(rm remote) (string, error) {
	dir := filepath.Join(p.ws, ".tmp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("github: %w", err)
	}
	f, err := os.CreateTemp(dir, "auth-*.gitconfig")
	if err != nil {
		return "", fmt.Errorf("github: %w", err)
	}
	section := "[http]"
	if u, err := url.Parse(rm.url); err == nil && (u.Scheme == "https" || u.Scheme == "http") {
		section = fmt.Sprintf("[http %q]", u.Scheme+"://"+u.Host+"/") // only this origin
	}
	cred := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + rm.token))
	_, werr := fmt.Fprintf(f, "%s\n\textraheader = AUTHORIZATION: basic %s\n", section, cred)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("github: write auth config: %v %v", werr, cerr)
	}
	return f.Name(), nil
}

func (p *Provider) mirrorDir(r model.Repo) string { return p.repoDir(r.Owner, r.Name) + ".git" }

// lock serialises operations on one mirror within this process. Concurrent
// processes sharing a workspace rely on git's own lock files.
func (p *Provider) lock(dir string) func() {
	m, _ := p.locks.LoadOrStore(dir, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// openMirror locks and prepares r's mirror; the caller must call unlock.
func (p *Provider) openMirror(ctx context.Context, r model.Repo) (dir string, rm remote, unlock func(), err error) {
	rm, err = p.remoteFor(ctx, r)
	if err != nil {
		return "", remote{}, nil, err
	}
	dir = p.mirrorDir(r)
	unlock = p.lock(dir)
	if err := p.ensureMirror(ctx, dir, rm); err != nil {
		unlock()
		return "", remote{}, nil, err
	}
	return dir, rm, unlock, nil
}

func (p *Provider) ensureMirror(ctx context.Context, dir string, rm remote) error {
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err == nil {
		cur, err := p.git.Run(ctx, dir, nil, "config", "--get", "remote.origin.url")
		if err == nil && strings.TrimSpace(string(cur)) == rm.url {
			return nil
		}
		_, err = p.git.Run(ctx, dir, nil, "config", "remote.origin.url", rm.url)
		return err
	}
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("github: %w", err)
	}
	tmp := dir + ".init"
	if err := os.RemoveAll(tmp); err != nil {
		return fmt.Errorf("github: %w", err)
	}
	if _, err := p.git.Run(ctx, parent, nil, "init", "-q", "--bare", tmp); err != nil {
		return err
	}
	for _, kv := range [][2]string{
		{"remote.origin.url", rm.url},
		{"remote.origin.promisor", "true"},
		{"remote.origin.partialclonefilter", "blob:none"},
	} {
		if _, err := p.git.Run(ctx, tmp, nil, "config", kv[0], kv[1]); err != nil {
			_ = os.RemoveAll(tmp)
			return err
		}
	}
	if err := os.Rename(tmp, dir); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("github: %w", err)
	}
	return nil
}

// known reports whether commit sha was already fetched into the mirror.
func (p *Provider) known(ctx context.Context, dir, sha string) (bool, error) {
	out, err := p.git.Run(ctx, dir, nil, "for-each-ref", "--format=%(objectname)", commitRefPrefix+sha)
	return len(bytes.TrimSpace(out)) > 0, err
}

// ensureCommit makes sure commit sha (and its trees) is in the mirror.
func (p *Provider) ensureCommit(ctx context.Context, dir string, rm remote, sha string) error {
	if !isSHA(sha) {
		return fmt.Errorf("github: %q is not a commit sha: %w", sha, vcs.ErrNotFound)
	}
	if ok, err := p.known(ctx, dir, sha); err != nil || ok {
		return err
	}
	_, err := p.run(ctx, dir, rm, "fetch", "-q", "--no-tags", "--depth", "1", "--filter=blob:none",
		"origin", "+"+sha+":"+commitRefPrefix+sha)
	if err != nil {
		if missingRemoteObject(err) {
			return fmt.Errorf("github: commit %s: %w (%v)", sha, vcs.ErrNotFound, err)
		}
		return err
	}
	return nil
}

func missingRemoteObject(err error) bool {
	s := err.Error()
	for _, m := range []string{"not our ref", "couldn't find remote ref", "unadvertised object", "no such remote ref", "not a valid object"} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func (p *Provider) gitDefaultBranch(ctx context.Context, r model.Repo) (string, error) {
	rm, err := p.remoteFor(ctx, r)
	if err != nil {
		return "", err
	}
	out, err := p.run(ctx, "", rm, "ls-remote", "--symref", rm.url, "HEAD")
	if err != nil {
		return "", fmt.Errorf("github: default branch of %s: %w", r.FullName(), err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(line, "ref: refs/heads/"); ok {
			if branch, _, ok := strings.Cut(rest, "\t"); ok && branch != "" {
				return branch, nil
			}
		}
	}
	return "", fmt.Errorf("github: default branch of %s (empty repository?): %w", r.FullName(), vcs.ErrNotFound)
}

func (p *Provider) gitListBranches(ctx context.Context, r model.Repo) ([]string, error) {
	rm, err := p.remoteFor(ctx, r)
	if err != nil {
		return nil, err
	}
	out, err := p.run(ctx, "", rm, "ls-remote", "--heads", rm.url)
	if err != nil {
		return nil, fmt.Errorf("github: list branches of %s: %w", r.FullName(), err)
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if _, ref, ok := strings.Cut(strings.TrimSpace(line), "\t"); ok {
			if name, ok := strings.CutPrefix(ref, "refs/heads/"); ok {
				names = append(names, name)
			}
		}
	}
	return names, nil
}

func (p *Provider) gitResolveRef(ctx context.Context, r model.Repo, ref string) (string, error) {
	dir, rm, unlock, err := p.openMirror(ctx, r)
	if err != nil {
		return "", err
	}
	defer unlock()
	if isSHA(ref) {
		return ref, p.ensureCommit(ctx, dir, rm, ref)
	}
	out, err := p.run(ctx, dir, rm, "ls-remote", "origin", "refs/heads/"+ref, "refs/tags/"+ref)
	if err != nil {
		return "", fmt.Errorf("github: resolve %s@%s: %w", r.FullName(), ref, err)
	}
	refs := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if sha, name, ok := strings.Cut(strings.TrimSpace(line), "\t"); ok {
			refs[name] = sha
		}
	}
	var full, sha string
	for _, cand := range [][2]string{
		{"refs/heads/" + ref, "refs/heads/" + ref},
		{"refs/tags/" + ref, "refs/tags/" + ref + "^{}"}, // annotated tag: peeled commit
		{"refs/tags/" + ref, "refs/tags/" + ref},
	} {
		if s, ok := refs[cand[1]]; ok {
			full, sha = cand[0], s
			break
		}
	}
	if full == "" {
		return "", fmt.Errorf("github: resolve %s@%s: %w", r.FullName(), ref, vcs.ErrNotFound)
	}
	if ok, err := p.known(ctx, dir, sha); err != nil || ok {
		return sha, err
	}
	if _, err := p.run(ctx, dir, rm, "fetch", "-q", "--no-tags", "--depth", "1", "--filter=blob:none",
		"origin", "+"+full+":"+full); err != nil {
		return "", fmt.Errorf("github: fetch %s@%s: %w", r.FullName(), ref, err)
	}
	// The branch may have moved since ls-remote: report what was fetched.
	got, err := p.git.Run(ctx, dir, nil, "rev-parse", "--verify", "-q", full+"^{commit}")
	if err != nil {
		return "", err
	}
	sha = strings.TrimSpace(string(got))
	if _, err := p.git.Run(ctx, dir, nil, "update-ref", commitRefPrefix+sha, sha); err != nil {
		return "", err
	}
	return sha, nil
}

// treeEntry is one line of `git ls-tree -z`: "<mode> <type> <oid>\t<path>".
type treeEntry struct{ typ, oid, path string }

func parseTree(out []byte) []treeEntry {
	var entries []treeEntry
	for _, rec := range strings.Split(string(out), "\x00") {
		meta, p, ok := strings.Cut(rec, "\t")
		if !ok {
			continue
		}
		f := strings.Fields(meta)
		if len(f) != 3 {
			continue
		}
		entries = append(entries, treeEntry{typ: f[1], oid: f[2], path: p})
	}
	return entries
}

func (p *Provider) gitListFiles(ctx context.Context, r model.Repo, sha string) ([]string, error) {
	dir, rm, unlock, err := p.openMirror(ctx, r)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := p.ensureCommit(ctx, dir, rm, sha); err != nil {
		return nil, err
	}
	out, err := p.git.Run(ctx, dir, nil, "ls-tree", "-r", "-z", "--full-tree", sha)
	if err != nil {
		return nil, fmt.Errorf("github: list files %s@%s: %w", r.FullName(), sha, err)
	}
	var files []string
	for _, e := range parseTree(out) {
		if e.typ == "blob" {
			files = append(files, e.path)
		}
	}
	return files, nil
}

func (p *Provider) gitReadFile(ctx context.Context, r model.Repo, sha, file string) ([]byte, error) {
	dir, rm, unlock, err := p.openMirror(ctx, r)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := p.ensureCommit(ctx, dir, rm, sha); err != nil {
		return nil, err
	}
	out, err := p.git.Run(ctx, dir, nil, "--literal-pathspecs", "ls-tree", "-z", "--full-tree", sha, "--", file)
	if err != nil {
		return nil, fmt.Errorf("github: read %s@%s:%s: %w", r.FullName(), sha, file, err)
	}
	for _, e := range parseTree(out) {
		if e.path == file && e.typ == "blob" {
			b, err := p.run(ctx, dir, rm, "cat-file", "blob", e.oid) // fetches the blob on demand
			if err != nil {
				return nil, fmt.Errorf("github: read %s@%s:%s: %w", r.FullName(), sha, file, err)
			}
			return b, nil
		}
	}
	return nil, fmt.Errorf("github: read %s@%s:%s: %w", r.FullName(), sha, file, vcs.ErrNotFound)
}

func (p *Provider) gitCheckout(ctx context.Context, r model.Repo, sha, target string) error {
	abs, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("github: %w", err)
	}
	dir, rm, unlock, err := p.openMirror(ctx, r)
	if err != nil {
		return err
	}
	defer unlock()
	if err := p.ensureCommit(ctx, dir, rm, sha); err != nil {
		return err
	}
	// Drop metadata of earlier checkouts whose directories are gone.
	if _, err := p.git.Run(ctx, dir, nil, "worktree", "prune"); err != nil {
		return err
	}
	if _, err := p.run(ctx, dir, rm, "worktree", "add", "-q", "--detach", abs, sha); err != nil {
		return fmt.Errorf("github: checkout %s@%s: %w", r.FullName(), sha, err)
	}
	return nil
}
