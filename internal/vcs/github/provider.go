package github

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/auth"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
)

// ListRepos implements vcs.Provider. A repo target and a static Repos list
// are explicit, so filters are not applied to them and no listing call is made.
func (p *Provider) ListRepos(ctx context.Context, t model.Target) ([]model.Repo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkName("owner", t.Owner); err != nil {
		return nil, err
	}
	switch {
	case t.Kind == model.TargetRepo:
		r, err := p.oneRepo(ctx, t, t.Owner, t.Name)
		if err != nil {
			return nil, err
		}
		return []model.Repo{r}, nil
	case len(t.Repos) > 0:
		out := make([]model.Repo, 0, len(t.Repos))
		for _, entry := range t.Repos {
			owner, name := t.Owner, entry
			if o, n, ok := strings.Cut(entry, "/"); ok {
				owner, name = o, n
			}
			r, err := p.oneRepo(ctx, t, owner, name)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, nil
	}
	return p.listAPI(ctx, t)
}

// oneRepo describes a named repo: through the API when the list credentials
// allow it, otherwise from git alone (SSH: default branch via ls-remote).
func (p *Provider) oneRepo(ctx context.Context, t model.Target, owner, name string) (model.Repo, error) {
	if err := checkName("owner", owner); err != nil {
		return model.Repo{}, err
	}
	if err := checkName("repo name", name); err != nil {
		return model.Repo{}, err
	}
	if ts, ok := p.list.(auth.TokenSource); ok {
		return p.getRepo(ctx, ts, t, owner, name)
	}
	if p.readSSH == nil {
		return model.Repo{}, fmt.Errorf("github: auth method %q cannot describe %s/%s: %w", p.list.Method(), owner, name, vcs.ErrUnsupported)
	}
	r := model.Repo{
		Provider: Name,
		Host:     p.host,
		Owner:    owner,
		Name:     name,
		HTMLURL:  p.web + "/" + owner + "/" + name,
		CloneURL: p.web + "/" + owner + "/" + name + ".git",
		SSHURL:   "git@" + p.host + ":" + owner + "/" + name + ".git",
		Auth:     t.Auth,
		Ref:      t.Branch,
	}
	if r.Ref == "" {
		def, err := p.gitDefaultBranch(ctx, r)
		if err != nil {
			return model.Repo{}, err
		}
		r.DefaultBranch, r.Ref = def, def
	}
	return r, nil
}

// matchFilter applies a RepoFilter. Names and topics compare case-insensitively,
// like GitHub itself.
func matchFilter(f model.RepoFilter, r model.Repo) bool {
	if (f.SkipArchived && r.Archived) || (f.SkipForks && r.Fork) || (f.SkipEmpty && r.Empty) {
		return false
	}
	name := strings.ToLower(r.Name)
	if len(f.Include) > 0 && !matchAny(f.Include, name) {
		return false
	}
	if matchAny(f.Exclude, name) {
		return false
	}
	if len(f.Topics) > 0 {
		for _, want := range f.Topics {
			for _, have := range r.Topics {
				if strings.EqualFold(want, have) {
					return true
				}
			}
		}
		return false
	}
	return true
}

func matchAny(globs []string, name string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(strings.ToLower(g), name); ok {
			return true
		}
	}
	return false
}

// ResolveRef implements vcs.Provider.
func (p *Provider) ResolveRef(ctx context.Context, r model.Repo, ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("github: %s: empty ref: %w", r.FullName(), vcs.ErrNotFound)
	}
	if err := p.checkRepo(r); err != nil {
		return "", err
	}
	if p.readToken != nil {
		return p.apiResolveRef(ctx, r, ref)
	}
	return p.gitResolveRef(ctx, r, ref)
}

var _ vcs.BranchLister = (*Provider)(nil)

// ListBranches implements vcs.BranchLister (sorted names).
func (p *Provider) ListBranches(ctx context.Context, r model.Repo) ([]string, error) {
	if err := p.checkRepo(r); err != nil {
		return nil, err
	}
	var out []string
	var err error
	if p.readToken != nil {
		out, err = p.apiListBranches(ctx, r)
	} else {
		out, err = p.gitListBranches(ctx, r)
	}
	sort.Strings(out)
	return out, err
}

// ListFiles implements vcs.Provider.
func (p *Provider) ListFiles(ctx context.Context, r model.Repo, sha string) ([]string, error) {
	if err := p.checkRepo(r); err != nil {
		return nil, err
	}
	if p.readToken != nil {
		files, truncated, err := p.apiListFiles(ctx, r, sha)
		if err != nil || !truncated {
			return files, err
		}
		p.log.Debug("tree truncated; listing through git", "repo", r.FullName())
	}
	return p.gitListFiles(ctx, r, sha)
}

// ReadFile implements vcs.Provider.
func (p *Provider) ReadFile(ctx context.Context, r model.Repo, sha, file string) ([]byte, error) {
	if err := p.checkRepo(r); err != nil {
		return nil, err
	}
	file, err := cleanPath(file)
	if err != nil {
		return nil, err
	}
	if p.readToken != nil {
		return p.apiReadFile(ctx, r, sha, file)
	}
	return p.gitReadFile(ctx, r, sha, file)
}

// Checkout implements vcs.Provider: a worktree of the repo's mirror at sha.
// dir must not exist or be empty.
func (p *Provider) Checkout(ctx context.Context, r model.Repo, sha, dir string) error {
	if err := p.checkRepo(r); err != nil {
		return err
	}
	return p.gitCheckout(ctx, r, sha, dir)
}

func (p *Provider) checkRepo(r model.Repo) error {
	return errors.Join(checkName("owner", r.Owner), checkName("repo name", r.Name))
}
