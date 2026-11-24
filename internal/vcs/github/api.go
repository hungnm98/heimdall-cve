package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/auth"
	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
)

const (
	apiVersion  = "2022-11-28"
	acceptJSON  = "application/vnd.github+json"
	maxFileSize = 100 << 20 // Contents API limit
)

// get sends an authenticated GET and returns a 2xx response (caller closes
// the body). 404, 409 (empty repo) and 422 (unknown commit) map to vcs.ErrNotFound.
func (p *Provider) get(ctx context.Context, ts auth.TokenSource, owner, u, accept string) (*http.Response, error) {
	tok, err := ts.Token(ctx, owner)
	if err != nil {
		return nil, fmt.Errorf("github: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: %w", err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return resp, nil
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	switch resp.StatusCode {
	case http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity:
		return nil, fmt.Errorf("github: GET %s: HTTP %d: %w", req.URL.Redacted(), resp.StatusCode, vcs.ErrNotFound)
	}
	return nil, fmt.Errorf("github: %w", &httpx.StatusError{Method: http.MethodGet, URL: req.URL.Redacted(), Code: resp.StatusCode, Body: string(snippet)})
}

// getJSON decodes a JSON response and returns the rel="next" link, if any.
func (p *Provider) getJSON(ctx context.Context, ts auth.TokenSource, owner, u string, out any) (string, error) {
	resp, err := p.get(ctx, ts, owner, u, acceptJSON)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return "", fmt.Errorf("github: GET %s: decode: %w", resp.Request.URL.Redacted(), err)
	}
	next := nextLink(resp.Header.Get("Link"))
	if next != "" && !p.sameOrigin(next) {
		return "", fmt.Errorf("github: refusing pagination link to another origin")
	}
	return next, nil
}

// nextLink extracts rel="next" from an RFC 8288 Link header.
func nextLink(h string) string {
	for _, part := range strings.Split(h, ",") {
		seg := strings.Split(part, ";")
		if len(seg) < 2 {
			continue
		}
		for _, attr := range seg[1:] {
			if strings.TrimSpace(attr) == `rel="next"` {
				return strings.Trim(strings.TrimSpace(seg[0]), "<>")
			}
		}
	}
	return ""
}

// sameOrigin keeps the token from being sent to a host other than the API's.
func (p *Provider) sameOrigin(raw string) bool {
	a, err1 := url.Parse(raw)
	b, err2 := url.Parse(p.api)
	return err1 == nil && err2 == nil && a.Scheme == b.Scheme && strings.EqualFold(a.Host, b.Host)
}

func (p *Provider) repoURL(owner, name string, rest ...string) string {
	u := p.api + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name)
	for _, r := range rest {
		u += "/" + r
	}
	return u
}

// apiRepo is the subset of GitHub's repository object we use.
type apiRepo struct {
	Name  string `json:"name"`
	Owner struct {
		Login string `json:"login"`
	} `json:"owner"`
	HTMLURL       string   `json:"html_url"`
	CloneURL      string   `json:"clone_url"`
	SSHURL        string   `json:"ssh_url"`
	DefaultBranch string   `json:"default_branch"`
	Private       bool     `json:"private"`
	Archived      bool     `json:"archived"`
	Fork          bool     `json:"fork"`
	Size          int64    `json:"size"`
	Topics        []string `json:"topics"`
}

func (p *Provider) toRepo(a apiRepo, t model.Target) model.Repo {
	r := model.Repo{
		Provider:      Name,
		Host:          p.host,
		Owner:         a.Owner.Login,
		Name:          a.Name,
		HTMLURL:       a.HTMLURL,
		CloneURL:      a.CloneURL,
		SSHURL:        a.SSHURL,
		DefaultBranch: a.DefaultBranch,
		Private:       a.Private,
		Archived:      a.Archived,
		Fork:          a.Fork,
		// GitHub reports size 0 (KB) for repositories without commits.
		Empty:  a.Size == 0,
		Topics: a.Topics,
		Auth:   t.Auth,
	}
	if r.Owner == "" {
		r.Owner = t.Owner
	}
	r.Ref = t.Branch
	if r.Ref == "" {
		r.Ref = r.DefaultBranch
	}
	return r
}

// listAPI pages through an org or user repo listing.
func (p *Provider) listAPI(ctx context.Context, t model.Target) ([]model.Repo, error) {
	ts, ok := p.list.(auth.TokenSource)
	if !ok {
		return nil, fmt.Errorf("github: listing %s needs token or app credentials (auth method %q); set list_auth or a static repos list: %w",
			t, p.list.Method(), vcs.ErrUnsupported)
	}
	owner := url.PathEscape(t.Owner)
	var next string
	switch t.Kind {
	case model.TargetOrg:
		next = p.api + "/orgs/" + owner + "/repos?per_page=100&type=all"
	case model.TargetUser:
		if p.isTokenUser(ctx, ts, t.Owner) {
			// includes the user's private repos
			next = p.api + "/user/repos?per_page=100&affiliation=owner&visibility=all"
		} else {
			next = p.api + "/users/" + owner + "/repos?per_page=100&type=owner"
		}
	default:
		return nil, fmt.Errorf("github: unknown target kind %q", t.Kind)
	}
	var out []model.Repo
	for next != "" {
		var page []apiRepo
		n, err := p.getJSON(ctx, ts, t.Owner, next, &page)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", t, err)
		}
		next = n
		for _, a := range page {
			r := p.toRepo(a, t)
			if !matchFilter(t.Filter, r) {
				continue
			}
			out = append(out, r)
			if t.Filter.MaxRepos > 0 && len(out) >= t.Filter.MaxRepos {
				return out, nil
			}
		}
	}
	return out, nil
}

// isTokenUser reports whether the List token is a token of user owner.
func (p *Provider) isTokenUser(ctx context.Context, ts auth.TokenSource, owner string) bool {
	if p.list.Method() != "token" {
		return false
	}
	p.userMu.Lock()
	defer p.userMu.Unlock()
	if p.userLogin == nil {
		var u struct {
			Login string `json:"login"`
		}
		if _, err := p.getJSON(ctx, ts, owner, p.api+"/user", &u); err != nil {
			p.log.Debug("token user lookup failed; using public user listing", "err", err)
			return false // retried next time
		}
		p.userLogin = &u.Login
	}
	return strings.EqualFold(*p.userLogin, owner)
}

// getRepo fetches one repository's metadata.
func (p *Provider) getRepo(ctx context.Context, ts auth.TokenSource, t model.Target, owner, name string) (model.Repo, error) {
	var a apiRepo
	if _, err := p.getJSON(ctx, ts, owner, p.repoURL(owner, name), &a); err != nil {
		return model.Repo{}, fmt.Errorf("get repo %s/%s: %w", owner, name, err)
	}
	return p.toRepo(a, t), nil
}

func (p *Provider) apiResolveRef(ctx context.Context, r model.Repo, ref string) (string, error) {
	resp, err := p.get(ctx, p.readToken, r.Owner, p.repoURL(r.Owner, r.Name, "commits", url.PathEscape(ref)), "application/vnd.github.sha")
	if err != nil {
		return "", fmt.Errorf("resolve %s@%s: %w", r.FullName(), ref, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return "", fmt.Errorf("github: resolve %s@%s: %w", r.FullName(), ref, err)
	}
	sha := strings.TrimSpace(string(b))
	if !isSHA(sha) {
		return "", fmt.Errorf("github: resolve %s@%s: unexpected response", r.FullName(), ref)
	}
	return sha, nil
}

func (p *Provider) apiListBranches(ctx context.Context, r model.Repo) ([]string, error) {
	var out []string
	u := p.repoURL(r.Owner, r.Name, "branches") + "?per_page=100"
	for u != "" {
		var page []struct {
			Name string `json:"name"`
		}
		next, err := p.getJSON(ctx, p.readToken, r.Owner, u, &page)
		if err != nil {
			return nil, fmt.Errorf("list branches of %s: %w", r.FullName(), err)
		}
		for _, b := range page {
			out = append(out, b.Name)
		}
		u = next
	}
	return out, nil
}

// apiListFiles uses the recursive Git Trees API. truncated reports a tree too
// large for one response.
func (p *Provider) apiListFiles(ctx context.Context, r model.Repo, sha string) (files []string, truncated bool, err error) {
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
		Truncated bool `json:"truncated"`
	}
	u := p.repoURL(r.Owner, r.Name, "git", "trees", url.PathEscape(sha)) + "?recursive=1"
	if _, err := p.getJSON(ctx, p.readToken, r.Owner, u, &tree); err != nil {
		return nil, false, fmt.Errorf("list files %s@%s: %w", r.FullName(), sha, err)
	}
	if tree.Truncated {
		return nil, true, nil
	}
	for _, e := range tree.Tree {
		if e.Type == "blob" {
			files = append(files, e.Path)
		}
	}
	return files, false, nil
}

// apiReadFile reads through the on-disk cache keyed by commit SHA.
func (p *Provider) apiReadFile(ctx context.Context, r model.Repo, sha, path string) ([]byte, error) {
	var cached string
	if isSHA(sha) {
		cached = filepath.Join(p.repoDir(r.Owner, r.Name), sha, filepath.FromSlash(path))
		if b, err := os.ReadFile(cached); err == nil {
			return b, nil
		}
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	u := p.repoURL(r.Owner, r.Name, "contents", strings.Join(segs, "/")) + "?ref=" + url.QueryEscape(sha)
	resp, err := p.get(ctx, p.readToken, r.Owner, u, "application/vnd.github.raw")
	if err != nil {
		return nil, fmt.Errorf("read %s@%s:%s: %w", r.FullName(), sha, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("github: read %s:%s: %w", r.FullName(), path, err)
	}
	if len(b) > maxFileSize {
		return nil, fmt.Errorf("github: read %s:%s: file larger than %d bytes", r.FullName(), path, maxFileSize)
	}
	if cached != "" {
		if err := writeAtomic(cached, b); err != nil {
			p.log.Warn("manifest cache write failed", "repo", r.FullName(), "err", err)
		}
	}
	return b, nil
}

// writeAtomic writes b to path through a temp file, so readers never see a
// partial file.
func writeAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(f.Name())
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		_ = os.Remove(f.Name())
		return err
	}
	return nil
}
