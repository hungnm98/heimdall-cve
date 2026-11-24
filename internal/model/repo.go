package model

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TargetKind says what a configured target points at.
type TargetKind string

const (
	TargetOrg  TargetKind = "org"  // every repo of an organisation
	TargetUser TargetKind = "user" // every repo of a personal account
	TargetRepo TargetKind = "repo" // a single repository URL
)

// Target is one entry of the `targets` config, resolved into repos by a vcs.Provider.
type Target struct {
	Kind     TargetKind
	Provider string // "github"
	BaseURL  string // API base URL; empty = provider default (GHES sets this)
	Owner    string // org or user login (also filled for kind=repo)
	Name     string // repo name, kind=repo only
	Branch   string // branch to scan; empty = default branch
	Auth     string // auth profile used to read code
	ListAuth string // auth profile used to list repos (needed when Auth is ssh)
	Repos    []string
	Filter   RepoFilter
}

// String is a human label such as "org:remitano" or "repo:remitano/foo".
func (t Target) String() string {
	if t.Kind == TargetRepo {
		return fmt.Sprintf("repo:%s/%s", t.Owner, t.Name)
	}
	return fmt.Sprintf("%s:%s", t.Kind, t.Owner)
}

// RepoFilter narrows the repos returned for org/user targets.
type RepoFilter struct {
	Include      []string // glob on repo name; empty = all
	Exclude      []string
	Topics       []string // repo must carry at least one of these topics
	SkipArchived bool
	SkipForks    bool
	SkipEmpty    bool
	MaxRepos     int // 0 = unlimited
}

// Repo is a repository discovered on a VCS provider.
type Repo struct {
	Provider      string
	Host          string // e.g. github.com
	Owner         string
	Name          string
	HTMLURL       string
	CloneURL      string // https
	SSHURL        string
	DefaultBranch string
	Ref           string // branch to scan: Target.Branch or DefaultBranch
	Private       bool
	Archived      bool
	Fork          bool
	Empty         bool
	Topics        []string
	Auth          string // auth profile used to read it
}

// FullName is "owner/name".
func (r Repo) FullName() string { return r.Owner + "/" + r.Name }

// RepoState remembers what was scanned last time, for incremental scans.
type RepoState struct {
	Repo      string // full name
	Ref       string
	HeadSHA   string
	ScannedAt time.Time
}

// RepoURL is a parsed repository URL.
type RepoURL struct {
	Host  string
	Owner string
	Name  string
	SSH   bool
}

// ParseRepoURL accepts https://host/owner/name(.git), git@host:owner/name(.git)
// and ssh://[user@]host[:port]/owner/name(.git).
func ParseRepoURL(raw string) (RepoURL, error) {
	raw = strings.TrimSpace(raw)
	var host, path string
	ssh := false
	switch {
	case strings.Contains(raw, "://"):
		u, err := url.Parse(raw)
		if err != nil {
			return RepoURL{}, fmt.Errorf("parse repo url %q: %w", raw, err)
		}
		if u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "ssh" {
			return RepoURL{}, fmt.Errorf("repo url %q: unsupported scheme %q", raw, u.Scheme)
		}
		ssh = u.Scheme == "ssh"
		host, path = u.Hostname(), u.Path
	case strings.Contains(raw, "@") && strings.Contains(raw, ":"):
		// scp-like: git@github.com:owner/name.git
		at := strings.Index(raw, "@")
		rest := raw[at+1:]
		colon := strings.Index(rest, ":")
		host, path, ssh = rest[:colon], rest[colon+1:], true
	default:
		return RepoURL{}, fmt.Errorf("repo url %q: expected https://, ssh:// or git@host:owner/name", raw)
	}
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	parts := strings.Split(path, "/")
	if host == "" || len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return RepoURL{}, fmt.Errorf("repo url %q: expected <host>/<owner>/<name>", raw)
	}
	return RepoURL{Host: host, Owner: parts[0], Name: parts[1], SSH: ssh}, nil
}
