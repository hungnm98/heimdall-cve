package memstore

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

var _ store.Catalog = (*Store)(nil)

// catalog is the in-memory store.Catalog state, guarded by its own mutex.
type catalog struct {
	mu       sync.Mutex
	seq      int64
	profiles map[int64]model.AuthProfile
	secrets  map[int64]store.SecretRecord
	targets  map[int64]model.TargetSpec
	repos    map[string]model.RepoRecord
	jobs     map[int64]model.Job
	events   []model.JobEvent
	audit    []model.AuditEntry
	suppr    map[string]model.Suppression
	now      func() time.Time
}

func (c *catalog) init() {
	if c.profiles == nil {
		c.profiles = map[int64]model.AuthProfile{}
		c.secrets = map[int64]store.SecretRecord{}
		c.targets = map[int64]model.TargetSpec{}
		c.repos = map[string]model.RepoRecord{}
		c.jobs = map[int64]model.Job{}
		c.suppr = map[string]model.Suppression{}
		c.now = time.Now
	}
}

func (c *catalog) next() int64 { c.seq++; return c.seq }

func notFound(what string, id any) error { return fmt.Errorf("%s %v: %w", what, id, store.ErrNotFound) }

// ---- auth profiles ----

func (s *Store) ListAuthProfiles(context.Context) ([]model.AuthProfile, error) {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	out := make([]model.AuthProfile, 0, len(c.profiles))
	for _, p := range c.profiles {
		out = append(out, cloneProfile(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) GetAuthProfile(_ context.Context, name string) (*model.AuthProfile, error) {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	for _, p := range c.profiles {
		if p.Name == name {
			p = cloneProfile(p)
			return &p, nil
		}
	}
	return nil, notFound("auth profile", name)
}

func (s *Store) SaveAuthProfile(_ context.Context, p *model.AuthProfile) error {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	for id, o := range c.profiles {
		if o.Name == p.Name && id != p.ID {
			return fmt.Errorf("auth profile %q: %w", p.Name, store.ErrConflict)
		}
	}
	now := c.now()
	if p.ID == 0 {
		p.ID, p.CreatedAt = c.next(), now
	} else if old, ok := c.profiles[p.ID]; ok {
		p.CreatedAt = old.CreatedAt
		if old.Name != p.Name { // keep target references valid (ON UPDATE CASCADE)
			for id, t := range c.targets {
				if t.Auth == old.Name {
					t.Auth = p.Name
				}
				if t.ListAuth == old.Name {
					t.ListAuth = p.Name
				}
				c.targets[id] = t
			}
		}
	} else {
		return notFound("auth profile", p.ID)
	}
	p.UpdatedAt = now
	c.profiles[p.ID] = cloneProfile(*p)
	return nil
}

func (s *Store) DeleteAuthProfile(_ context.Context, name string) error {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	for _, t := range c.targets {
		if t.Auth == name || t.ListAuth == name {
			return fmt.Errorf("auth profile %q is used by target %d: %w", name, t.ID, store.ErrConflict)
		}
	}
	for id, p := range c.profiles {
		if p.Name == name {
			delete(c.profiles, id)
			return nil
		}
	}
	return notFound("auth profile", name)
}

// ---- secrets ----

func (s *Store) SaveSecret(_ context.Context, r *store.SecretRecord) error {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	if r.ID == 0 {
		r.ID, r.CreatedAt = c.next(), c.now()
	} else if old, ok := c.secrets[r.ID]; ok {
		r.CreatedAt = old.CreatedAt
	} else {
		return notFound("secret", r.ID)
	}
	c.secrets[r.ID] = *r
	return nil
}

func (s *Store) GetSecret(_ context.Context, id int64) (*store.SecretRecord, error) {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	r, ok := c.secrets[id]
	if !ok {
		return nil, notFound("secret", id)
	}
	return &r, nil
}

func (s *Store) ListSecrets(context.Context) ([]store.SecretRecord, error) {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	out := make([]store.SecretRecord, 0, len(c.secrets))
	for _, r := range c.secrets {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) DeleteSecret(_ context.Context, id int64) error {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	if _, ok := c.secrets[id]; !ok {
		return notFound("secret", id)
	}
	for _, p := range c.profiles {
		if p.SecretID != nil && *p.SecretID == id {
			return fmt.Errorf("secret %d is used by auth profile %q: %w", id, p.Name, store.ErrConflict)
		}
	}
	delete(c.secrets, id)
	return nil
}

// ---- targets ----

func (s *Store) ListTargets(_ context.Context, f store.TargetFilter) ([]model.TargetSpec, error) {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	var out []model.TargetSpec
	for _, t := range c.targets {
		if (f.Enabled == nil || t.Enabled == *f.Enabled) && (f.Origin == "" || t.Origin == f.Origin) {
			out = append(out, cloneTarget(t))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) GetTarget(_ context.Context, id int64) (*model.TargetSpec, error) {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	t, ok := c.targets[id]
	if !ok {
		return nil, notFound("target", id)
	}
	t = cloneTarget(t)
	return &t, nil
}

func (s *Store) SaveTarget(_ context.Context, t *model.TargetSpec) error {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	for _, name := range []string{t.Auth, t.ListAuth} {
		if name != "" && !c.hasProfile(name) {
			return fmt.Errorf("auth profile %q does not exist: %w", name, store.ErrConflict)
		}
	}
	now := c.now()
	if t.ID == 0 {
		t.ID, t.CreatedAt = c.next(), now
	} else if old, ok := c.targets[t.ID]; ok {
		t.CreatedAt = old.CreatedAt
	} else {
		return notFound("target", t.ID)
	}
	t.UpdatedAt = now
	c.targets[t.ID] = cloneTarget(*t)
	return nil
}

func (c *catalog) hasProfile(name string) bool {
	for _, p := range c.profiles {
		if p.Name == name {
			return true
		}
	}
	return false
}

func (s *Store) DeleteTarget(_ context.Context, id int64) error {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	if _, ok := c.targets[id]; !ok {
		return notFound("target", id)
	}
	delete(c.targets, id)
	for name, r := range c.repos { // cached repos go with their target
		if r.TargetID == id {
			delete(c.repos, name)
		}
	}
	return nil
}

func (s *Store) DueTargets(_ context.Context, now time.Time) ([]model.TargetSpec, error) {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	var out []model.TargetSpec
	for _, t := range c.targets {
		if t.Enabled && t.NextRunAt != nil && !t.NextRunAt.After(now) {
			out = append(out, cloneTarget(t))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].NextRunAt.Equal(*out[j].NextRunAt) {
			return out[i].NextRunAt.Before(*out[j].NextRunAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (s *Store) DuePolls(_ context.Context, now time.Time) ([]model.TargetSpec, error) {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	var out []model.TargetSpec
	for _, t := range c.targets {
		if t.Enabled && t.NextPollAt != nil && !t.NextPollAt.After(now) {
			out = append(out, cloneTarget(t))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].NextPollAt.Equal(*out[j].NextPollAt) {
			return out[i].NextPollAt.Before(*out[j].NextPollAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// ---- repos ----

func (s *Store) UpsertRepos(_ context.Context, targetID int64, repos []model.Repo, at time.Time) error {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	if _, ok := c.targets[targetID]; !ok {
		return notFound("target", targetID)
	}
	for _, r := range repos {
		rec := c.repos[r.FullName()]
		rec.Repo, rec.TargetID, rec.LastListedAt = cloneRepo(r), targetID, at
		c.repos[r.FullName()] = rec
	}
	return nil
}

func (s *Store) ListRepos(_ context.Context, f store.RepoFilter) ([]model.RepoRecord, error) {
	sortKey, order, err := store.ResolveRepoSort(f.Sort, f.Order)
	if err != nil {
		return nil, err
	}
	var cur *store.RepoKey
	if f.After != "" {
		k, err := store.ParseRepoCursor(f)
		if err != nil {
			return nil, err
		}
		cur = &k
	}
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	var out []model.RepoRecord
	for name, r := range c.repos {
		if (f.TargetID == 0 || r.TargetID == f.TargetID) &&
			(f.Query == "" || strings.Contains(strings.ToLower(name), strings.ToLower(f.Query))) &&
			(cur == nil || store.RepoKeyOf(r, sortKey, order).Compare(*cur) > 0) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return store.RepoKeyOf(out[i], sortKey, order).Compare(store.RepoKeyOf(out[j], sortKey, order)) < 0
	})
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (s *Store) GetRepo(_ context.Context, fullName string) (*model.RepoRecord, error) {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	r, ok := c.repos[fullName]
	if !ok {
		return nil, notFound("repo", fullName)
	}
	return &r, nil
}

func (s *Store) MarkRepoScanned(_ context.Context, fullName, headSHA string, at time.Time) error {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	r, ok := c.repos[fullName]
	if !ok {
		return notFound("repo", fullName)
	}
	r.LastHeadSHA, r.LastScannedAt = headSHA, &at
	c.repos[fullName] = r
	return nil
}

// ---- jobs ----

func sameScope(a, b model.Job) bool {
	return a.Repo == b.Repo && ((a.TargetID == nil && b.TargetID == nil) ||
		(a.TargetID != nil && b.TargetID != nil && *a.TargetID == *b.TargetID))
}

func (s *Store) CreateJob(_ context.Context, j *model.Job) (bool, error) {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	for _, o := range c.jobs {
		if o.Status.Active() && sameScope(o, *j) {
			*j = o
			return false, nil
		}
	}
	j.ID, j.CreatedAt = c.next(), c.now()
	if j.Status == "" {
		j.Status = model.JobQueued
	}
	c.jobs[j.ID] = *j
	return true, nil
}

func (s *Store) GetJob(_ context.Context, id int64) (*model.Job, error) {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	j, ok := c.jobs[id]
	if !ok {
		return nil, notFound("job", id)
	}
	return &j, nil
}

func (s *Store) ListJobs(_ context.Context, f store.JobFilter) ([]model.Job, error) {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	var out []model.Job
	for _, j := range c.jobs {
		if (f.Status == "" || j.Status == f.Status) &&
			(f.TargetID == 0 || (j.TargetID != nil && *j.TargetID == f.TargetID)) &&
			(f.BeforeID == 0 || j.ID < f.BeforeID) {
			out = append(out, j)
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].ID > out[k].ID })
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (s *Store) UpdateJob(_ context.Context, j *model.Job) error {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	old, ok := c.jobs[j.ID]
	if !ok {
		return notFound("job", j.ID)
	}
	j.CreatedAt = old.CreatedAt
	c.jobs[j.ID] = *j
	return nil
}

func (s *Store) AppendJobEvent(_ context.Context, e *model.JobEvent) error {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	if _, ok := c.jobs[e.JobID]; !ok {
		return notFound("job", e.JobID)
	}
	e.ID = c.next()
	if e.At.IsZero() {
		e.At = c.now()
	}
	c.events = append(c.events, *e)
	return nil
}

func (s *Store) ListJobEvents(_ context.Context, jobID, afterID int64, limit int) ([]model.JobEvent, error) {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	var out []model.JobEvent
	for _, e := range c.events { // appended in ID order
		if e.JobID == jobID && e.ID > afterID {
			out = append(out, e)
			if limit > 0 && len(out) == limit {
				break
			}
		}
	}
	return out, nil
}

// ---- suppressions ----
// Lock order: Store.mu (findings) before catalog.mu.

func (s *Store) SaveSuppression(_ context.Context, sp *model.Suppression) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.findings[sp.FindingID]
	if !ok {
		return notFound("finding", sp.FindingID)
	}
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	if old, ok := c.suppr[sp.FindingID]; ok {
		sp.CreatedAt = old.CreatedAt
	} else if sp.CreatedAt.IsZero() {
		sp.CreatedAt = c.now()
	}
	c.suppr[sp.FindingID] = *sp
	f.Status = model.StatusSuppressed
	s.findings[sp.FindingID] = f
	return nil
}

func (s *Store) GetSuppression(_ context.Context, findingID string) (*model.Suppression, error) {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	sp, ok := c.suppr[findingID]
	if !ok {
		return nil, notFound("suppression", findingID)
	}
	return &sp, nil
}

func (s *Store) DeleteSuppression(_ context.Context, findingID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	if _, ok := c.suppr[findingID]; !ok {
		return notFound("suppression", findingID)
	}
	delete(c.suppr, findingID)
	if f, ok := s.findings[findingID]; ok && f.Status == model.StatusSuppressed {
		f.Status = model.StatusOpen
		s.findings[findingID] = f
	}
	return nil
}

func (s *Store) ExpiredSuppressions(_ context.Context, now time.Time) ([]model.Suppression, error) {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	var out []model.Suppression
	for _, sp := range c.suppr {
		if !sp.ExpiresAt.After(now) {
			out = append(out, sp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FindingID < out[j].FindingID })
	return out, nil
}

// ---- audit ----

func (s *Store) AppendAudit(_ context.Context, e *model.AuditEntry) error {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	e.ID = c.next()
	if e.At.IsZero() {
		e.At = c.now()
	}
	cp := *e
	cp.Details = maps.Clone(e.Details)
	c.audit = append(c.audit, cp)
	return nil
}

func (s *Store) ListAudit(_ context.Context, beforeID int64, limit int) ([]model.AuditEntry, error) {
	c := &s.cat
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	var out []model.AuditEntry
	for i := len(c.audit) - 1; i >= 0; i-- {
		e := c.audit[i]
		if beforeID == 0 || e.ID < beforeID {
			out = append(out, e)
			if limit > 0 && len(out) == limit {
				break
			}
		}
	}
	return out, nil
}

// ---- copies (callers must not alias internal state) ----

func cloneProfile(p model.AuthProfile) model.AuthProfile {
	p.Options = maps.Clone(p.Options)
	if p.SecretID != nil {
		id := *p.SecretID
		p.SecretID = &id
	}
	return p
}

func cloneTarget(t model.TargetSpec) model.TargetSpec {
	t.Repos = append([]string(nil), t.Repos...)
	t.Branches = append([]string(nil), t.Branches...)
	t.Filter.Include = append([]string(nil), t.Filter.Include...)
	t.Filter.Exclude = append([]string(nil), t.Filter.Exclude...)
	t.Filter.Topics = append([]string(nil), t.Filter.Topics...)
	if t.NextRunAt != nil {
		n := *t.NextRunAt
		t.NextRunAt = &n
	}
	if t.NextPollAt != nil {
		n := *t.NextPollAt
		t.NextPollAt = &n
	}
	return t
}

func cloneRepo(r model.Repo) model.Repo {
	r.Topics = append([]string(nil), r.Topics...)
	return r
}
