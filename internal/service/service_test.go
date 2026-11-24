package service_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/jobs"
	"github.com/hungnm98/heimdall-cve/internal/jobs/inline"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/hungnm98/heimdall-cve/internal/service"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/hungnm98/heimdall-cve/internal/store/memstore"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
)

var t0 = time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)

// countingJobs wraps a backend and counts calls.
type countingJobs struct {
	jobs.Backend
	mu       sync.Mutex
	enqueued []int64
	canceled []int64
	failNext error
}

func (c *countingJobs) Enqueue(ctx context.Context, id int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failNext != nil {
		err := c.failNext
		c.failNext = nil
		return err
	}
	c.enqueued = append(c.enqueued, id)
	return c.Backend.Enqueue(ctx, id)
}

func (c *countingJobs) Cancel(ctx context.Context, id int64) error {
	c.mu.Lock()
	c.canceled = append(c.canceled, id)
	c.mu.Unlock()
	return c.Backend.Cancel(ctx, id)
}

type fakeProvider struct {
	repos []model.Repo
	err   error
}

func (p *fakeProvider) Name() string { return "github" }
func (p *fakeProvider) ListRepos(context.Context, model.Target) ([]model.Repo, error) {
	return p.repos, p.err
}
func (p *fakeProvider) ResolveRef(context.Context, model.Repo, string) (string, error) {
	return "", nil
}
func (p *fakeProvider) ListFiles(context.Context, model.Repo, string) ([]string, error) {
	return nil, nil
}
func (p *fakeProvider) ReadFile(context.Context, model.Repo, string, string) ([]byte, error) {
	return nil, nil
}
func (p *fakeProvider) Checkout(context.Context, model.Repo, string, string) error { return nil }

type env struct {
	st   *memstore.Store
	jobs *countingJobs
	keys *secret.KeyRing
	prov *fakeProvider
	svc  *service.Services
	now  time.Time
}

func newKeyRing(t *testing.T) *secret.KeyRing {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	kr, err := secret.NewKeyRing(base64.StdEncoding.EncodeToString(b))
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func newEnv(t *testing.T, withKeys bool) *env {
	t.Helper()
	ib, err := inline.New(plugin.Config{}, plugin.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{st: memstore.New(), jobs: &countingJobs{Backend: ib}, prov: &fakeProvider{}, now: t0}
	if withKeys {
		e.keys = newKeyRing(t)
	}
	e.svc = service.New(service.Deps{
		Store: e.st, Jobs: e.jobs, Keys: e.keys,
		ProviderFor: func(context.Context, model.Target) (vcs.Provider, error) { return e.prov, nil },
		Now:         func() time.Time { return e.now },
	})
	return e
}

func strp(s string) *string { return &s }

func (e *env) profile(t *testing.T, name, typ string) {
	t.Helper()
	if _, err := e.svc.AuthProfiles.Create(context.Background(), "alice", service.AuthProfileInput{Name: name, Type: typ}); err != nil {
		t.Fatal(err)
	}
}

func fieldsOf(t *testing.T, err error) map[string]string {
	t.Helper()
	var ve *service.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want *ValidationError, got %v", err)
	}
	return ve.Fields
}

func auditActions(t *testing.T, st *memstore.Store) []string {
	t.Helper()
	es, err := st.ListAudit(context.Background(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := len(es) - 1; i >= 0; i-- {
		out = append(out, es[i].Action)
	}
	return out
}

func TestTargetValidation(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	_, err := e.svc.Targets.Create(ctx, "a", service.TargetInput{Kind: "team", Schedule: "not cron"})
	f := fieldsOf(t, err)
	for _, k := range []string{"kind", "auth", "schedule"} {
		if f[k] == "" {
			t.Errorf("missing field error %q in %v", k, f)
		}
	}
	_, err = e.svc.Targets.Create(ctx, "a", service.TargetInput{Kind: model.TargetRepo, URL: "ftp://x", Auth: "nope"})
	f = fieldsOf(t, err)
	if f["url"] == "" || f["auth"] == "" {
		t.Errorf("fields %v", f)
	}
	e.profile(t, "ssh-key", "ssh")
	_, err = e.svc.Targets.Create(ctx, "a", service.TargetInput{Kind: model.TargetOrg, Owner: "acme", Auth: "ssh-key"})
	if fieldsOf(t, err)["list_auth"] == "" {
		t.Error("ssh org target without list_auth must fail")
	}
	_, err = e.svc.Targets.Create(ctx, "a", service.TargetInput{Kind: model.TargetRepo, URL: "https://git.corp/acme/api", Auth: "ssh-key"})
	if fieldsOf(t, err)["base_url"] == "" {
		t.Error("non-github host without base_url must fail")
	}
}

func TestTargetCRUDAndSchedule(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.profile(t, "pat", "token")
	tg, err := e.svc.Targets.Create(ctx, "alice", service.TargetInput{
		Kind: model.TargetRepo, URL: "git@github.com:acme/api.git", Auth: "pat", Schedule: "0 2 * * *", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tg.Owner != "acme" || tg.Name != "api" || tg.Provider != "github" || tg.ListAuth != "pat" || tg.Origin != model.OriginUI {
		t.Fatalf("target %+v", tg)
	}
	want := time.Date(2026, 1, 11, 2, 0, 0, 0, time.UTC)
	if tg.NextRunAt == nil || !tg.NextRunAt.Equal(want) {
		t.Fatalf("next run %v, want %v", tg.NextRunAt, want)
	}
	tg, err = e.svc.Targets.Update(ctx, "alice", tg.ID, service.TargetInput{Kind: model.TargetOrg, Owner: "acme", Auth: "pat", Enabled: false, Schedule: "0 2 * * *"})
	if err != nil {
		t.Fatal(err)
	}
	if tg.NextRunAt != nil {
		t.Fatal("disabled target must not be scheduled")
	}
	if err := e.svc.Targets.Delete(ctx, "alice", tg.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Targets.Get(ctx, tg.ID); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
	got := strings.Join(auditActions(t, e.st), ",")
	if got != "auth_profile.create,target.create,target.update,target.delete" {
		t.Fatalf("audit %s", got)
	}
}

func TestConfigOriginReadOnly(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	p := &model.AuthProfile{Name: "cfg", Type: "token", Options: map[string]any{"token_env": "GITHUB_TOKEN"}, Origin: model.OriginConfig}
	if err := e.st.SaveAuthProfile(ctx, p); err != nil {
		t.Fatal(err)
	}
	tg := &model.TargetSpec{Target: model.Target{Kind: model.TargetOrg, Owner: "acme", Auth: "cfg", Provider: "github"}, Origin: model.OriginConfig, Enabled: true}
	if err := e.st.SaveTarget(ctx, tg); err != nil {
		t.Fatal(err)
	}
	in := service.TargetInput{Kind: model.TargetOrg, Owner: "acme", Auth: "cfg"}
	if _, err := e.svc.Targets.Update(ctx, "a", tg.ID, in); !errors.Is(err, service.ErrReadOnly) {
		t.Fatal(err)
	}
	if err := e.svc.Targets.Delete(ctx, "a", tg.ID); !errors.Is(err, service.ErrReadOnly) {
		t.Fatal(err)
	}
	if _, err := e.svc.AuthProfiles.Update(ctx, "a", "cfg", service.AuthProfileInput{Name: "cfg", Type: "token"}); !errors.Is(err, service.ErrReadOnly) {
		t.Fatal(err)
	}
	if err := e.svc.AuthProfiles.Delete(ctx, "a", "cfg"); !errors.Is(err, service.ErrReadOnly) {
		t.Fatal(err)
	}
}

func TestTargetPreview(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.profile(t, "pat", "token")
	e.prov.repos = []model.Repo{{Owner: "acme", Name: "api"}}
	repos, err := e.svc.Targets.Preview(ctx, service.TargetInput{Kind: model.TargetOrg, Owner: "acme", Auth: "pat"})
	if err != nil || len(repos) != 1 {
		t.Fatal(repos, err)
	}
	e.prov.err = errors.New("401")
	_, err = e.svc.Targets.Preview(ctx, service.TargetInput{Kind: model.TargetOrg, Owner: "acme", Auth: "pat"})
	var up *service.UpstreamError
	if !errors.As(err, &up) {
		t.Fatal(err)
	}
	noProv := service.New(service.Deps{Store: e.st})
	if _, err := noProv.Targets.Preview(ctx, service.TargetInput{Kind: model.TargetOrg, Owner: "acme", Auth: "pat"}); !errors.Is(err, service.ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestAuthProfileSecretSealing(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	const value = "ghp_verysecretvalue1234"
	p, err := e.svc.AuthProfiles.Create(ctx, "alice", service.AuthProfileInput{Name: "pat", Type: "token", Secret: strp(value), Options: map[string]any{"base_url": "https://api.github.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.SecretID == nil || p.SecretFingerprint != secret.Fingerprint(value) {
		t.Fatalf("profile %+v", p)
	}
	if p.Options["token_ref"] != itoa(*p.SecretID) {
		t.Fatalf("token_ref %v", p.Options)
	}
	recs, _ := e.st.ListSecrets(ctx)
	if len(recs) != 1 {
		t.Fatalf("secrets %d", len(recs))
	}
	rec := recs[0]
	if bytes.Contains(rec.Sealed.Ciphertext, []byte("verysecret")) || bytes.Contains(rec.Sealed.WrappedDEK, []byte("verysecret")) {
		t.Fatal("plaintext stored")
	}
	if got, err := e.keys.Open(rec.Sealed, service.SecretAAD(rec.ID)); err != nil || string(got) != value {
		t.Fatalf("open: %q %v", got, err)
	}
	// Nothing else in the catalog holds the value.
	stored, _ := e.st.GetAuthProfile(ctx, "pat")
	for k, v := range stored.Options {
		if s, _ := v.(string); strings.Contains(s, "verysecret") {
			t.Fatalf("option %s leaks the secret", k)
		}
	}
	audit, _ := e.st.ListAudit(ctx, 0, 0)
	for _, a := range audit {
		for k, v := range a.Details {
			if s, _ := v.(string); strings.Contains(s, "verysecret") {
				t.Fatalf("audit detail %s leaks the secret", k)
			}
		}
	}

	// Update without secret keeps the ref; with secret replaces the value in place.
	p, err = e.svc.AuthProfiles.Update(ctx, "alice", "pat", service.AuthProfileInput{Name: "pat-2", Type: "token"})
	if err != nil || p.Options["token_ref"] != itoa(rec.ID) || *p.SecretID != rec.ID {
		t.Fatalf("update kept secret? %+v %v", p, err)
	}
	if _, err := e.svc.AuthProfiles.Update(ctx, "alice", "pat-2", service.AuthProfileInput{Name: "pat-2", Type: "app"}); fieldsOf(t, err)["secret"] == "" {
		t.Fatal("changing type must require a new secret")
	}
	p, err = e.svc.AuthProfiles.Update(ctx, "alice", "pat-2", service.AuthProfileInput{Name: "pat-2", Type: "token", Secret: strp("ghp_newvalue_abcdefgh")})
	if err != nil || *p.SecretID != rec.ID {
		t.Fatalf("replace: %+v %v", p, err)
	}
	r2, _ := e.st.GetSecret(ctx, rec.ID)
	if got, _ := e.keys.Open(r2.Sealed, service.SecretAAD(rec.ID)); string(got) != "ghp_newvalue_abcdefgh" {
		t.Fatalf("replaced value %q", got)
	}
	if _, err := e.keys.Open(r2.Sealed, service.SecretAAD(rec.ID+1)); err == nil {
		t.Fatal("aad must bind the record id")
	}

	if _, err := e.svc.AuthProfiles.Create(ctx, "a", service.AuthProfileInput{Name: "x", Type: "token", Options: map[string]any{"token": "inline"}}); fieldsOf(t, err)["options"] == "" {
		t.Fatal("inline secret option must be rejected")
	}
	if err := e.svc.AuthProfiles.Delete(ctx, "alice", "pat-2"); err != nil {
		t.Fatal(err)
	}
	if recs, _ := e.st.ListSecrets(ctx); len(recs) != 0 {
		t.Fatal("secret must be deleted with its profile")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestAuthProfileSecretsDisabled(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	if e.svc.AuthProfiles.SecretsEnabled() {
		t.Fatal("no keys")
	}
	_, err := e.svc.AuthProfiles.Create(ctx, "a", service.AuthProfileInput{Name: "pat", Type: "token", Secret: strp("ghp_x")})
	if !errors.Is(err, service.ErrUnavailable) {
		t.Fatal(err)
	}
	if recs, _ := e.st.ListSecrets(ctx); len(recs) != 0 {
		t.Fatal("nothing stored")
	}
	_, err = e.svc.AuthProfiles.Create(ctx, "a", service.AuthProfileInput{Name: "Bad Name", Type: "nope"})
	f := fieldsOf(t, err)
	if f["name"] == "" || f["type"] == "" {
		t.Fatal(f)
	}
	e.profile(t, "pat", "token")
	if _, err := e.svc.AuthProfiles.Create(ctx, "a", service.AuthProfileInput{Name: "pat", Type: "token"}); !errors.Is(err, service.ErrConflict) {
		t.Fatal(err)
	}
}

func TestAuthProfileTest(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.profile(t, "pat", "token")
	res, err := e.svc.AuthProfiles.Test(ctx, "pat")
	if err != nil || !res.OK {
		t.Fatal(res, err)
	}
	if _, err := e.svc.Targets.Create(ctx, "a", service.TargetInput{Kind: model.TargetOrg, Owner: "acme", Auth: "pat"}); err != nil {
		t.Fatal(err)
	}
	e.prov.repos = []model.Repo{{}, {}}
	if res, _ := e.svc.AuthProfiles.Test(ctx, "pat"); !res.OK || !strings.Contains(res.Message, "2 repos") {
		t.Fatal(res)
	}
	e.prov.err = errors.New("bad credentials")
	if res, _ := e.svc.AuthProfiles.Test(ctx, "pat"); res.OK {
		t.Fatal(res)
	}
	if _, err := e.svc.AuthProfiles.Test(ctx, "missing"); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestJobTriggerIdempotentAndCancel(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.profile(t, "pat", "token")
	tg, err := e.svc.Targets.Create(ctx, "a", service.TargetInput{Kind: model.TargetOrg, Owner: "acme", Auth: "pat", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	j1, created, err := e.svc.Jobs.Trigger(ctx, "bob", service.JobRequest{TargetID: &tg.ID})
	if err != nil || !created || j1.Status != model.JobQueued || j1.RequestedBy != "bob" || j1.Trigger != model.TriggerManual {
		t.Fatal(j1, created, err)
	}
	j2, created, err := e.svc.Jobs.Trigger(ctx, "bob", service.JobRequest{TargetID: &tg.ID})
	if err != nil || created || j2.ID != j1.ID {
		t.Fatal(j2, created, err)
	}
	if len(e.jobs.enqueued) != 1 {
		t.Fatalf("enqueued %v", e.jobs.enqueued)
	}
	if err := e.svc.Jobs.Cancel(ctx, "bob", j1.ID); err != nil {
		t.Fatal(err)
	}
	j, _ := e.svc.Jobs.Get(ctx, j1.ID)
	if j.Status != model.JobCanceled || j.FinishedAt == nil || len(e.jobs.canceled) != 1 {
		t.Fatalf("job %+v canceled %v", j, e.jobs.canceled)
	}
	if err := e.svc.Jobs.Cancel(ctx, "bob", j1.ID); !errors.Is(err, service.ErrConflict) {
		t.Fatal(err)
	}
	evs, err := e.svc.Jobs.Events(ctx, j1.ID, 0, 0)
	if err != nil || len(evs) != 1 || evs[0].Level != "warn" {
		t.Fatal(evs, err)
	}
	// A new trigger after cancel creates a new job.
	j3, created, _ := e.svc.Jobs.Trigger(ctx, "bob", service.JobRequest{TargetID: &tg.ID})
	if !created || j3.ID == j1.ID {
		t.Fatal("new job expected")
	}
	if _, _, err := e.svc.Jobs.Trigger(ctx, "bob", service.JobRequest{TargetID: ptr(int64(999))}); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := e.svc.Jobs.Get(ctx, 999); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
}

func ptr[T any](v T) *T { return &v }

func TestJobTriggerAdHocAndAll(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	_, _, err := e.svc.Jobs.Trigger(ctx, "a", service.JobRequest{RepoURL: "nope"})
	f := fieldsOf(t, err)
	if f["repo_url"] == "" || f["auth_profile"] == "" {
		t.Fatal(f)
	}
	e.profile(t, "pat", "token")
	j, created, err := e.svc.Jobs.Trigger(ctx, "a", service.JobRequest{RepoURL: "https://github.com/acme/api.git", AuthProfile: "pat", Branch: "dev"})
	if err != nil || !created || j.Repo != "acme/api" || j.AuthProfile != "pat" || j.Branch != "dev" || j.TargetID != nil {
		t.Fatal(j, err)
	}
	all, created, err := e.svc.Jobs.Trigger(ctx, "a", service.JobRequest{})
	if err != nil || !created || all.TargetID != nil || all.Repo != "" {
		t.Fatal(all, err)
	}
	// Enqueue failure marks the job failed so the scope is not blocked.
	e.jobs.failNext = errors.New("queue down")
	tg, _ := e.svc.Targets.Create(ctx, "a", service.TargetInput{Kind: model.TargetOrg, Owner: "acme", Auth: "pat"})
	if _, _, err := e.svc.Jobs.Trigger(ctx, "a", service.JobRequest{TargetID: &tg.ID}); err == nil {
		t.Fatal("enqueue error expected")
	}
	failed, _ := e.st.ListJobs(ctx, store.JobFilter{Status: model.JobFailed})
	if len(failed) != 1 {
		t.Fatal(failed)
	}
}

func seedFindings(t *testing.T, st *memstore.Store, n int) []model.Finding {
	t.Helper()
	ctx := context.Background()
	run := &model.ScanRun{StartedAt: t0}
	if err := st.StartRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	sevs := []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityLow}
	var fs []model.Finding
	for i := 0; i < n; i++ {
		f := model.Finding{
			Kind: model.KindDependency, Provider: "github", Repo: "acme/api", ManifestPath: "go.mod",
			Package: model.NewPackage(model.EcosystemGo, "example.com/m", "v1.0.0"), AdvisoryID: "GO-" + itoa(int64(i)),
			Severity: sevs[i%3], InKEV: i == 0, Sources: []string{"osv"}, Verified: true, Priority: float64(i),
			RecommendedVersion: "v1.2.0", Bump: model.BumpMinor,
		}
		f.ComputeID()
		fs = append(fs, f)
	}
	rt := model.Finding{Kind: model.KindRuntime, Provider: "github", Repo: "acme/api", ManifestPath: "go.mod", AdvisoryID: "EOL-go-1.20",
		Severity: model.SeverityMedium, Runtime: &model.RuntimeStatus{Runtime: model.Runtime{Name: "go", Version: "1.20"}, Status: model.SupportEOL}}
	rt.ComputeID()
	fs = append(fs, rt)
	if _, err := st.RecordFindings(ctx, run.ID, []string{"acme/api"}, fs, t0); err != nil {
		t.Fatal(err)
	}
	run.Status, run.FinishedAt = model.RunPartial, t0.Add(time.Minute)
	run.Sources = []model.SourceHealth{{Name: "osv", Healthy: true}, {Name: "kev", Healthy: false, Error: "timeout"}}
	if err := st.FinishRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	return fs
}

func TestFindingsPaginationAndSuppress(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	seedFindings(t, e.st, 7)
	var seen []string
	cursor := ""
	for pages := 0; ; pages++ {
		p, err := e.svc.Findings.List(ctx, store.FindingFilter{Limit: 3, After: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range p.Items {
			seen = append(seen, f.ID)
		}
		if p.NextCursor == "" {
			if pages != 2 {
				t.Fatalf("pages %d", pages)
			}
			break
		}
		cursor = p.NextCursor
	}
	if len(seen) != 8 {
		t.Fatalf("seen %d", len(seen))
	}
	if _, err := e.svc.Findings.List(ctx, store.FindingFilter{After: "!!"}); fieldsOf(t, err)["cursor"] == "" {
		t.Fatal("bad cursor")
	}
	if _, err := e.svc.Findings.List(ctx, store.FindingFilter{Sort: store.SortName, After: cursor}); fieldsOf(t, err)["cursor"] == "" {
		t.Fatal("cursor of another sort must be rejected")
	}
	if _, err := e.svc.Findings.List(ctx, store.FindingFilter{Sort: "cvss"}); fieldsOf(t, err)["sort"] == "" {
		t.Fatal("bad sort")
	}
	if _, err := e.svc.Findings.List(ctx, store.FindingFilter{Order: "up"}); fieldsOf(t, err)["order"] == "" {
		t.Fatal("bad order")
	}

	id := seen[0]
	if err := e.svc.Findings.Suppress(ctx, "carol", id, "  ", e.now.Add(-time.Hour)); err != nil {
		f := fieldsOf(t, err)
		if f["reason"] == "" || f["expires_at"] == "" {
			t.Fatal(f)
		}
	} else {
		t.Fatal("validation expected")
	}
	if err := e.svc.Findings.Suppress(ctx, "carol", id, "accepted risk", e.now.Add(366*24*time.Hour)); err == nil {
		t.Fatal("more than a year must fail")
	}
	if err := e.svc.Findings.Suppress(ctx, "carol", "missing", "accepted risk", e.now.Add(time.Hour)); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
	if err := e.svc.Findings.Suppress(ctx, "carol", id, "accepted risk", e.now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	d, err := e.svc.Findings.Get(ctx, id)
	if err != nil || d.Suppression == nil || d.Suppression.Actor != "carol" || d.Finding.Status != model.StatusSuppressed {
		t.Fatal(d, err)
	}
	if err := e.svc.Findings.Unsuppress(ctx, "carol", id); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Findings.Unsuppress(ctx, "carol", id); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
	d, _ = e.svc.Findings.Get(ctx, id)
	if d.Suppression != nil || d.Finding.Status != model.StatusOpen {
		t.Fatal(d)
	}
	got := strings.Join(auditActions(t, e.st), ",")
	if got != "finding.suppress,finding.unsuppress" {
		t.Fatal(got)
	}
}

func TestDashboardAndRepos(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	seedFindings(t, e.st, 6)
	e.profile(t, "pat", "token")
	tg, _ := e.svc.Targets.Create(ctx, "a", service.TargetInput{Kind: model.TargetOrg, Owner: "acme", Auth: "pat"})
	if err := e.st.UpsertRepos(ctx, tg.ID, []model.Repo{{Owner: "acme", Name: "api"}, {Owner: "acme", Name: "web"}}, t0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Jobs.Trigger(ctx, "a", service.JobRequest{}); err != nil {
		t.Fatal(err)
	}
	sum, err := e.svc.Dashboard.Summary(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if sum.OpenBySeverity[model.SeverityCritical] != 2 || sum.OpenBySeverity[model.SeverityMedium] != 1 || sum.OpenKEV != 1 || sum.Repos != 2 {
		t.Fatalf("summary %+v", sum)
	}
	if len(sum.TopFindings) != 7 || sum.TopFindings[0].Priority != 5 {
		t.Fatalf("top %v", sum.TopFindings)
	}
	if len(sum.EOLRuntimes) != 1 || len(sum.UnhealthySources) != 1 || sum.UnhealthySources[0].Name != "kev" || len(sum.ActiveJobs) != 1 || sum.LastRun == nil || len(sum.Trend) != 1 {
		t.Fatalf("summary %+v", sum)
	}

	page, err := e.svc.Repos.List(ctx, store.RepoFilter{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.NextCursor != "acme/api" {
		t.Fatal(page, err)
	}
	page, _ = e.svc.Repos.List(ctx, store.RepoFilter{Limit: 1, After: page.NextCursor})
	if len(page.Items) != 1 || page.NextCursor != "" {
		t.Fatal(page)
	}
	d, err := e.svc.Repos.Get(ctx, "acme/api", "")
	if err != nil || len(d.Findings) != 7 || len(d.Runtimes) != 1 || len(d.UpgradePlan) != 1 || len(d.UpgradePlan[0].Advisories) != 6 || d.UpgradePlan[0].Severity != model.SeverityCritical {
		t.Fatalf("detail %+v %v", d, err)
	}
	if _, err := e.svc.Repos.Get(ctx, "acme/none", ""); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestRunsAndAuditPagination(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		r := &model.ScanRun{StartedAt: t0}
		_ = e.st.StartRun(ctx, r)
		r.Status, r.FinishedAt = model.RunSucceeded, t0
		_ = e.st.FinishRun(ctx, r)
	}
	p, err := e.svc.Runs.List(ctx, 0, 2)
	if err != nil || len(p.Items) != 2 || p.Items[0].ID != 5 || p.NextCursor != "4" {
		t.Fatal(p, err)
	}
	p, _ = e.svc.Runs.List(ctx, 4, 2)
	if len(p.Items) != 2 || p.Items[0].ID != 3 || p.NextCursor != "2" {
		t.Fatal(p)
	}
	p, _ = e.svc.Runs.List(ctx, 2, 2)
	if len(p.Items) != 1 || p.NextCursor != "" {
		t.Fatal(p)
	}
	if d, err := e.svc.Runs.Diff(ctx, 3, 0); err != nil || d.FromRun != 2 || d.ToRun != 3 {
		t.Fatal(d, err)
	}
	if _, err := e.svc.Runs.Diff(ctx, 1, 0); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		e.profile(t, "p"+itoa(int64(i)), "token")
	}
	a, err := e.svc.System.Audit(ctx, 0, 2)
	if err != nil || len(a.Items) != 2 || a.NextCursor == "" {
		t.Fatal(a, err)
	}
	if a.Items[0].Actor != "alice" || a.Items[0].ObjectID != "p2" {
		t.Fatal(a.Items[0])
	}
}

func TestSyncConfig(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	cfg := &config.Config{
		AuthProfiles: map[string]config.Plugin{"gh": {Type: "token", Options: plugin.Config{"token_env": "GITHUB_TOKEN"}}},
		Targets:      []config.Target{{Kind: "org", Name: "acme", Auth: "gh"}, {Kind: "repo", URL: "https://github.com/acme/api", Auth: "gh"}},
	}
	d := service.Deps{Config: cfg, Catalog: e.st}
	if err := service.SyncConfig(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := service.SyncConfig(ctx, d); err != nil { // idempotent
		t.Fatal(err)
	}
	ts, _ := e.st.ListTargets(ctx, store.TargetFilter{})
	if len(ts) != 2 || ts[0].Origin != model.OriginConfig || !ts[0].Enabled {
		t.Fatalf("targets %+v", ts)
	}
	cfg.Targets = cfg.Targets[:1]
	if err := service.SyncConfig(ctx, d); err != nil {
		t.Fatal(err)
	}
	if ts, _ := e.st.ListTargets(ctx, store.TargetFilter{}); len(ts) != 1 {
		t.Fatalf("stale config target kept: %+v", ts)
	}
	p, err := e.st.GetAuthProfile(ctx, "gh")
	if err != nil || p.Origin != model.OriginConfig || p.Options["token_env"] != "GITHUB_TOKEN" {
		t.Fatal(p, err)
	}
}

func TestReposCarryOpenCounts(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.profile(t, "pat", "token")
	tg, err := e.svc.Targets.Create(ctx, "alice", service.TargetInput{Kind: model.TargetOrg, Owner: "acme", Auth: "pat", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.UpsertRepos(ctx, tg.ID, []model.Repo{{Provider: "github", Owner: "acme", Name: "api", Ref: "main"}}, t0); err != nil {
		t.Fatal(err)
	}
	run := &model.ScanRun{StartedAt: t0}
	if err := e.st.StartRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	mk := func(adv string, sev model.Severity) model.Finding {
		f := model.Finding{Kind: model.KindDependency, Provider: "github", Repo: "acme/api", ManifestPath: "go.mod",
			Package: model.NewPackage(model.EcosystemGo, "example.com/x", "v1.0.0"), AdvisoryID: adv, Severity: sev}
		f.ComputeID()
		return f
	}
	if _, err := e.st.RecordFindings(ctx, run.ID, []string{"acme/api"}, []model.Finding{mk("GO-1", model.SeverityHigh), mk("GO-2", model.SeverityHigh), mk("GO-3", model.SeverityLow)}, t0); err != nil {
		t.Fatal(err)
	}
	page, err := e.svc.Repos.List(ctx, store.RepoFilter{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("list: %v %+v", err, page)
	}
	if c := page.Items[0].OpenBySeverity; c[model.SeverityHigh] != 2 || c[model.SeverityLow] != 1 {
		t.Fatalf("open counts = %v", c)
	}
	d, err := e.svc.Repos.Get(ctx, "acme/api", "")
	if err != nil || d.Record.OpenBySeverity[model.SeverityHigh] != 2 {
		t.Fatalf("detail counts: %v %+v", err, d)
	}
}
