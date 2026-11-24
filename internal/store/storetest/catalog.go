package storetest

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// RunCatalog executes the store.Catalog contract. newStore must return a fresh,
// migrated-or-migratable store that implements store.Catalog.
func RunCatalog(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Helper()
	open := func(t *testing.T) store.Catalog {
		s := newStore(t)
		if err := s.Migrate(context.Background()); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		c, ok := s.(store.Catalog)
		if !ok {
			t.Fatalf("%T does not implement store.Catalog", s)
		}
		return c
	}
	t.Run("AuthProfiles", func(t *testing.T) { testProfiles(t, open(t)) })
	t.Run("Secrets", func(t *testing.T) { testSecrets(t, open(t)) })
	t.Run("Targets", func(t *testing.T) { testTargets(t, open(t)) })
	t.Run("Repos", func(t *testing.T) { testRepos(t, open(t)) })
	t.Run("Jobs", func(t *testing.T) { testJobs(t, open(t)) })
	t.Run("JobsConcurrentCreate", func(t *testing.T) { testJobsConcurrent(t, open(t)) })
	t.Run("Audit", func(t *testing.T) { testAudit(t, open(t)) })
	t.Run("Suppressions", func(t *testing.T) {
		c := open(t)
		testSuppressions(t, c.(store.Store), c)
	})
}

func testSuppressions(t *testing.T, s store.Store, c store.Catalog) {
	ctx := context.Background()
	f := F("o/r", "example.com/a", "v1.0.0", "GO-1", model.SeverityHigh)
	exp := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	wantErr(t, "suppress unknown finding",
		c.SaveSuppression(ctx, &model.Suppression{FindingID: "nope", Reason: "x", ExpiresAt: exp}), store.ErrNotFound)
	record(t, s, []string{"o/r"}, t0, f)

	sp := &model.Suppression{FindingID: f.ID, Reason: "not reachable", ExpiresAt: exp, Actor: "alice"}
	must(t, c.SaveSuppression(ctx, sp))
	if got, _ := s.GetFinding(ctx, f.ID); got.Status != model.StatusSuppressed {
		t.Fatalf("finding status = %s, want suppressed", got.Status)
	}
	got, err := c.GetSuppression(ctx, f.ID)
	must(t, err)
	if got.Reason != "not reachable" || !got.ExpiresAt.Equal(exp) || got.Actor != "alice" || got.CreatedAt.IsZero() {
		t.Fatalf("GetSuppression = %+v", got)
	}
	// A rescan keeps it suppressed and out of the diff.
	_, d := record(t, s, []string{"o/r"}, t0.Add(time.Hour), f)
	if len(d.New)+len(d.StillOpen) != 0 {
		t.Fatalf("suppressed finding in diff: %+v", d)
	}
	if l, _ := c.ExpiredSuppressions(ctx, exp.Add(-time.Second)); len(l) != 0 {
		t.Fatal("not expired yet")
	}
	if l, _ := c.ExpiredSuppressions(ctx, exp); len(l) != 1 || l[0].FindingID != f.ID {
		t.Fatalf("ExpiredSuppressions = %+v", l)
	}
	must(t, c.DeleteSuppression(ctx, f.ID))
	if got, _ := s.GetFinding(ctx, f.ID); got.Status != model.StatusOpen {
		t.Fatalf("finding status after unsuppress = %s, want open", got.Status)
	}
	wantErr(t, "delete missing suppression", c.DeleteSuppression(ctx, f.ID), store.ErrNotFound)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, what string, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: err = %v, want %v", what, err, target)
	}
}

func profile(name string) *model.AuthProfile {
	return &model.AuthProfile{Name: name, Type: "token", Options: map[string]any{"token_env": "GITHUB_TOKEN"}, Origin: model.OriginUI}
}

func target(owner, auth string) *model.TargetSpec {
	return &model.TargetSpec{
		Target: model.Target{Kind: model.TargetOrg, Provider: "github", Owner: owner, Auth: auth, ListAuth: auth,
			Filter: model.RepoFilter{Exclude: []string{"sandbox-*"}, SkipArchived: true}},
		Schedule: "0 2 * * *", Enabled: true, Origin: model.OriginUI,
	}
}

func testProfiles(t *testing.T, c store.Catalog) {
	ctx := context.Background()
	p := profile("pat")
	must(t, c.SaveAuthProfile(ctx, p))
	if p.ID == 0 || p.CreatedAt.IsZero() {
		t.Fatalf("SaveAuthProfile must set ID and timestamps: %+v", p)
	}
	wantErr(t, "duplicate name", c.SaveAuthProfile(ctx, profile("pat")), store.ErrConflict)
	must(t, c.SaveAuthProfile(ctx, profile("app")))

	got, err := c.GetAuthProfile(ctx, "pat")
	must(t, err)
	if got.ID != p.ID || got.Options["token_env"] != "GITHUB_TOKEN" || got.Origin != model.OriginUI {
		t.Fatalf("GetAuthProfile = %+v", got)
	}
	got.Options["token_env"] = "MUTATED"
	if again, _ := c.GetAuthProfile(ctx, "pat"); again.Options["token_env"] != "GITHUB_TOKEN" {
		t.Fatal("returned profiles must not alias stored state")
	}
	list, err := c.ListAuthProfiles(ctx)
	must(t, err)
	if len(list) != 2 || list[0].Name != "app" || list[1].Name != "pat" {
		t.Fatalf("ListAuthProfiles must be sorted by name: %+v", list)
	}

	tg := target("acme", "pat")
	must(t, c.SaveTarget(ctx, tg))
	wantErr(t, "delete used profile", c.DeleteAuthProfile(ctx, "pat"), store.ErrConflict)

	p.Name = "pat-renamed" // rename follows into targets
	must(t, c.SaveAuthProfile(ctx, p))
	if gt, _ := c.GetTarget(ctx, tg.ID); gt.Auth != "pat-renamed" || gt.ListAuth != "pat-renamed" {
		t.Fatalf("rename must update target references: %+v", gt.Target)
	}
	must(t, c.DeleteAuthProfile(ctx, "app"))
	_, err = c.GetAuthProfile(ctx, "app")
	wantErr(t, "get deleted", err, store.ErrNotFound)
	wantErr(t, "delete missing", c.DeleteAuthProfile(ctx, "nope"), store.ErrNotFound)
}

func testSecrets(t *testing.T, c store.Catalog) {
	ctx := context.Background()
	r := &store.SecretRecord{Kind: "token", Fingerprint: "abcd1234",
		Sealed: secret.Sealed{KEKID: "k1", WrappedDEK: []byte{1, 2}, Ciphertext: []byte{3, 4}}}
	must(t, c.SaveSecret(ctx, r))
	if r.ID == 0 || r.CreatedAt.IsZero() {
		t.Fatalf("SaveSecret must set ID and CreatedAt: %+v", r)
	}
	created := r.CreatedAt
	rotated := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	r.Sealed.KEKID, r.RotatedAt = "k2", &rotated
	must(t, c.SaveSecret(ctx, r))
	got, err := c.GetSecret(ctx, r.ID)
	must(t, err)
	if got.Sealed.KEKID != "k2" || string(got.Sealed.Ciphertext) != string([]byte{3, 4}) ||
		!got.CreatedAt.Equal(created) || got.RotatedAt == nil || !got.RotatedAt.Equal(rotated) {
		t.Fatalf("GetSecret = %+v", got)
	}
	all, err := c.ListSecrets(ctx)
	must(t, err)
	if len(all) != 1 {
		t.Fatalf("ListSecrets = %d", len(all))
	}

	p := profile("with-secret")
	p.SecretID, p.SecretFingerprint = &r.ID, r.Fingerprint
	must(t, c.SaveAuthProfile(ctx, p))
	wantErr(t, "delete used secret", c.DeleteSecret(ctx, r.ID), store.ErrConflict)
	if gp, _ := c.GetAuthProfile(ctx, "with-secret"); gp.SecretID == nil || *gp.SecretID != r.ID || gp.SecretFingerprint != "abcd1234" {
		t.Fatalf("profile secret link lost: %+v", gp)
	}
	p.SecretID = nil
	must(t, c.SaveAuthProfile(ctx, p))
	must(t, c.DeleteSecret(ctx, r.ID))
	_, err = c.GetSecret(ctx, r.ID)
	wantErr(t, "get deleted secret", err, store.ErrNotFound)
}

func testTargets(t *testing.T, c store.Catalog) {
	ctx := context.Background()
	wantErr(t, "unknown auth", c.SaveTarget(ctx, target("acme", "missing")), store.ErrConflict)
	must(t, c.SaveAuthProfile(ctx, profile("pat")))

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	past1, past2, future := now.Add(-2*time.Hour), now.Add(-time.Hour), now.Add(time.Hour)
	a := target("a", "pat")
	a.NextRunAt = &past2
	b := target("b", "pat")
	b.NextRunAt = &past1
	b.Origin = model.OriginConfig
	off := target("off", "pat")
	off.Enabled, off.NextRunAt = false, &past1
	later := target("later", "pat")
	later.NextRunAt = &future
	manual := target("manual", "pat")
	manual.Schedule = ""
	for _, x := range []*model.TargetSpec{a, b, off, later, manual} {
		must(t, c.SaveTarget(ctx, x))
	}

	got, err := c.GetTarget(ctx, a.ID)
	must(t, err)
	if got.Owner != "a" || got.Schedule != "0 2 * * *" || got.Filter.Exclude[0] != "sandbox-*" || !got.Filter.SkipArchived ||
		got.NextRunAt == nil || !got.NextRunAt.Equal(past2) {
		t.Fatalf("GetTarget lost fields: %+v", got)
	}
	created := got.CreatedAt
	a.Branch = "develop"
	must(t, c.SaveTarget(ctx, a))
	if got, _ := c.GetTarget(ctx, a.ID); got.Branch != "develop" || !got.CreatedAt.Equal(created) {
		t.Fatalf("update: %+v", got)
	}

	due, err := c.DueTargets(ctx, now)
	must(t, err)
	if len(due) != 2 || due[0].ID != b.ID || due[1].ID != a.ID {
		t.Fatalf("DueTargets = %v, want [b a] (enabled, due, oldest first)", targetIDs(due))
	}
	polled := target("polled", "pat")
	polled.Branches, polled.MaxBranches, polled.Poll, polled.NextPollAt = []string{"release/*", "develop"}, 3, "@every 1h", &past1
	must(t, c.SaveTarget(ctx, polled))
	if got, _ := c.GetTarget(ctx, polled.ID); strings.Join(got.Branches, ",") != "release/*,develop" || got.MaxBranches != 3 ||
		got.Poll != "@every 1h" || got.NextPollAt == nil || !got.NextPollAt.Equal(past1) {
		t.Fatalf("branches/poll lost: %+v", got)
	}
	polls, err := c.DuePolls(ctx, now)
	must(t, err)
	if len(polls) != 1 || polls[0].ID != polled.ID {
		t.Fatalf("DuePolls = %v, want [polled]", targetIDs(polls))
	}
	must(t, c.DeleteTarget(ctx, polled.ID))
	enabled := true
	if l, _ := c.ListTargets(ctx, store.TargetFilter{Enabled: &enabled}); len(l) != 4 {
		t.Fatalf("enabled targets = %d, want 4", len(l))
	}
	if l, _ := c.ListTargets(ctx, store.TargetFilter{Origin: model.OriginConfig}); len(l) != 1 || l[0].ID != b.ID {
		t.Fatalf("config targets = %v", targetIDs(l))
	}
	must(t, c.DeleteTarget(ctx, off.ID))
	_, err = c.GetTarget(ctx, off.ID)
	wantErr(t, "get deleted target", err, store.ErrNotFound)
	wantErr(t, "delete missing target", c.DeleteTarget(ctx, 99999), store.ErrNotFound)
}

func targetIDs(ts []model.TargetSpec) []int64 {
	out := make([]int64, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.ID)
	}
	return out
}

func testRepos(t *testing.T, c store.Catalog) {
	ctx := context.Background()
	must(t, c.SaveAuthProfile(ctx, profile("pat")))
	t1, t2 := target("acme", "pat"), target("other", "pat")
	must(t, c.SaveTarget(ctx, t1))
	must(t, c.SaveTarget(ctx, t2))
	at := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	repo := func(owner, name string) model.Repo {
		return model.Repo{Provider: "github", Host: "github.com", Owner: owner, Name: name, DefaultBranch: "main", Ref: "main",
			HTMLURL: "https://github.com/" + owner + "/" + name, Topics: []string{"go"}}
	}
	wantErr(t, "unknown target", c.UpsertRepos(ctx, 99999, []model.Repo{repo("x", "y")}, at), store.ErrNotFound)
	must(t, c.UpsertRepos(ctx, t1.ID, []model.Repo{repo("acme", "api"), repo("acme", "web"), repo("acme", "worker")}, at))
	must(t, c.UpsertRepos(ctx, t2.ID, []model.Repo{repo("other", "lib")}, at))
	upd := repo("acme", "api")
	upd.DefaultBranch = "master"
	must(t, c.UpsertRepos(ctx, t1.ID, []model.Repo{upd}, at.Add(time.Hour)))

	got, err := c.GetRepo(ctx, "acme/api")
	must(t, err)
	if got.DefaultBranch != "master" || got.TargetID != t1.ID || !got.LastListedAt.Equal(at.Add(time.Hour)) || len(got.Topics) != 1 {
		t.Fatalf("GetRepo = %+v", got)
	}
	scannedAt := at.Add(2 * time.Hour)
	must(t, c.MarkRepoScanned(ctx, "acme/api", "sha1", scannedAt))
	if got, _ := c.GetRepo(ctx, "acme/api"); got.LastHeadSHA != "sha1" || got.LastScannedAt == nil || !got.LastScannedAt.Equal(scannedAt) {
		t.Fatalf("MarkRepoScanned: %+v", got)
	}
	wantErr(t, "mark unknown repo", c.MarkRepoScanned(ctx, "no/such", "x", at), store.ErrNotFound)

	page1, _ := c.ListRepos(ctx, store.RepoFilter{TargetID: t1.ID, Limit: 2})
	page2, _ := c.ListRepos(ctx, store.RepoFilter{TargetID: t1.ID, Limit: 2, After: page1[len(page1)-1].FullName()})
	if len(page1) != 2 || page1[0].FullName() != "acme/api" || len(page2) != 1 || page2[0].FullName() != "acme/worker" {
		t.Fatalf("pagination: %v then %v", repoNames(page1), repoNames(page2))
	}
	if l, _ := c.ListRepos(ctx, store.RepoFilter{Query: "WEB"}); len(l) != 1 || l[0].FullName() != "acme/web" {
		t.Fatalf("query: %v", repoNames(l))
	}
	must(t, c.DeleteTarget(ctx, t2.ID))
	_, err = c.GetRepo(ctx, "other/lib")
	wantErr(t, "repos of a deleted target", err, store.ErrNotFound)
}

func repoNames(rs []model.RepoRecord) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.FullName())
	}
	return out
}

func testJobs(t *testing.T, c store.Catalog) {
	ctx := context.Background()
	must(t, c.SaveAuthProfile(ctx, profile("pat")))
	tg := target("acme", "pat")
	must(t, c.SaveTarget(ctx, tg))

	j1 := &model.Job{TargetID: &tg.ID, Trigger: model.TriggerManual, RequestedBy: "alice"}
	created, err := c.CreateJob(ctx, j1)
	must(t, err)
	if !created || j1.ID == 0 || j1.Status != model.JobQueued || j1.CreatedAt.IsZero() {
		t.Fatalf("CreateJob = %v %+v", created, j1)
	}
	dup := &model.Job{TargetID: &tg.ID, Trigger: model.TriggerSchedule}
	created, err = c.CreateJob(ctx, dup)
	must(t, err)
	if created || dup.ID != j1.ID || dup.RequestedBy != "alice" {
		t.Fatalf("an active job with the same scope must be returned instead: created=%v %+v", created, dup)
	}
	repoJob := &model.Job{TargetID: &tg.ID, Repo: "acme/api", Trigger: model.TriggerManual,
		BaseURL: "https://ghe.example.com/api/v3", Force: true}
	all := &model.Job{Trigger: model.TriggerManual}
	for _, j := range []*model.Job{repoJob, all} {
		created, err := c.CreateJob(ctx, j)
		must(t, err)
		if !created {
			t.Fatalf("different scope must create a new job: %+v", j)
		}
	}
	if got, _ := c.GetJob(ctx, repoJob.ID); got == nil || got.BaseURL != "https://ghe.example.com/api/v3" || !got.Force {
		t.Fatalf("BaseURL/Force not stored: %+v", got)
	}
	if created, _ := c.CreateJob(ctx, &model.Job{Trigger: model.TriggerAPI}); created {
		t.Fatal("a second all-targets job must be deduplicated")
	}

	started := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	runID := int64(42)
	j1.Status, j1.StartedAt, j1.Attempts, j1.RunID = model.JobRunning, &started, 1, &runID
	must(t, c.UpdateJob(ctx, j1))
	finished := started.Add(time.Minute)
	j1.Status, j1.FinishedAt, j1.Error = model.JobFailed, &finished, "boom"
	must(t, c.UpdateJob(ctx, j1))
	got, err := c.GetJob(ctx, j1.ID)
	must(t, err)
	if got.Status != model.JobFailed || got.Error != "boom" || got.Attempts != 1 || got.RunID == nil || *got.RunID != 42 ||
		got.StartedAt == nil || !got.StartedAt.Equal(started) || got.FinishedAt == nil || got.RequestedBy != "alice" {
		t.Fatalf("GetJob = %+v", got)
	}
	if created, _ := c.CreateJob(ctx, &model.Job{TargetID: &tg.ID, Trigger: model.TriggerManual}); !created {
		t.Fatal("once the job finished, the same scope can be queued again")
	}
	wantErr(t, "update missing job", c.UpdateJob(ctx, &model.Job{ID: 99999}), store.ErrNotFound)

	jobs, _ := c.ListJobs(ctx, store.JobFilter{})
	if len(jobs) != 4 || jobs[0].ID < jobs[len(jobs)-1].ID {
		t.Fatalf("ListJobs must return 4 jobs newest first, got %d", len(jobs))
	}
	if l, _ := c.ListJobs(ctx, store.JobFilter{Status: model.JobFailed}); len(l) != 1 || l[0].ID != j1.ID {
		t.Fatal("status filter")
	}
	if l, _ := c.ListJobs(ctx, store.JobFilter{TargetID: tg.ID, Limit: 10}); len(l) != 3 {
		t.Fatalf("target filter: %d jobs, want 3", len(l))
	}
	if l, _ := c.ListJobs(ctx, store.JobFilter{BeforeID: jobs[0].ID, Limit: 1}); len(l) != 1 || l[0].ID != jobs[1].ID {
		t.Fatal("BeforeID cursor")
	}

	for i, msg := range []string{"listing", "scanning acme/api", "done"} {
		e := &model.JobEvent{JobID: j1.ID, Level: "info", Repo: "acme/api", Message: msg}
		must(t, c.AppendJobEvent(ctx, e))
		if e.ID == 0 || e.At.IsZero() {
			t.Fatalf("event %d: ID and At must be set", i)
		}
	}
	evs, _ := c.ListJobEvents(ctx, j1.ID, 0, 0)
	if len(evs) != 3 || evs[0].Message != "listing" {
		t.Fatalf("ListJobEvents = %+v", evs)
	}
	rest, _ := c.ListJobEvents(ctx, j1.ID, evs[0].ID, 1)
	if len(rest) != 1 || rest[0].Message != "scanning acme/api" {
		t.Fatalf("resume after id: %+v", rest)
	}
	wantErr(t, "event for missing job", c.AppendJobEvent(ctx, &model.JobEvent{JobID: 99999, Message: "x"}), store.ErrNotFound)
}

func testJobsConcurrent(t *testing.T, c store.Catalog) {
	ctx := context.Background()
	var createdN atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			created, err := c.CreateJob(ctx, &model.Job{Repo: "acme/api", Trigger: model.TriggerManual})
			if err != nil {
				t.Error(err)
			}
			if created {
				createdN.Add(1)
			}
		}()
	}
	wg.Wait()
	if createdN.Load() != 1 {
		t.Fatalf("concurrent CreateJob with one scope created %d jobs, want 1", createdN.Load())
	}
}

func testAudit(t *testing.T, c store.Catalog) {
	ctx := context.Background()
	details := map[string]any{"name": "pat"}
	for _, a := range []string{"profile.create", "target.create", "job.trigger"} {
		e := &model.AuditEntry{Actor: "alice@example.com", Action: a, ObjectType: "x", ObjectID: "1", Details: details}
		must(t, c.AppendAudit(ctx, e))
		if e.ID == 0 || e.At.IsZero() {
			t.Fatal("AppendAudit must set ID and At")
		}
	}
	details["name"] = "mutated"
	l, _ := c.ListAudit(ctx, 0, 2)
	if len(l) != 2 || l[0].Action != "job.trigger" || l[1].Action != "target.create" || l[0].Details["name"] != "pat" {
		t.Fatalf("ListAudit newest first, details copied: %+v", l)
	}
	rest, _ := c.ListAudit(ctx, l[1].ID, 0)
	if len(rest) != 1 || rest[0].Action != "profile.create" {
		t.Fatalf("before cursor: %+v", rest)
	}
}
