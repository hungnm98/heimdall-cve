package api

import (
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/service"
)

// DTOs mirror api/openapi.yaml exactly (snake_case). Optional arrays use
// omitempty because the spec does not allow null for them; required arrays
// are always initialised; nullable fields are pointers without omitempty.

type listResponse[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

func list[T, M any](items []M, next string, conv func(M) T) listResponse[T] {
	out := make([]T, 0, len(items))
	for _, it := range items {
		out = append(out, conv(it))
	}
	return listResponse[T]{Items: out, NextCursor: next}
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func tsPtr(t *time.Time) *string {
	if t == nil || t.IsZero() {
		return nil
	}
	s := ts(*t)
	return &s
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// ---- meta ----

type metaDTO struct {
	Version        string   `json:"version"`
	SecretsEnabled bool     `json:"secrets_enabled"`
	JobsBackend    string   `json:"jobs_backend"`
	Providers      []string `json:"providers"`
	AuthTypes      []string `json:"auth_types"`
}

// ---- targets ----

type repoFilterDTO struct {
	Include      []string `json:"include,omitempty"`
	Exclude      []string `json:"exclude,omitempty"`
	Topics       []string `json:"topics,omitempty"`
	SkipArchived *bool    `json:"skip_archived,omitempty"`
	SkipForks    *bool    `json:"skip_forks,omitempty"`
	SkipEmpty    *bool    `json:"skip_empty,omitempty"`
	MaxRepos     int      `json:"max_repos,omitempty"`
}

type targetInputDTO struct {
	Kind     string         `json:"kind"`
	Provider string         `json:"provider,omitempty"`
	BaseURL  string         `json:"base_url,omitempty"`
	Owner    string         `json:"owner,omitempty"`
	URL      string         `json:"url,omitempty"`
	Branch   string         `json:"branch,omitempty"`
	Auth     string         `json:"auth"`
	ListAuth string         `json:"list_auth,omitempty"`
	Repos    []string       `json:"repos,omitempty"`
	Filter   *repoFilterDTO `json:"filter,omitempty"`
	Schedule string         `json:"schedule"`
	// Branches are extra branches (names or globs) scanned besides Branch.
	Branches    []string `json:"branches,omitempty"`
	MaxBranches int      `json:"max_branches,omitempty"`
	Poll        string   `json:"poll,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
}

func orTrue(b *bool) bool { return b == nil || *b }

func (in targetInputDTO) toService() service.TargetInput {
	out := service.TargetInput{
		Kind: model.TargetKind(in.Kind), Provider: in.Provider, BaseURL: in.BaseURL, Owner: in.Owner,
		URL: in.URL, Branch: in.Branch, Auth: in.Auth, ListAuth: in.ListAuth, Repos: in.Repos,
		Schedule: strings.TrimSpace(in.Schedule), Enabled: orTrue(in.Enabled),
		Branches: in.Branches, MaxBranches: in.MaxBranches, Poll: strings.TrimSpace(in.Poll),
		Filter: model.RepoFilter{SkipArchived: true, SkipForks: true, SkipEmpty: true},
	}
	if f := in.Filter; f != nil {
		out.Filter = model.RepoFilter{
			Include: f.Include, Exclude: f.Exclude, Topics: f.Topics, MaxRepos: f.MaxRepos,
			SkipArchived: orTrue(f.SkipArchived), SkipForks: orTrue(f.SkipForks), SkipEmpty: orTrue(f.SkipEmpty),
		}
	}
	return out
}

type targetDTO struct {
	targetInputDTO
	ID         int64   `json:"id"`
	Name       string  `json:"name,omitempty"`
	Label      string  `json:"label"`
	Origin     string  `json:"origin"`
	NextRunAt  *string `json:"next_run_at"`
	NextPollAt *string `json:"next_poll_at,omitempty"`
	CreatedAt  string  `json:"created_at"`
	UpdatedAt  string  `json:"updated_at"`
}

// repoURL rebuilds a repo target's URL: the model keeps owner/name and the
// API base URL only (github.com unless base_url names another host).
func repoURL(t model.Target) string {
	host := "github.com"
	if t.BaseURL != "" {
		h := strings.TrimPrefix(strings.TrimPrefix(t.BaseURL, "https://"), "http://")
		h, _, _ = strings.Cut(h, "/")
		if h != "" && h != "api.github.com" {
			host = h
		}
	}
	return "https://" + host + "/" + t.Owner + "/" + t.Name
}

func toTarget(t model.TargetSpec) targetDTO {
	b := func(v bool) *bool { return &v }
	d := targetDTO{
		targetInputDTO: targetInputDTO{
			Kind: string(t.Kind), Provider: t.Provider, BaseURL: t.BaseURL, Owner: t.Owner, Branch: t.Branch,
			Auth: t.Auth, ListAuth: t.ListAuth, Repos: t.Repos, Schedule: t.Schedule, Enabled: b(t.Enabled),
			Branches: t.Branches, MaxBranches: t.MaxBranches, Poll: t.Poll,
			Filter: &repoFilterDTO{
				Include: t.Filter.Include, Exclude: t.Filter.Exclude, Topics: t.Filter.Topics, MaxRepos: t.Filter.MaxRepos,
				SkipArchived: b(t.Filter.SkipArchived), SkipForks: b(t.Filter.SkipForks), SkipEmpty: b(t.Filter.SkipEmpty),
			},
		},
		ID: t.ID, Label: t.String(), Origin: string(t.Origin), NextRunAt: tsPtr(t.NextRunAt), NextPollAt: tsPtr(t.NextPollAt),
		CreatedAt: ts(t.CreatedAt), UpdatedAt: ts(t.UpdatedAt),
	}
	if t.Kind == model.TargetRepo {
		d.Name, d.URL = t.Name, repoURL(t.Target)
	}
	return d
}

// ---- auth profiles ----

type authProfileInputDTO struct {
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	Options    map[string]any `json:"options"`
	Secret     *string        `json:"secret"`
	SecretKind string         `json:"secret_kind"`
}

func (in authProfileInputDTO) toService() service.AuthProfileInput {
	return service.AuthProfileInput{Name: in.Name, Type: in.Type, Options: in.Options, Secret: in.Secret, SecretKind: in.SecretKind}
}

type authProfileDTO struct {
	ID                int64          `json:"id"`
	Name              string         `json:"name"`
	Type              string         `json:"type"`
	Options           map[string]any `json:"options,omitempty"`
	HasSecret         bool           `json:"has_secret"`
	SecretFingerprint string         `json:"secret_fingerprint,omitempty"`
	Origin            string         `json:"origin"`
	UsedBy            []int64        `json:"used_by"`
	CreatedAt         string         `json:"created_at"`
	UpdatedAt         string         `json:"updated_at"`
}

func toAuthProfile(p model.AuthProfile, usedBy []int64) authProfileDTO {
	opts := map[string]any{}
	for k, v := range p.Options {
		if !service.IsSecretRefOption(k) {
			opts[k] = v
		}
	}
	return authProfileDTO{
		ID: p.ID, Name: p.Name, Type: p.Type, Options: opts, HasSecret: p.SecretID != nil,
		SecretFingerprint: p.SecretFingerprint, Origin: string(p.Origin), UsedBy: nonNil(usedBy),
		CreatedAt: ts(p.CreatedAt), UpdatedAt: ts(p.UpdatedAt),
	}
}

type connectionTestDTO struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// ---- repos ----

type repoDTO struct {
	Provider      string   `json:"provider"`
	Host          string   `json:"host,omitempty"`
	Owner         string   `json:"owner"`
	Name          string   `json:"name"`
	FullName      string   `json:"full_name"`
	HTMLURL       string   `json:"html_url,omitempty"`
	DefaultBranch string   `json:"default_branch,omitempty"`
	Ref           string   `json:"ref"`
	Private       bool     `json:"private"`
	Archived      bool     `json:"archived"`
	Fork          bool     `json:"fork"`
	Topics        []string `json:"topics,omitempty"`
}

func toRepo(r model.Repo) repoDTO {
	return repoDTO{
		Provider: r.Provider, Host: r.Host, Owner: r.Owner, Name: r.Name, FullName: r.FullName(),
		HTMLURL: r.HTMLURL, DefaultBranch: r.DefaultBranch, Ref: r.Ref, Private: r.Private,
		Archived: r.Archived, Fork: r.Fork, Topics: r.Topics,
	}
}

type repoRecordDTO struct {
	repoDTO
	TargetID       int64          `json:"target_id"`
	LastListedAt   string         `json:"last_listed_at"`
	LastHeadSHA    string         `json:"last_head_sha,omitempty"`
	LastScannedAt  *string        `json:"last_scanned_at"`
	OpenBySeverity map[string]int `json:"open_by_severity,omitempty"`
}

func toRepoRecord(r model.RepoRecord) repoRecordDTO {
	d := repoRecordDTO{
		repoDTO: toRepo(r.Repo), TargetID: r.TargetID, LastListedAt: ts(r.LastListedAt),
		LastHeadSHA: r.LastHeadSHA, LastScannedAt: tsPtr(r.LastScannedAt),
	}
	if r.OpenBySeverity != nil {
		d.OpenBySeverity = sevCounts(r.OpenBySeverity)
	}
	return d
}

type runtimeStatusDTO struct {
	Name        string  `json:"name"`
	Version     string  `json:"version"`
	Origin      string  `json:"origin"`
	Via         string  `json:"via,omitempty"`
	Cycle       string  `json:"cycle,omitempty"`
	Status      string  `json:"status"`
	EOLDate     *string `json:"eol_date"`
	LatestPatch string  `json:"latest_patch,omitempty"`
	LatestCycle string  `json:"latest_cycle,omitempty"`
}

func toRuntime(r model.RuntimeStatus) runtimeStatusDTO {
	d := runtimeStatusDTO{
		Name: r.Runtime.Name, Version: r.Runtime.Version, Origin: r.Runtime.Origin, Via: r.Runtime.Via,
		Cycle: r.Cycle, Status: string(r.Status), LatestPatch: r.LatestPatch, LatestCycle: r.LatestCycle,
	}
	if d.Status == "" {
		d.Status = string(model.SupportUnknown)
	}
	if r.EOLDate != nil {
		s := r.EOLDate.UTC().Format(time.DateOnly)
		d.EOLDate = &s
	}
	return d
}

type packageDTO struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	PURL      string `json:"purl"`
}

func toPackage(p model.Package) packageDTO {
	return packageDTO{Ecosystem: string(p.Ecosystem), Name: p.Name, Version: p.Version, PURL: p.PURL}
}

type upgradeItemDTO struct {
	Package     packageDTO `json:"package"`
	Manifest    string     `json:"manifest"`
	Direct      bool       `json:"direct"`
	Recommended string     `json:"recommended,omitempty"`
	Bump        string     `json:"bump"`
	Severity    string     `json:"severity"`
	Advisories  []string   `json:"advisories"`
	Advice      string     `json:"advice,omitempty"`
}

type branchStatusDTO struct {
	Name           string         `json:"name"`
	Primary        bool           `json:"primary"`
	HeadSHA        string         `json:"head_sha,omitempty"`
	ScannedAt      *string        `json:"scanned_at,omitempty"`
	OpenBySeverity map[string]int `json:"open_by_severity"`
}

type repoDetailDTO struct {
	Repo        repoRecordDTO      `json:"repo"`
	Branch      string             `json:"branch,omitempty"` // "" = primary branch
	Branches    []branchStatusDTO  `json:"branches"`
	Findings    []findingDTO       `json:"findings"`
	Runtimes    []runtimeStatusDTO `json:"runtimes"`
	UpgradePlan []upgradeItemDTO   `json:"upgrade_plan"`
}

func toRepoDetail(d *service.RepoDetail) repoDetailDTO {
	out := repoDetailDTO{
		Repo:        toRepoRecord(d.Record),
		Branch:      d.Branch,
		Branches:    make([]branchStatusDTO, 0, len(d.Branches)),
		Findings:    list(d.Findings, "", toFinding).Items,
		Runtimes:    list(d.Runtimes, "", toRuntime).Items,
		UpgradePlan: make([]upgradeItemDTO, 0, len(d.UpgradePlan)),
	}
	for _, b := range d.Branches {
		bd := branchStatusDTO{Name: b.Name, Primary: b.Primary, HeadSHA: b.HeadSHA, OpenBySeverity: sevCounts(b.OpenBySeverity)}
		if !b.ScannedAt.IsZero() {
			bd.ScannedAt = tsPtr(&b.ScannedAt)
		}
		out.Branches = append(out.Branches, bd)
	}
	for _, u := range d.UpgradePlan {
		out.UpgradePlan = append(out.UpgradePlan, upgradeItemDTO{
			Package: toPackage(u.Package), Manifest: u.Manifest, Direct: u.Direct, Recommended: u.Recommended,
			Bump: string(u.Bump), Severity: severity(u.Severity), Advisories: nonNil(u.Advisories), Advice: u.Advice,
		})
	}
	return out
}

// ---- findings ----

func severity(s model.Severity) string {
	if s == "" {
		return string(model.SeverityUnknown)
	}
	return string(s)
}

type findingDTO struct {
	ID                 string            `json:"id"`
	Kind               string            `json:"kind"`
	Repo               string            `json:"repo"`
	Branch             string            `json:"branch,omitempty"` // "" = primary branch
	ManifestPath       string            `json:"manifest_path"`
	Package            *packageDTO       `json:"package,omitempty"`
	Direct             bool              `json:"direct"`
	Scope              string            `json:"scope"`
	Parents            []string          `json:"parents,omitempty"`
	AdvisoryID         string            `json:"advisory_id,omitempty"`
	Aliases            []string          `json:"aliases,omitempty"`
	Summary            string            `json:"summary,omitempty"`
	Severity           string            `json:"severity"`
	CVSSVector         string            `json:"cvss_vector,omitempty"`
	CVSSScore          float64           `json:"cvss_score"`
	EPSS               float64           `json:"epss"`
	EPSSPercentile     float64           `json:"epss_percentile"`
	InKEV              bool              `json:"in_kev"`
	Malicious          bool              `json:"malicious"`
	Verified           bool              `json:"verified"`
	References         []string          `json:"references,omitempty"`
	FixedVersions      []string          `json:"fixed_versions,omitempty"`
	RecommendedVersion string            `json:"recommended_version,omitempty"`
	Bump               string            `json:"bump"`
	Advice             string            `json:"advice,omitempty"`
	Priority           float64           `json:"priority"`
	Runtime            *runtimeStatusDTO `json:"runtime,omitempty"`
	Sources            []string          `json:"sources"`
	FirstSeen          string            `json:"first_seen"`
	LastSeen           string            `json:"last_seen"`
	Status             string            `json:"status"`
}

func toFinding(f model.Finding) findingDTO {
	d := findingDTO{
		ID: f.ID, Kind: string(f.Kind), Repo: f.Repo, Branch: f.Branch, ManifestPath: f.ManifestPath, Direct: f.Direct,
		Scope: string(f.Scope), Parents: f.Parents, AdvisoryID: f.AdvisoryID, Aliases: f.Aliases, Summary: f.Summary,
		Severity: severity(f.Severity), CVSSVector: f.CVSSVector, CVSSScore: f.CVSSScore, EPSS: f.EPSS,
		EPSSPercentile: f.EPSSPercentile, InKEV: f.InKEV, Malicious: f.Malicious, Verified: f.Verified,
		References: f.References, FixedVersions: f.FixedVersions, RecommendedVersion: f.RecommendedVersion,
		Bump: string(f.Bump), Advice: f.Advice, Priority: f.Priority, Sources: nonNil(f.Sources),
		FirstSeen: ts(f.FirstSeen), LastSeen: ts(f.LastSeen), Status: string(f.Status),
	}
	if f.Package.Name != "" {
		p := toPackage(f.Package)
		d.Package = &p
	}
	if f.Runtime != nil {
		r := toRuntime(*f.Runtime)
		d.Runtime = &r
	}
	if d.Status == "" {
		d.Status = string(model.StatusOpen)
	}
	return d
}

type suppressionDTO struct {
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at"`
	Actor     string `json:"actor,omitempty"`
	CreatedAt string `json:"created_at"`
}

type findingDetailDTO struct {
	findingDTO
	Suppression *suppressionDTO `json:"suppression,omitempty"`
}

func toFindingDetail(d *service.FindingDetail) findingDetailDTO {
	out := findingDetailDTO{findingDTO: toFinding(d.Finding)}
	if s := d.Suppression; s != nil {
		out.Suppression = &suppressionDTO{Reason: s.Reason, ExpiresAt: ts(s.ExpiresAt), Actor: s.Actor, CreatedAt: ts(s.CreatedAt)}
	}
	return out
}

type suppressInputDTO struct {
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ---- runs ----

type sourceHealthDTO struct {
	Name       string `json:"name"`
	Healthy    bool   `json:"healthy"`
	Error      string `json:"error,omitempty"`
	Calls      int    `json:"calls"`
	DurationMS int64  `json:"duration_ms"`
}

func toSourceHealth(h model.SourceHealth) sourceHealthDTO {
	return sourceHealthDTO{Name: h.Name, Healthy: h.Healthy, Error: h.Error, Calls: h.Calls, DurationMS: h.Duration.Milliseconds()}
}

type runStatsDTO struct {
	OpenBySeverity map[string]int `json:"open_by_severity"`
	New            int            `json:"new"`
	Fixed          int            `json:"fixed"`
	Repos          int            `json:"repos"`
}

func sevCounts(m map[model.Severity]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[severity(k)] += v
	}
	return out
}

type scanRunDTO struct {
	ID           int64             `json:"id"`
	StartedAt    string            `json:"started_at"`
	FinishedAt   *string           `json:"finished_at"`
	Status       string            `json:"status"`
	Targets      []string          `json:"targets"`
	ReposScanned []string          `json:"repos_scanned"`
	ReposFailed  []string          `json:"repos_failed"`
	Sources      []sourceHealthDTO `json:"sources"`
	Stats        runStatsDTO       `json:"stats"`
	Error        string            `json:"error,omitempty"`
}

func toRun(r model.ScanRun) scanRunDTO {
	return scanRunDTO{
		ID: r.ID, StartedAt: ts(r.StartedAt), FinishedAt: tsPtr(&r.FinishedAt), Status: string(r.Status),
		Targets: nonNil(r.Targets), ReposScanned: nonNil(r.ReposScanned), ReposFailed: nonNil(r.ReposFailed),
		Sources: list(r.Sources, "", toSourceHealth).Items,
		Stats:   runStatsDTO{OpenBySeverity: sevCounts(r.Stats.OpenBySeverity), New: r.Stats.New, Fixed: r.Stats.Fixed, Repos: r.Stats.Repos},
		Error:   r.Error,
	}
}

type diffDTO struct {
	FromRun   int64        `json:"from_run"`
	ToRun     int64        `json:"to_run"`
	New       []findingDTO `json:"new"`
	Fixed     []findingDTO `json:"fixed"`
	StillOpen []findingDTO `json:"still_open"`
}

func toDiff(d *model.Diff) diffDTO {
	return diffDTO{
		FromRun: d.FromRun, ToRun: d.ToRun,
		New:       list(d.New, "", toFinding).Items,
		Fixed:     list(d.Fixed, "", toFinding).Items,
		StillOpen: list(d.StillOpen, "", toFinding).Items,
	}
}

// ---- jobs ----

type jobRequestDTO struct {
	TargetID    *int64 `json:"target_id"`
	Repo        string `json:"repo"`
	RepoURL     string `json:"repo_url"`
	Branch      string `json:"branch"`
	AuthProfile string `json:"auth_profile"`
	Force       bool   `json:"force"`
}

type jobDTO struct {
	ID          int64   `json:"id"`
	TargetID    *int64  `json:"target_id"`
	Repo        string  `json:"repo,omitempty"`
	Branch      string  `json:"branch,omitempty"`
	AuthProfile string  `json:"auth_profile,omitempty"`
	Trigger     string  `json:"trigger"`
	Status      string  `json:"status"`
	RunID       *int64  `json:"run_id"`
	Attempts    int     `json:"attempts"`
	RequestedBy string  `json:"requested_by,omitempty"`
	Error       string  `json:"error,omitempty"`
	CreatedAt   string  `json:"created_at"`
	StartedAt   *string `json:"started_at"`
	FinishedAt  *string `json:"finished_at"`
}

func toJob(j model.Job) jobDTO {
	return jobDTO{
		ID: j.ID, TargetID: j.TargetID, Repo: j.Repo, Branch: j.Branch, AuthProfile: j.AuthProfile,
		Trigger: string(j.Trigger), Status: string(j.Status), RunID: j.RunID, Attempts: j.Attempts,
		RequestedBy: j.RequestedBy, Error: j.Error, CreatedAt: ts(j.CreatedAt),
		StartedAt: tsPtr(j.StartedAt), FinishedAt: tsPtr(j.FinishedAt),
	}
}

type jobEventDTO struct {
	ID      int64  `json:"id"`
	JobID   int64  `json:"job_id"`
	At      string `json:"at"`
	Level   string `json:"level"`
	Repo    string `json:"repo,omitempty"`
	Message string `json:"message"`
}

func toJobEvent(e model.JobEvent) jobEventDTO {
	lvl := e.Level
	if lvl != "warn" && lvl != "error" {
		lvl = "info"
	}
	return jobEventDTO{ID: e.ID, JobID: e.JobID, At: ts(e.At), Level: lvl, Repo: e.Repo, Message: e.Message}
}

// ---- dashboard ----

type eolRuntimeDTO struct {
	runtimeStatusDTO
	Repo string `json:"repo,omitempty"`
}

type dashboardDTO struct {
	OpenBySeverity   map[string]int    `json:"open_by_severity"`
	OpenKEV          int               `json:"open_kev"`
	OpenMalicious    int               `json:"open_malicious"`
	Repos            int               `json:"repos"`
	Trend            []scanRunDTO      `json:"trend"`
	TopFindings      []findingDTO      `json:"top_findings"`
	EOLRuntimes      []eolRuntimeDTO   `json:"eol_runtimes"`
	UnhealthySources []sourceHealthDTO `json:"unhealthy_sources"`
	ActiveJobs       []jobDTO          `json:"active_jobs"`
	LastRun          *scanRunDTO       `json:"last_run,omitempty"`
}

func toDashboard(s *service.DashboardSummary) dashboardDTO {
	d := dashboardDTO{
		OpenBySeverity: sevCounts(s.OpenBySeverity), OpenKEV: s.OpenKEV, OpenMalicious: s.OpenMalicious, Repos: s.Repos,
		Trend:            list(s.Trend, "", toRun).Items,
		TopFindings:      list(s.TopFindings, "", toFinding).Items,
		EOLRuntimes:      list(s.EOLRuntimes, "", func(r model.RuntimeStatus) eolRuntimeDTO { return eolRuntimeDTO{runtimeStatusDTO: toRuntime(r)} }).Items,
		UnhealthySources: list(s.UnhealthySources, "", toSourceHealth).Items,
		ActiveJobs:       list(s.ActiveJobs, "", toJob).Items,
	}
	if s.LastRun != nil {
		r := toRun(*s.LastRun)
		d.LastRun = &r
	}
	return d
}

// ---- system ----

type sourceStatusDTO struct {
	Name     string   `json:"name"`
	Kinds    []string `json:"kinds"`
	Healthy  bool     `json:"healthy"`
	Error    string   `json:"error,omitempty"`
	LastSeen *string  `json:"last_seen"`
}

func toSourceStatus(s service.SourceStatus) sourceStatusDTO {
	return sourceStatusDTO{Name: s.Name, Kinds: nonNil(s.Kinds), Healthy: s.Healthy, Error: s.Error, LastSeen: tsPtr(s.LastSeen)}
}

type notifierStatusDTO struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func toNotifier(n service.NotifierStatus) notifierStatusDTO {
	return notifierStatusDTO{Name: n.Name, Type: n.Type}
}

type auditEntryDTO struct {
	ID         int64          `json:"id"`
	At         string         `json:"at"`
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	ObjectType string         `json:"object_type,omitempty"`
	ObjectID   string         `json:"object_id,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

func toAudit(e model.AuditEntry) auditEntryDTO {
	return auditEntryDTO{ID: e.ID, At: ts(e.At), Actor: e.Actor, Action: e.Action, ObjectType: e.ObjectType, ObjectID: e.ObjectID, Details: e.Details}
}
