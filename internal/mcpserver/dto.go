package mcpserver

import (
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/service"
)

// Output shapes: snake_case, concise, empty fields omitted. They never carry
// secrets (auth profiles appear by name only).

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func tsPtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return ts(*t)
}

type targetOut struct {
	ID        int64    `json:"id"`
	Kind      string   `json:"kind"`
	Provider  string   `json:"provider"`
	Owner     string   `json:"owner,omitempty"`
	Name      string   `json:"name,omitempty"`
	Branch    string   `json:"branch,omitempty"`
	Auth      string   `json:"auth_profile,omitempty"`
	Repos     []string `json:"repos,omitempty"`
	Schedule  string   `json:"schedule,omitempty"`
	Enabled   bool     `json:"enabled"`
	Origin    string   `json:"origin"`
	NextRunAt string   `json:"next_run_at,omitempty"`
}

func toTarget(t model.TargetSpec) targetOut {
	return targetOut{
		ID: t.ID, Kind: string(t.Kind), Provider: t.Provider, Owner: t.Owner, Name: t.Name, Branch: t.Branch,
		Auth: t.Auth, Repos: t.Repos, Schedule: t.Schedule, Enabled: t.Enabled, Origin: string(t.Origin), NextRunAt: tsPtr(t.NextRunAt),
	}
}

type repoOut struct {
	FullName      string `json:"full_name"`
	TargetID      int64  `json:"target_id"`
	DefaultBranch string `json:"default_branch,omitempty"`
	Private       bool   `json:"private,omitempty"`
	Archived      bool   `json:"archived,omitempty"`
	URL           string `json:"url,omitempty"`
	LastScannedAt string `json:"last_scanned_at,omitempty"`
	LastHeadSHA   string `json:"last_head_sha,omitempty"`
}

func toRepo(r model.RepoRecord) repoOut {
	return repoOut{
		FullName: r.FullName(), TargetID: r.TargetID, DefaultBranch: r.DefaultBranch, Private: r.Private, Archived: r.Archived,
		URL: r.HTMLURL, LastScannedAt: tsPtr(r.LastScannedAt), LastHeadSHA: r.LastHeadSHA,
	}
}

type pkgOut struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
}

func toPkg(p model.Package) pkgOut {
	return pkgOut{Ecosystem: string(p.Ecosystem), Name: p.Name, Version: p.Version}
}

type inventoryOut struct {
	Repo     string `json:"repo"`
	Manifest string `json:"manifest"`
	pkgOut
	PURL         string `json:"purl,omitempty"`
	Direct       bool   `json:"direct"`
	Scope        string `json:"scope,omitempty"`
	Private      bool   `json:"private,omitempty"`
	Unresolvable string `json:"unresolvable,omitempty"`
}

func toInventory(it model.InventoryItem) inventoryOut {
	return inventoryOut{
		Repo: it.Repo, Manifest: it.ManifestPath, pkgOut: toPkg(it.Package), PURL: it.Package.PURL, Direct: it.Direct,
		Scope: string(it.Scope), Private: it.Private, Unresolvable: it.Unresolvable,
	}
}

type analysisOut struct {
	ID                 int64    `json:"id"`
	Ecosystem          string   `json:"ecosystem"`
	Name               string   `json:"name"`
	Version            string   `json:"version,omitempty"`
	Verdict            string   `json:"verdict"`
	Summary            string   `json:"summary"`
	Evidence           []string `json:"evidence"`
	RecommendedVersion string   `json:"recommended_version,omitempty"`
	Confidence         string   `json:"confidence"`
	Agent              string   `json:"agent"`
	AnalyzedAt         string   `json:"analyzed_at"`
}

func toAnalysis(a model.LibraryAnalysis) analysisOut {
	return analysisOut{
		ID: a.ID, Ecosystem: string(a.Ecosystem), Name: a.Name, Version: a.Version, Verdict: string(a.Verdict), Summary: a.Summary,
		Evidence: a.Evidence, RecommendedVersion: a.RecommendedVersion, Confidence: string(a.Confidence), Agent: a.Agent, AnalyzedAt: ts(a.AnalyzedAt),
	}
}

type queueOut struct {
	Ecosystem    string       `json:"ecosystem"`
	Name         string       `json:"name"`
	Versions     []string     `json:"versions"`
	RepoCount    int          `json:"repo_count"`
	Repos        []string     `json:"repos"` // first 10
	Direct       bool         `json:"direct"`
	OpenFindings int          `json:"open_findings"`
	Score        float64      `json:"score"`
	Reason       string       `json:"reason"`
	LastAnalysis *analysisOut `json:"last_analysis,omitempty"`
}

func toQueue(q service.QueueItem) queueOut {
	out := queueOut{
		Ecosystem: string(q.Usage.Ecosystem), Name: q.Usage.Name, Versions: q.Usage.Versions, RepoCount: len(q.Usage.Repos),
		Repos: q.Usage.Repos[:min(10, len(q.Usage.Repos))], Direct: q.Usage.Direct, OpenFindings: q.OpenFindings, Score: q.Score, Reason: q.Reason,
	}
	if q.LastAnalysis != nil {
		a := toAnalysis(*q.LastAnalysis)
		out.LastAnalysis = &a
	}
	return out
}

type runtimeOut struct {
	Repo        string `json:"repo,omitempty"`
	Runtime     string `json:"runtime"`
	Version     string `json:"version"`
	Origin      string `json:"origin,omitempty"`
	Cycle       string `json:"cycle,omitempty"`
	Status      string `json:"status"`
	EOLDate     string `json:"eol_date,omitempty"`
	LatestPatch string `json:"latest_patch,omitempty"`
	LatestCycle string `json:"latest_cycle,omitempty"`
}

func toRuntime(repo string, r model.RuntimeStatus) runtimeOut {
	eol := ""
	if r.EOLDate != nil {
		eol = r.EOLDate.UTC().Format("2006-01-02")
	}
	return runtimeOut{
		Repo: repo, Runtime: r.Runtime.Name, Version: r.Runtime.Version, Origin: r.Runtime.Origin, Cycle: r.Cycle,
		Status: string(r.Status), EOLDate: eol, LatestPatch: r.LatestPatch, LatestCycle: r.LatestCycle,
	}
}

// findingOut is the list shape; findingDetailOut adds the rest.
type findingOut struct {
	ID                 string      `json:"id"`
	Kind               string      `json:"kind"`
	Repo               string      `json:"repo"`
	Branch             string      `json:"branch,omitempty"`
	Manifest           string      `json:"manifest,omitempty"`
	Package            *pkgOut     `json:"package,omitempty"`
	Direct             bool        `json:"direct,omitempty"`
	AdvisoryID         string      `json:"advisory_id"`
	Aliases            []string    `json:"aliases,omitempty"`
	Summary            string      `json:"summary,omitempty"`
	Severity           string      `json:"severity"`
	CVSSScore          float64     `json:"cvss_score,omitempty"`
	EPSS               float64     `json:"epss,omitempty"`
	KEV                bool        `json:"kev,omitempty"`
	Malicious          bool        `json:"malicious,omitempty"`
	Verified           bool        `json:"verified"`
	FixedVersions      []string    `json:"fixed_versions,omitempty"`
	RecommendedVersion string      `json:"recommended_version,omitempty"`
	Bump               string      `json:"bump,omitempty"`
	Priority           float64     `json:"priority,omitempty"`
	Status             string      `json:"status"`
	FirstSeen          string      `json:"first_seen"`
	Sources            []string    `json:"sources,omitempty"`
	Runtime            *runtimeOut `json:"runtime,omitempty"`
	// AgentAssessment is the latest agent triage that applies (unverified).
	AgentAssessment *assessmentBriefOut `json:"agent_assessment,omitempty"`
}

type assessmentBriefOut struct {
	ID         int64   `json:"id"`
	Decision   string  `json:"decision"`
	Score      float64 `json:"score"`
	Confidence string  `json:"confidence"`
	Repo       string  `json:"repo,omitempty"` // set when specific to the finding's repo
	Fresh      bool    `json:"fresh"`          // false: the finding changed or the assessment is old
	AssessedAt string  `json:"assessed_at"`
}

func toAssessmentBrief(st service.AssessmentStatus) *assessmentBriefOut {
	a := st.Assessment
	return &assessmentBriefOut{ID: a.ID, Decision: string(a.Decision), Score: a.Score, Confidence: string(a.Confidence), Repo: a.Repo,
		Fresh: st.Fresh, AssessedAt: ts(a.AssessedAt)}
}

type assessmentOut struct {
	ID         int64    `json:"id"`
	AdvisoryID string   `json:"advisory_id"`
	Package    pkgOut   `json:"package"`
	Repo       string   `json:"repo,omitempty"` // empty = applies to every repo
	Decision   string   `json:"decision"`
	Score      float64  `json:"score"`
	Rationale  string   `json:"rationale,omitempty"`
	Evidence   []string `json:"evidence"`
	Confidence string   `json:"confidence"`
	AssessedBy string   `json:"assessed_by"`
	AssessedAt string   `json:"assessed_at"`
}

func toAssessment(a model.FindingAssessment) assessmentOut {
	return assessmentOut{
		ID: a.ID, AdvisoryID: a.AdvisoryID, Package: pkgOut{Ecosystem: string(a.Ecosystem), Name: a.Package, Version: a.Version}, Repo: a.Repo,
		Decision: string(a.Decision), Score: a.Score, Rationale: a.Rationale, Evidence: nonNil(a.Evidence), Confidence: string(a.Confidence),
		AssessedBy: a.AssessedBy, AssessedAt: ts(a.AssessedAt),
	}
}

type triageOut struct {
	Finding        findingOut     `json:"finding"`
	RepoCount      int            `json:"repo_count"`
	Repos          []string       `json:"repos"` // first 10
	Reason         string         `json:"reason"`
	LastAssessment *assessmentOut `json:"last_assessment,omitempty"`
}

func toTriage(it service.TriageItem) triageOut {
	out := triageOut{Finding: toFinding(it.Finding), RepoCount: len(it.Repos), Repos: it.Repos[:min(10, len(it.Repos))], Reason: it.Reason}
	if it.LastAssessment != nil {
		a := toAssessment(*it.LastAssessment)
		out.LastAssessment = &a
	}
	return out
}

func toFinding(f model.Finding) findingOut {
	out := findingOut{
		ID: f.ID, Kind: string(f.Kind), Repo: f.Repo, Branch: f.Branch, Manifest: f.ManifestPath, Direct: f.Direct,
		AdvisoryID: f.AdvisoryID, Aliases: f.Aliases, Summary: f.Summary, Severity: string(f.Severity), CVSSScore: f.CVSSScore,
		EPSS: f.EPSS, KEV: f.InKEV, Malicious: f.Malicious, Verified: f.Verified, FixedVersions: f.FixedVersions,
		RecommendedVersion: f.RecommendedVersion, Bump: string(f.Bump), Priority: f.Priority, Status: string(f.Status),
		FirstSeen: ts(f.FirstSeen), Sources: f.Sources,
	}
	if f.Package.Name != "" {
		p := toPkg(f.Package)
		out.Package = &p
	}
	if f.Runtime != nil {
		r := toRuntime("", *f.Runtime)
		out.Runtime = &r
	}
	return out
}

type findingDetailOut struct {
	findingOut
	CVSSVector  string          `json:"cvss_vector,omitempty"`
	Scope       string          `json:"scope,omitempty"`
	Parents     []string        `json:"parents,omitempty"`
	References  []string        `json:"references,omitempty"`
	Advice      string          `json:"advice,omitempty"`
	LastSeen    string          `json:"last_seen"`
	Suppression *suppressionOut `json:"suppression,omitempty"`
}

type suppressionOut struct {
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at"`
	By        string `json:"by"`
}

func toFindingDetail(d *service.FindingDetail) findingDetailOut {
	f := d.Finding
	out := findingDetailOut{
		findingOut: toFinding(f), CVSSVector: f.CVSSVector, Scope: string(f.Scope), Parents: f.Parents,
		References: f.References, Advice: f.Advice, LastSeen: ts(f.LastSeen),
	}
	if d.Suppression != nil {
		out.Suppression = &suppressionOut{Reason: d.Suppression.Reason, ExpiresAt: ts(d.Suppression.ExpiresAt), By: d.Suppression.Actor}
	}
	return out
}

type upgradeOut struct {
	pkgOut
	Manifest    string   `json:"manifest"`
	Direct      bool     `json:"direct"`
	Recommended string   `json:"recommended,omitempty"`
	Bump        string   `json:"bump,omitempty"`
	Severity    string   `json:"severity"`
	Advisories  []string `json:"advisories"`
	Advice      string   `json:"advice,omitempty"`
}

func toUpgrade(u model.UpgradeItem) upgradeOut {
	return upgradeOut{
		pkgOut: toPkg(u.Package), Manifest: u.Manifest, Direct: u.Direct, Recommended: u.Recommended, Bump: string(u.Bump),
		Severity: string(u.Severity), Advisories: u.Advisories, Advice: u.Advice,
	}
}

type sourceHealthOut struct {
	Name    string `json:"name"`
	Healthy bool   `json:"healthy"`
	Error   string `json:"error,omitempty"`
}

type runOut struct {
	ID               int64             `json:"id"`
	Status           string            `json:"status"`
	StartedAt        string            `json:"started_at"`
	FinishedAt       string            `json:"finished_at,omitempty"`
	Targets          []string          `json:"targets,omitempty"`
	ReposScanned     int               `json:"repos_scanned"`
	ReposFailed      []string          `json:"repos_failed,omitempty"`
	OpenBySeverity   map[string]int    `json:"open_by_severity,omitempty"`
	New              int               `json:"new"`
	Fixed            int               `json:"fixed"`
	UnhealthySources []sourceHealthOut `json:"unhealthy_sources,omitempty"`
	Error            string            `json:"error,omitempty"`
}

func toRun(r model.ScanRun) runOut {
	out := runOut{
		ID: r.ID, Status: string(r.Status), StartedAt: ts(r.StartedAt), FinishedAt: ts(r.FinishedAt), Targets: r.Targets,
		ReposScanned: len(r.ReposScanned), ReposFailed: r.ReposFailed, New: r.Stats.New, Fixed: r.Stats.Fixed, Error: r.Error,
	}
	if len(r.Stats.OpenBySeverity) > 0 {
		out.OpenBySeverity = map[string]int{}
		for k, v := range r.Stats.OpenBySeverity {
			out.OpenBySeverity[string(k)] = v
		}
	}
	for _, h := range r.Sources {
		if !h.Healthy {
			out.UnhealthySources = append(out.UnhealthySources, sourceHealthOut{Name: h.Name, Error: h.Error})
		}
	}
	return out
}

type jobOut struct {
	JobID      int64      `json:"job_id"`
	Status     string     `json:"status"`
	TargetID   *int64     `json:"target_id,omitempty"`
	Repo       string     `json:"repo,omitempty"`
	Branch     string     `json:"branch,omitempty"`
	RunID      *int64     `json:"run_id,omitempty"`
	Error      string     `json:"error,omitempty"`
	CreatedAt  string     `json:"created_at"`
	StartedAt  string     `json:"started_at,omitempty"`
	FinishedAt string     `json:"finished_at,omitempty"`
	Events     []eventOut `json:"recent_events,omitempty"`
}

type eventOut struct {
	At      string `json:"at"`
	Level   string `json:"level"`
	Repo    string `json:"repo,omitempty"`
	Message string `json:"message"`
}

func toJob(j model.Job) jobOut {
	return jobOut{
		JobID: j.ID, Status: string(j.Status), TargetID: j.TargetID, Repo: j.Repo, Branch: j.Branch, RunID: j.RunID, Error: j.Error,
		CreatedAt: ts(j.CreatedAt), StartedAt: tsPtr(j.StartedAt), FinishedAt: tsPtr(j.FinishedAt),
	}
}
