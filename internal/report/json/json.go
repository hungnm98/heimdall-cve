// Package json renders the whole scan report as stable, snake_case JSON. Field
// names follow the schemas of api/openapi.yaml where the concepts overlap.
package json

import (
	"cmp"
	encjson "encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/report"
)

func init() { report.Registry.Register("json", New) }

// New builds the reporter. It takes no options.
func New(cfg plugin.Config, _ plugin.Deps) (report.Reporter, error) {
	if err := cfg.Decode(&struct{}{}); err != nil {
		return nil, fmt.Errorf("report json: %w", err)
	}
	return Reporter{}, nil
}

// Reporter implements report.Reporter.
type Reporter struct{}

// Format implements report.Reporter.
func (Reporter) Format() string { return "json" }

// FileExtension implements report.Reporter.
func (Reporter) FileExtension() string { return ".json" }

// Render implements report.Reporter: indented JSON with a trailing newline.
func (Reporter) Render(w io.Writer, r *model.Report) error {
	enc := encjson.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(toReport(r))
}

type reportDTO struct {
	GeneratedAt *string    `json:"generated_at"`
	Run         scanRunDTO `json:"run"`
	Repos       []repoDTO  `json:"repos"`
	Diff        *diffDTO   `json:"diff"`
}

type scanRunDTO struct {
	ID           int64             `json:"id"`
	StartedAt    *string           `json:"started_at"`
	FinishedAt   *string           `json:"finished_at"`
	Status       model.RunStatus   `json:"status"`
	Targets      []string          `json:"targets"`
	ReposScanned []string          `json:"repos_scanned"`
	ReposFailed  []string          `json:"repos_failed"`
	Sources      []sourceHealthDTO `json:"sources"`
	Stats        runStatsDTO       `json:"stats"`
	Error        string            `json:"error,omitempty"`
}

type sourceHealthDTO struct {
	Name       string `json:"name"`
	Healthy    bool   `json:"healthy"`
	Error      string `json:"error,omitempty"`
	Calls      int    `json:"calls"`
	DurationMS int64  `json:"duration_ms"`
}

type runStatsDTO struct {
	OpenBySeverity map[model.Severity]int `json:"open_by_severity"` // encoding/json sorts map keys
	New            int                    `json:"new"`
	Fixed          int                    `json:"fixed"`
	Repos          int                    `json:"repos"`
}

type repoDTO struct {
	Repo        repoInfoDTO        `json:"repo"`
	HeadSHA     string             `json:"head_sha"`
	Findings    []findingDTO       `json:"findings"`
	Runtimes    []runtimeStatusDTO `json:"runtimes"`
	UpgradePlan []upgradeItemDTO   `json:"upgrade_plan"`
	Errors      []string           `json:"errors"`
}

type repoInfoDTO struct {
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
	Topics        []string `json:"topics"`
}

type packageDTO struct {
	Ecosystem model.Ecosystem `json:"ecosystem"`
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	PURL      string          `json:"purl"`
}

type findingDTO struct {
	ID                 string              `json:"id"`
	Kind               model.FindingKind   `json:"kind"`
	Provider           string              `json:"provider,omitempty"`
	Repo               string              `json:"repo"`
	ManifestPath       string              `json:"manifest_path"`
	Package            packageDTO          `json:"package"`
	Direct             bool                `json:"direct"`
	Scope              model.Scope         `json:"scope"`
	Parents            []string            `json:"parents"`
	AdvisoryID         string              `json:"advisory_id"`
	Aliases            []string            `json:"aliases"`
	Summary            string              `json:"summary"`
	Severity           model.Severity      `json:"severity"`
	CVSSVector         string              `json:"cvss_vector,omitempty"`
	CVSSScore          float64             `json:"cvss_score"`
	EPSS               float64             `json:"epss"`
	EPSSPercentile     float64             `json:"epss_percentile"`
	InKEV              bool                `json:"in_kev"`
	Malicious          bool                `json:"malicious"`
	Verified           bool                `json:"verified"`
	References         []string            `json:"references"`
	FixedVersions      []string            `json:"fixed_versions"`
	RecommendedVersion string              `json:"recommended_version"`
	Bump               model.BumpType      `json:"bump"`
	Advice             string              `json:"advice,omitempty"`
	Priority           float64             `json:"priority"`
	Runtime            *runtimeStatusDTO   `json:"runtime,omitempty"`
	Sources            []string            `json:"sources"`
	FirstSeen          *string             `json:"first_seen"`
	LastSeen           *string             `json:"last_seen"`
	Status             model.FindingStatus `json:"status"`
}

type runtimeStatusDTO struct {
	Name        string              `json:"name"`
	Version     string              `json:"version"`
	Origin      string              `json:"origin"`
	Via         string              `json:"via,omitempty"`
	Cycle       string              `json:"cycle"`
	Status      model.SupportStatus `json:"status"`
	EOLDate     *string             `json:"eol_date"`
	LatestPatch string              `json:"latest_patch"`
	LatestCycle string              `json:"latest_cycle"`
	Source      string              `json:"source,omitempty"`
}

type upgradeItemDTO struct {
	Package     packageDTO     `json:"package"`
	Manifest    string         `json:"manifest"`
	Direct      bool           `json:"direct"`
	Recommended string         `json:"recommended"`
	Bump        model.BumpType `json:"bump"`
	Severity    model.Severity `json:"severity"`
	Advisories  []string       `json:"advisories"`
	Advice      string         `json:"advice,omitempty"`
}

type diffDTO struct {
	FromRun   int64        `json:"from_run"`
	ToRun     int64        `json:"to_run"`
	New       []findingDTO `json:"new"`
	Fixed     []findingDTO `json:"fixed"`
	StillOpen []findingDTO `json:"still_open"`
}

func toReport(r *model.Report) reportDTO {
	repos := slices.SortedFunc(slices.Values(r.Repos), func(a, b model.RepoReport) int {
		return cmp.Compare(a.Repo.FullName(), b.Repo.FullName())
	})
	out := reportDTO{
		GeneratedAt: timestamp(r.GeneratedAt),
		Run:         toRun(r.Run),
		Repos:       make([]repoDTO, 0, len(repos)),
	}
	for _, rr := range repos {
		out.Repos = append(out.Repos, toRepo(rr))
	}
	if d := r.Diff; d != nil {
		out.Diff = &diffDTO{FromRun: d.FromRun, ToRun: d.ToRun,
			New: toFindings(d.New), Fixed: toFindings(d.Fixed), StillOpen: toFindings(d.StillOpen)}
	}
	return out
}

func toRun(r model.ScanRun) scanRunDTO {
	sources := slices.SortedFunc(slices.Values(r.Sources), func(a, b model.SourceHealth) int { return cmp.Compare(a.Name, b.Name) })
	out := scanRunDTO{
		ID: r.ID, StartedAt: timestamp(r.StartedAt), FinishedAt: timestamp(r.FinishedAt), Status: r.Status,
		Targets: sortedStrings(r.Targets), ReposScanned: sortedStrings(r.ReposScanned), ReposFailed: sortedStrings(r.ReposFailed),
		Sources: make([]sourceHealthDTO, 0, len(sources)),
		Stats:   runStatsDTO{OpenBySeverity: r.Stats.OpenBySeverity, New: r.Stats.New, Fixed: r.Stats.Fixed, Repos: r.Stats.Repos},
		Error:   r.Error,
	}
	if out.Stats.OpenBySeverity == nil {
		out.Stats.OpenBySeverity = map[model.Severity]int{}
	}
	for _, s := range sources {
		out.Sources = append(out.Sources, sourceHealthDTO{Name: s.Name, Healthy: s.Healthy, Error: s.Error,
			Calls: s.Calls, DurationMS: s.Duration.Milliseconds()})
	}
	return out
}

func toRepo(rr model.RepoReport) repoDTO {
	r := rr.Repo
	out := repoDTO{
		Repo: repoInfoDTO{Provider: r.Provider, Host: r.Host, Owner: r.Owner, Name: r.Name, FullName: r.FullName(),
			HTMLURL: r.HTMLURL, DefaultBranch: r.DefaultBranch, Ref: r.Ref, Private: r.Private, Archived: r.Archived,
			Fork: r.Fork, Topics: sortedStrings(r.Topics)},
		HeadSHA:     rr.HeadSHA,
		Findings:    toFindings(rr.Findings),
		Runtimes:    make([]runtimeStatusDTO, 0, len(rr.Runtimes)),
		UpgradePlan: make([]upgradeItemDTO, 0, len(rr.UpgradePlan)),
		Errors:      sortedStrings(rr.Errors),
	}
	rts := slices.SortedFunc(slices.Values(rr.Runtimes), func(a, b model.RuntimeStatus) int {
		return cmp.Or(
			cmp.Compare(a.Runtime.Name, b.Runtime.Name),
			cmp.Compare(a.Runtime.Origin, b.Runtime.Origin),
			cmp.Compare(a.Runtime.Version, b.Runtime.Version),
			cmp.Compare(a.Runtime.Via, b.Runtime.Via),
		)
	})
	for _, rt := range rts {
		out.Runtimes = append(out.Runtimes, toRuntime(rt))
	}
	items := slices.SortedFunc(slices.Values(rr.UpgradePlan), func(a, b model.UpgradeItem) int {
		return cmp.Or(
			cmp.Compare(b.Severity.Rank(), a.Severity.Rank()),
			cmp.Compare(a.Package.Name, b.Package.Name),
			cmp.Compare(a.Manifest, b.Manifest),
			cmp.Compare(a.Recommended, b.Recommended),
		)
	})
	for _, it := range items {
		out.UpgradePlan = append(out.UpgradePlan, upgradeItemDTO{Package: toPackage(it.Package), Manifest: it.Manifest,
			Direct: it.Direct, Recommended: it.Recommended, Bump: it.Bump, Severity: it.Severity,
			Advisories: sortedStrings(it.Advisories), Advice: it.Advice})
	}
	return out
}

func toFindings(fs []model.Finding) []findingDTO {
	sorted := slices.SortedFunc(slices.Values(fs), func(a, b model.Finding) int {
		return cmp.Or(
			cmp.Compare(b.Severity.Rank(), a.Severity.Rank()),
			cmp.Compare(a.Repo, b.Repo),
			cmp.Compare(a.Package.Name, b.Package.Name),
			cmp.Compare(a.AdvisoryID, b.AdvisoryID),
			cmp.Compare(a.ManifestPath, b.ManifestPath),
			cmp.Compare(a.ID, b.ID),
		)
	})
	out := make([]findingDTO, 0, len(sorted))
	for _, f := range sorted {
		d := findingDTO{
			ID: f.ID, Kind: f.Kind, Provider: f.Provider, Repo: f.Repo, ManifestPath: f.ManifestPath,
			Package: toPackage(f.Package), Direct: f.Direct, Scope: f.Scope, Parents: sortedStrings(f.Parents),
			AdvisoryID: f.AdvisoryID, Aliases: sortedStrings(f.Aliases), Summary: f.Summary, Severity: f.Severity,
			CVSSVector: f.CVSSVector, CVSSScore: f.CVSSScore, EPSS: f.EPSS, EPSSPercentile: f.EPSSPercentile,
			InKEV: f.InKEV, Malicious: f.Malicious, Verified: f.Verified, References: sortedStrings(f.References),
			FixedVersions:      orEmpty(f.FixedVersions), // already in version order
			RecommendedVersion: f.RecommendedVersion, Bump: f.Bump, Advice: f.Advice, Priority: f.Priority,
			Sources: sortedStrings(f.Sources), FirstSeen: timestamp(f.FirstSeen), LastSeen: timestamp(f.LastSeen),
			Status: f.Status,
		}
		if f.Runtime != nil {
			rt := toRuntime(*f.Runtime)
			d.Runtime = &rt
		}
		out = append(out, d)
	}
	return out
}

func toRuntime(rt model.RuntimeStatus) runtimeStatusDTO {
	out := runtimeStatusDTO{Name: rt.Runtime.Name, Version: rt.Runtime.Version, Origin: rt.Runtime.Origin,
		Via: rt.Runtime.Via, Cycle: rt.Cycle, Status: rt.Status, LatestPatch: rt.LatestPatch,
		LatestCycle: rt.LatestCycle, Source: rt.Source}
	if rt.EOLDate != nil {
		d := rt.EOLDate.UTC().Format(time.DateOnly)
		out.EOLDate = &d
	}
	return out
}

func toPackage(p model.Package) packageDTO {
	return packageDTO{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version, PURL: p.PURL}
}

// timestamp formats t in UTC, or returns nil (JSON null) for the zero time.
func timestamp(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := t.UTC().Format(time.RFC3339Nano)
	return &s
}

// sortedStrings returns a sorted copy of s, never nil, so empty lists encode as [].
func sortedStrings(s []string) []string { return orEmpty(slices.Sorted(slices.Values(s))) }

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
