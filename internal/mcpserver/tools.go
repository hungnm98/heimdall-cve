package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/service"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// Tool limits: agents get small pages by default.
const (
	defaultToolLimit = 20
	maxToolLimit     = 100
	maxDiffItems     = 50
	recentEvents     = 10
)

func toolLimit(n int) int {
	switch {
	case n <= 0:
		return defaultToolLimit
	case n > maxToolLimit:
		return maxToolLimit
	}
	return n
}

func badArg(field, msg string) error {
	return &service.ValidationError{Fields: map[string]string{field: msg}}
}

var errNoIntel = fmt.Errorf("agent intelligence is not available: the configured store does not implement it: %w", service.ErrUnavailable)

// ---- inputs ----

type noArgs struct{}

type listReposIn struct {
	TargetID int64  `json:"target_id,omitempty" jsonschema:"only repos of this target (see list_targets)"`
	Q        string `json:"q,omitempty" jsonschema:"substring of owner/name"`
	Cursor   string `json:"cursor,omitempty" jsonschema:"next_cursor from the previous page"`
	Limit    int    `json:"limit,omitempty" jsonschema:"page size (default 20, max 100)"`
}

type inventoryIn struct {
	Repo       string `json:"repo,omitempty" jsonschema:"owner/name"`
	Ecosystem  string `json:"ecosystem,omitempty" jsonschema:"go, npm or rubygems"`
	Name       string `json:"name,omitempty" jsonschema:"exact package name"`
	DirectOnly bool   `json:"direct_only,omitempty" jsonschema:"only direct dependencies"`
	Limit      int    `json:"limit,omitempty" jsonschema:"max items (default 20, max 100)"`
}

type queueIn struct {
	Limit     int `json:"limit,omitempty" jsonschema:"max libraries (default 20, max 100)"`
	StaleDays int `json:"stale_days,omitempty" jsonschema:"an analysis older than this many days is stale (default 30)"`
}

type analysesIn struct {
	Ecosystem string `json:"ecosystem" jsonschema:"go, npm or rubygems"`
	Name      string `json:"name" jsonschema:"package name"`
	Limit     int    `json:"limit,omitempty" jsonschema:"max analyses, newest first (default 20)"`
}

type findingsIn struct {
	Repo              string `json:"repo,omitempty" jsonschema:"owner/name"`
	Severity          string `json:"severity,omitempty" jsonschema:"minimum severity: CRITICAL, HIGH, MEDIUM or LOW"`
	Kind              string `json:"kind,omitempty" jsonschema:"dependency, runtime, code, secret or config"`
	Status            string `json:"status,omitempty" jsonschema:"open (default), fixed, suppressed or all"`
	KEV               bool   `json:"kev,omitempty" jsonschema:"only findings in CISA KEV"`
	Branch            string `json:"branch,omitempty" jsonschema:"only this extra branch; omitted = every branch (primary-branch findings have no branch field)"`
	PrimaryBranchOnly bool   `json:"primary_branch_only,omitempty" jsonschema:"only findings of each repo's primary (default or configured) branch"`
	NewSince          string `json:"new_since,omitempty" jsonschema:"first seen at or after this time (RFC 3339 or YYYY-MM-DD)"`
	Q                 string `json:"q,omitempty" jsonschema:"package name substring or exact advisory id / alias"`
	Sort              string `json:"sort,omitempty" jsonschema:"severity (default), priority, name, first_seen or repo"`
	Order             string `json:"order,omitempty" jsonschema:"asc or desc (default desc for severity, priority, first_seen; asc for name, repo)"`
	Cursor            string `json:"cursor,omitempty" jsonschema:"next_cursor from the previous page (same sort and order)"`
	Limit             int    `json:"limit,omitempty" jsonschema:"page size (default 20, max 100)"`
}

type idIn struct {
	ID string `json:"id" jsonschema:"finding id"`
}

type repoIn struct {
	Repo string `json:"repo" jsonschema:"owner/name"`
}

type runtimeIn struct {
	Repo string `json:"repo,omitempty" jsonschema:"owner/name; omitted = open runtime findings (EOL / EOL soon) across all repos"`
}

type listRunsIn struct {
	Cursor string `json:"cursor,omitempty" jsonschema:"next_cursor from the previous page"`
	Limit  int    `json:"limit,omitempty" jsonschema:"page size (default 20, max 100)"`
}

type diffIn struct {
	RunID   int64 `json:"run_id" jsonschema:"the newer run"`
	Against int64 `json:"against,omitempty" jsonschema:"the older run (default: the run before run_id)"`
}

type scanTargetIn struct {
	TargetID int64 `json:"target_id" jsonschema:"target id from list_targets"`
	Force    bool  `json:"force,omitempty" jsonschema:"rescan even if nothing changed"`
}

type scanRepoIn struct {
	RepoURL     string `json:"repo_url" jsonschema:"https://host/owner/name or git@host:owner/name.git"`
	AuthProfile string `json:"auth_profile" jsonschema:"name of a configured auth profile"`
	Branch      string `json:"branch,omitempty" jsonschema:"branch to scan (default branch if omitted)"`
}

type jobIn struct {
	JobID int64 `json:"job_id" jsonschema:"job id returned by scan_target or scan_repo"`
}

type advisoryIn struct {
	OSVJSON    any      `json:"osv_json" jsonschema:"an OSV record, as a JSON string or object. Omit id to get HEIMDALL-AGENT-<year>-<n>; public ids (CVE-, GHSA-...) go in aliases"`
	Evidence   []string `json:"evidence" jsonschema:"https URLs supporting the advisory (at least one)"`
	Confidence string   `json:"confidence" jsonschema:"low, medium or high"`
}

type analysisIn struct {
	Ecosystem          string   `json:"ecosystem" jsonschema:"go, npm or rubygems"`
	Name               string   `json:"name" jsonschema:"package name"`
	Version            string   `json:"version,omitempty" jsonschema:"version analyzed (omit for the library in general)"`
	Verdict            string   `json:"verdict" jsonschema:"ok, safe-to-bump, breaking-change, abandoned, suspicious-release or malicious"`
	Summary            string   `json:"summary" jsonschema:"what you checked and found, 10 to 4000 characters"`
	Evidence           []string `json:"evidence" jsonschema:"https URLs (at least one)"`
	RecommendedVersion string   `json:"recommended_version,omitempty" jsonschema:"version to upgrade to, if any"`
	Confidence         string   `json:"confidence" jsonschema:"low, medium or high"`
}

type triageIn struct {
	MinSeverity string `json:"min_severity,omitempty" jsonschema:"CRITICAL, HIGH (default), MEDIUM or LOW; KEV and malicious findings are included at any severity"`
	Repo        string `json:"repo,omitempty" jsonschema:"owner/name"`
	KEVOnly     bool   `json:"kev_only,omitempty" jsonschema:"only findings in CISA KEV"`
	Limit       int    `json:"limit,omitempty" jsonschema:"max items (default 20, max 100)"`
	StaleDays   int    `json:"stale_days,omitempty" jsonschema:"an assessment older than this many days is redone (default 30)"`
}

type assessmentIn struct {
	FindingID    string   `json:"finding_id" jsonschema:"finding id (from triage_queue or get_findings)"`
	Decision     string   `json:"decision" jsonschema:"fix-now, schedule, monitor, not-affected or false-positive"`
	Score        float64  `json:"score" jsonschema:"your urgency, 0 to 100"`
	Rationale    string   `json:"rationale,omitempty" jsonschema:"why, at most 4000 characters; at least 20 characters when no evidence is given"`
	Evidence     []string `json:"evidence,omitempty" jsonschema:"https URLs you relied on"`
	Confidence   string   `json:"confidence" jsonschema:"low, medium or high"`
	RepoSpecific bool     `json:"repo_specific,omitempty" jsonschema:"the decision depends on this repo's code (e.g. the vulnerable function is not reachable here); default: applies to every repo using this package version"`
}

type assessmentsIn struct {
	FindingID string `json:"finding_id" jsonschema:"finding id"`
	Limit     int    `json:"limit,omitempty" jsonschema:"max assessments, newest first (default 20)"`
}

type notifyIn struct {
	Title    string   `json:"title" jsonschema:"short title, at most 200 characters"`
	Body     string   `json:"body" jsonschema:"concise message, at most 4000 characters"`
	Severity string   `json:"severity" jsonschema:"CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN"`
	Refs     []string `json:"refs,omitempty" jsonschema:"finding ids, advisory ids or URLs (max 20)"`
}

// ---- registration ----

func (s *Server) addTools() {
	addTool(s, "list_targets", "List scan targets (orgs, users, single repos) with their schedule.", s.listTargets)
	addTool(s, "list_repos", "List cached repositories, optionally of one target or matching a substring. Paginated.", s.listRepos)
	addTool(s, "get_inventory", "Dependencies in use as last scanned (repo, manifest, package, version, direct). Items marked private are internal and must never be researched outside the organisation.", s.getInventory)
	addTool(s, "get_analysis_queue", "Public libraries to analyze next, ranked: never analyzed or stale first, then direct dependencies, wide usage and open findings. Each item says why.", s.getAnalysisQueue)
	addTool(s, "get_analyses", "Analysis history of one library, newest first.", s.getAnalyses)
	addTool(s, "get_findings", "Search findings, worst first (or by sort/order). Defaults to open findings. Paginated.", s.getFindings)
	addTool(s, "get_finding", "One finding in full: advisory, aliases, references, fix versions, recommendation, suppression.", s.getFinding)
	addTool(s, "triage_queue", "Open findings to assess next (HIGH+ by default, KEV and malicious always), without a fresh agent assessment, highest priority first. One item per advisory and package version covers every repo listed. Each item says why.", s.triageQueue)
	addTool(s, "get_assessments", "Agent assessments of a finding (repo-wide and for its repo), newest first.", s.getAssessments)
	addTool(s, "get_upgrade_plan", "Per-package upgrade plan of a repo (recommended version, bump size, advisories fixed).", s.getUpgradePlan)
	addTool(s, "get_runtime_status", "Runtime support status (Go/Node/Ruby EOL) of a repo, or open runtime findings across all repos.", s.getRuntimeStatus)
	addTool(s, "list_runs", "Scan runs, newest first, with stats. Paginated.", s.listRuns)
	addTool(s, "diff_scans", "What changed between two runs: new and fixed findings (worst first, max 50 each) and the count still open.", s.diffScans)
	addTool(s, "list_sources", "Configured vulnerability/runtime sources and their health in the latest run.", s.listSources)
	addTool(s, "scan_target", "Queue a scan of a target (needs --allow-scan). Returns a job id; jobs are executed by `heimdall serve` or `heimdall worker`, poll get_scan_status.", s.scanTarget)
	addTool(s, "scan_repo", "Queue a scan of one repository URL with an auth profile (needs --allow-scan). Returns a job id.", s.scanRepo)
	addTool(s, "get_scan_status", "Status of a scan job and its latest progress events.", s.getScanStatus)
	addTool(s, "submit_advisory", "Submit a vulnerability not yet in public databases, as an OSV record with evidence (needs --allow-agent-writes). Stored as source agent, unverified; it merges with the public record once one shares an alias.", s.submitAdvisory)
	addTool(s, "submit_analysis", "Record your assessment of a library with evidence (needs --allow-agent-writes).", s.submitAnalysis)
	addTool(s, "submit_assessment", "Record your triage of a finding: decision, urgency score and rationale with evidence (needs --allow-agent-writes). Shown beside the finding as unverified; it never changes its priority or status.", s.submitAssessment)
	addTool(s, "notify_user", "Send one concise message to the team through the configured notifiers (needs --allow-notify). Identical messages are sent once; there is a daily limit.", s.notifyUser)
}

// ---- read tools ----

func (s *Server) listTargets(ctx context.Context, _ service.Actor, _ noArgs) (any, error) {
	ts, err := s.svcs.Targets.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]targetOut, 0, len(ts))
	for _, t := range ts {
		out = append(out, toTarget(t))
	}
	return map[string]any{"targets": out}, nil
}

func (s *Server) listRepos(ctx context.Context, _ service.Actor, in listReposIn) (any, error) {
	page, err := s.svcs.Repos.List(ctx, store.RepoFilter{TargetID: in.TargetID, Query: in.Q, After: in.Cursor, Limit: toolLimit(in.Limit)})
	if err != nil {
		return nil, err
	}
	out := make([]repoOut, 0, len(page.Items))
	for _, r := range page.Items {
		out = append(out, toRepo(r))
	}
	return map[string]any{"repos": out, "next_cursor": page.NextCursor}, nil
}

func (s *Server) getInventory(ctx context.Context, _ service.Actor, in inventoryIn) (any, error) {
	if s.svcs.Intel == nil {
		return nil, errNoIntel
	}
	limit := toolLimit(in.Limit)
	items, err := s.svcs.Intel.Inventory(ctx, store.InventoryFilter{
		Repo: in.Repo, Ecosystem: model.Ecosystem(in.Ecosystem), Name: in.Name, DirectOnly: in.DirectOnly, Limit: limit + 1,
	})
	if err != nil {
		return nil, err
	}
	truncated := len(items) > limit
	if truncated {
		items = items[:limit]
	}
	out := make([]inventoryOut, 0, len(items))
	for _, it := range items {
		out = append(out, toInventory(it))
	}
	return map[string]any{"items": out, "truncated": truncated}, nil
}

func (s *Server) getAnalysisQueue(ctx context.Context, _ service.Actor, in queueIn) (any, error) {
	if s.svcs.Intel == nil {
		return nil, errNoIntel
	}
	if in.StaleDays < 0 {
		return nil, badArg("stale_days", "must be positive")
	}
	q, err := s.svcs.Intel.AnalysisQueue(ctx, toolLimit(in.Limit), time.Duration(in.StaleDays)*24*time.Hour)
	if err != nil {
		return nil, err
	}
	out := make([]queueOut, 0, len(q))
	for _, it := range q {
		out = append(out, toQueue(it))
	}
	return map[string]any{"libraries": out}, nil
}

func (s *Server) getAnalyses(ctx context.Context, _ service.Actor, in analysesIn) (any, error) {
	if s.svcs.Intel == nil {
		return nil, errNoIntel
	}
	as, err := s.svcs.Intel.Analyses(ctx, model.Ecosystem(in.Ecosystem), in.Name, toolLimit(in.Limit))
	if err != nil {
		return nil, err
	}
	out := make([]analysisOut, 0, len(as))
	for _, a := range as {
		out = append(out, toAnalysis(a))
	}
	return map[string]any{"analyses": out}, nil
}

func parseSince(v string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", v)
}

func (s *Server) getFindings(ctx context.Context, _ service.Actor, in findingsIn) (any, error) {
	f := store.FindingFilter{Repo: in.Repo, InKEV: in.KEV, Query: in.Q, After: in.Cursor, Limit: toolLimit(in.Limit),
		Branch: in.Branch, DefaultBranchOnly: in.PrimaryBranchOnly,
		Sort: store.FindingSort(strings.ToLower(in.Sort)), Order: store.SortOrder(strings.ToLower(in.Order))}
	if in.Severity != "" {
		if f.MinSeverity = model.ParseSeverity(in.Severity); f.MinSeverity == model.SeverityUnknown {
			return nil, badArg("severity", "must be CRITICAL, HIGH, MEDIUM or LOW")
		}
	}
	switch k := model.FindingKind(strings.ToLower(in.Kind)); k {
	case "", model.KindDependency, model.KindRuntime, model.KindCode, model.KindSecret, model.KindConfig:
		f.Kind = k
	default:
		return nil, badArg("kind", "must be dependency, runtime, code, secret or config")
	}
	switch st := model.FindingStatus(strings.ToLower(in.Status)); st {
	case "":
		f.Status = model.StatusOpen
	case "all":
	case model.StatusOpen, model.StatusFixed, model.StatusSuppressed:
		f.Status = st
	default:
		return nil, badArg("status", "must be open, fixed, suppressed or all")
	}
	if in.NewSince != "" {
		t, err := parseSince(in.NewSince)
		if err != nil {
			return nil, badArg("new_since", "must be RFC 3339 or YYYY-MM-DD")
		}
		f.NewSince = t
	}
	page, err := s.svcs.Findings.List(ctx, f)
	if err != nil {
		return nil, err
	}
	assessed, err := s.assessmentsOf(ctx, page.Items)
	if err != nil {
		return nil, err
	}
	out := make([]findingOut, 0, len(page.Items))
	for _, it := range page.Items {
		fo := toFinding(it)
		if st, ok := assessed[it.ID]; ok {
			fo.AgentAssessment = toAssessmentBrief(st)
		}
		out = append(out, fo)
	}
	return map[string]any{"findings": out, "next_cursor": page.NextCursor}, nil
}

func (s *Server) getFinding(ctx context.Context, _ service.Actor, in idIn) (any, error) {
	if strings.TrimSpace(in.ID) == "" {
		return nil, badArg("id", "required")
	}
	d, err := s.svcs.Findings.Get(ctx, strings.TrimSpace(in.ID))
	if err != nil {
		return nil, err
	}
	assessed, err := s.assessmentsOf(ctx, []model.Finding{d.Finding})
	if err != nil {
		return nil, err
	}
	out := toFindingDetail(d)
	if st, ok := assessed[d.Finding.ID]; ok {
		out.AgentAssessment = toAssessmentBrief(st)
	}
	return out, nil
}

// assessmentsOf returns the latest agent assessment per finding id (none
// without agent intelligence).
func (s *Server) assessmentsOf(ctx context.Context, fs []model.Finding) (map[string]service.AssessmentStatus, error) {
	if s.svcs.Intel == nil {
		return nil, nil
	}
	return s.svcs.Intel.LatestAssessments(ctx, fs, 0)
}

func (s *Server) triageQueue(ctx context.Context, _ service.Actor, in triageIn) (any, error) {
	if s.svcs.Intel == nil {
		return nil, errNoIntel
	}
	if in.StaleDays < 0 {
		return nil, badArg("stale_days", "must be positive")
	}
	q, err := s.svcs.Intel.TriageQueue(ctx, service.TriageFilter{
		MinSeverity: model.Severity(in.MinSeverity), Repo: in.Repo, KEVOnly: in.KEVOnly, Limit: toolLimit(in.Limit),
		StaleAfter: time.Duration(in.StaleDays) * 24 * time.Hour,
	})
	if err != nil {
		return nil, err
	}
	out := make([]triageOut, 0, len(q))
	for _, it := range q {
		out = append(out, toTriage(it))
	}
	return map[string]any{"items": out}, nil
}

func (s *Server) getAssessments(ctx context.Context, _ service.Actor, in assessmentsIn) (any, error) {
	if s.svcs.Intel == nil {
		return nil, errNoIntel
	}
	as, err := s.svcs.Intel.Assessments(ctx, in.FindingID, toolLimit(in.Limit))
	if err != nil {
		return nil, err
	}
	out := make([]assessmentOut, 0, len(as))
	for _, a := range as {
		out = append(out, toAssessment(a))
	}
	return map[string]any{"assessments": out}, nil
}

func (s *Server) repoDetail(ctx context.Context, repo string) (*service.RepoDetail, error) {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return nil, badArg("repo", "required (owner/name)")
	}
	d, err := s.svcs.Repos.Get(ctx, repo, "")
	if err != nil {
		return nil, fmt.Errorf("repo %q: %w", repo, err)
	}
	return d, nil
}

func (s *Server) getUpgradePlan(ctx context.Context, _ service.Actor, in repoIn) (any, error) {
	d, err := s.repoDetail(ctx, in.Repo)
	if err != nil {
		return nil, err
	}
	out := make([]upgradeOut, 0, len(d.UpgradePlan))
	for _, u := range d.UpgradePlan {
		out = append(out, toUpgrade(u))
	}
	return map[string]any{"repo": d.Record.FullName(), "upgrades": out}, nil
}

func (s *Server) getRuntimeStatus(ctx context.Context, _ service.Actor, in runtimeIn) (any, error) {
	var out []runtimeOut
	if in.Repo != "" {
		d, err := s.repoDetail(ctx, in.Repo)
		if err != nil {
			return nil, err
		}
		for _, r := range d.Runtimes {
			out = append(out, toRuntime(d.Record.FullName(), r))
		}
		return map[string]any{"runtimes": nonNil(out)}, nil
	}
	page, err := s.svcs.Findings.List(ctx, store.FindingFilter{Kind: model.KindRuntime, Status: model.StatusOpen, Limit: maxToolLimit})
	if err != nil {
		return nil, err
	}
	for _, f := range page.Items {
		if f.Runtime != nil {
			out = append(out, toRuntime(f.Repo, *f.Runtime))
		}
	}
	return map[string]any{"runtimes": nonNil(out), "truncated": page.NextCursor != ""}, nil
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func (s *Server) listRuns(ctx context.Context, _ service.Actor, in listRunsIn) (any, error) {
	var before int64
	if in.Cursor != "" {
		n, err := strconv.ParseInt(in.Cursor, 10, 64)
		if err != nil || n <= 0 {
			return nil, badArg("cursor", "invalid cursor")
		}
		before = n
	}
	page, err := s.svcs.Runs.List(ctx, before, toolLimit(in.Limit))
	if err != nil {
		return nil, err
	}
	out := make([]runOut, 0, len(page.Items))
	for _, r := range page.Items {
		out = append(out, toRun(r))
	}
	return map[string]any{"runs": out, "next_cursor": page.NextCursor}, nil
}

func worstFirst(fs []model.Finding) []findingOut {
	fs = append([]model.Finding(nil), fs...)
	sort.SliceStable(fs, func(i, j int) bool {
		if a, b := fs[i].Severity.Rank(), fs[j].Severity.Rank(); a != b {
			return a > b
		}
		return fs[i].Priority > fs[j].Priority
	})
	out := make([]findingOut, 0, min(len(fs), maxDiffItems))
	for _, f := range fs[:min(len(fs), maxDiffItems)] {
		out = append(out, toFinding(f))
	}
	return out
}

func (s *Server) diffScans(ctx context.Context, _ service.Actor, in diffIn) (any, error) {
	if in.RunID <= 0 {
		return nil, badArg("run_id", "required (see list_runs)")
	}
	d, err := s.svcs.Runs.Diff(ctx, in.RunID, in.Against)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"from_run": d.FromRun, "to_run": d.ToRun,
		"new_count": len(d.New), "fixed_count": len(d.Fixed), "still_open_count": len(d.StillOpen),
		"new": worstFirst(d.New), "fixed": worstFirst(d.Fixed),
	}, nil
}

func (s *Server) listSources(ctx context.Context, _ service.Actor, _ noArgs) (any, error) {
	srcs, err := s.svcs.System.Sources(ctx)
	if err != nil {
		return nil, err
	}
	type sourceOut struct {
		Name     string   `json:"name"`
		Kinds    []string `json:"kinds"`
		Healthy  bool     `json:"healthy"`
		Error    string   `json:"error,omitempty"`
		LastSeen string   `json:"last_seen,omitempty"`
	}
	out := make([]sourceOut, 0, len(srcs))
	for _, src := range srcs {
		out = append(out, sourceOut{Name: src.Name, Kinds: src.Kinds, Healthy: src.Healthy, Error: src.Error, LastSeen: tsPtr(src.LastSeen)})
	}
	return map[string]any{"sources": out}, nil
}

// ---- scan tools ----

const jobNote = "queued: jobs are executed by `heimdall serve` or `heimdall worker`; poll get_scan_status"

func (s *Server) scanTarget(ctx context.Context, actor service.Actor, in scanTargetIn) (any, error) {
	if !s.opts.AllowScan {
		return nil, disabledError("scan_target")
	}
	if in.TargetID <= 0 {
		return nil, badArg("target_id", "required (see list_targets)")
	}
	id := in.TargetID
	return s.trigger(ctx, actor, service.JobRequest{TargetID: &id, Force: in.Force, Trigger: model.TriggerMCP})
}

func (s *Server) scanRepo(ctx context.Context, actor service.Actor, in scanRepoIn) (any, error) {
	if !s.opts.AllowScan {
		return nil, disabledError("scan_repo")
	}
	if strings.TrimSpace(in.RepoURL) == "" {
		return nil, badArg("repo_url", "required")
	}
	return s.trigger(ctx, actor, service.JobRequest{RepoURL: in.RepoURL, AuthProfile: in.AuthProfile, Branch: in.Branch, Trigger: model.TriggerMCP})
}

func (s *Server) trigger(ctx context.Context, actor service.Actor, req service.JobRequest) (any, error) {
	j, created, err := s.svcs.Jobs.Trigger(ctx, actor, req)
	if err != nil {
		return nil, err
	}
	note := jobNote
	if !created {
		note = "a job for this scope is already active; follow it with get_scan_status"
	}
	return map[string]any{"job": toJob(*j), "created": created, "note": note}, nil
}

func (s *Server) getScanStatus(ctx context.Context, _ service.Actor, in jobIn) (any, error) {
	if in.JobID <= 0 {
		return nil, badArg("job_id", "required")
	}
	j, err := s.svcs.Jobs.Get(ctx, in.JobID)
	if err != nil {
		return nil, fmt.Errorf("job %d: %w", in.JobID, err)
	}
	out := toJob(*j)
	evs, err := s.svcs.Jobs.Events(ctx, j.ID, 0, 1000)
	if err != nil {
		return nil, err
	}
	for _, e := range evs[max(0, len(evs)-recentEvents):] {
		out.Events = append(out.Events, eventOut{At: ts(e.At), Level: e.Level, Repo: e.Repo, Message: e.Message})
	}
	return out, nil
}

// ---- intel writes ----

func (s *Server) submitAdvisory(ctx context.Context, actor service.Actor, in advisoryIn) (any, error) {
	if s.svcs.Intel == nil {
		return nil, errNoIntel
	}
	var raw []byte
	switch v := in.OSVJSON.(type) {
	case nil:
	case string:
		raw = []byte(v)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, badArg("osv_json", "not JSON")
		}
		raw = b
	}
	a, err := s.svcs.Intel.SubmitAdvisory(ctx, actor, service.AdvisoryInput{OSV: raw, Evidence: in.Evidence, Confidence: model.Confidence(in.Confidence)})
	if err != nil {
		return nil, err
	}
	pkgs := make([]string, 0, len(a.Advisory.Affected))
	for _, af := range a.Advisory.Affected {
		pkgs = append(pkgs, string(af.Ecosystem)+"/"+af.Name)
	}
	return map[string]any{
		"id": a.Advisory.ID, "aliases": a.Advisory.Aliases, "severity": a.Advisory.Severity, "packages": pkgs,
		"source": model.AgentSource, "verified": false,
		"note": "stored; the next scan reports it as unverified findings until a public source confirms it",
	}, nil
}

func (s *Server) submitAnalysis(ctx context.Context, actor service.Actor, in analysisIn) (any, error) {
	if s.svcs.Intel == nil {
		return nil, errNoIntel
	}
	a, err := s.svcs.Intel.SubmitAnalysis(ctx, actor, service.AnalysisInput{
		Ecosystem: model.Ecosystem(in.Ecosystem), Name: in.Name, Version: in.Version, Verdict: model.Verdict(in.Verdict),
		Summary: in.Summary, Evidence: in.Evidence, RecommendedVersion: in.RecommendedVersion, Confidence: model.Confidence(in.Confidence),
	})
	if err != nil {
		return nil, err
	}
	return toAnalysis(*a), nil
}

func (s *Server) submitAssessment(ctx context.Context, actor service.Actor, in assessmentIn) (any, error) {
	if s.svcs.Intel == nil {
		return nil, errNoIntel
	}
	a, err := s.svcs.Intel.SubmitAssessment(ctx, actor, service.AssessmentInput{
		FindingID: in.FindingID, Decision: model.Decision(in.Decision), Score: in.Score, Rationale: in.Rationale,
		Evidence: in.Evidence, Confidence: model.Confidence(in.Confidence), RepoSpecific: in.RepoSpecific,
	})
	if err != nil {
		return nil, err
	}
	return toAssessment(*a), nil
}

func (s *Server) notifyUser(ctx context.Context, actor service.Actor, in notifyIn) (any, error) {
	if s.svcs.Messenger == nil {
		return nil, errNoIntel
	}
	sent, err := s.svcs.Messenger.NotifyUser(ctx, actor, service.MessageInput{
		Title: in.Title, Body: in.Body, Severity: model.Severity(in.Severity), Refs: in.Refs,
	})
	if err != nil {
		return nil, err
	}
	note := "sent"
	if !sent {
		note = "not sent: an identical message was already sent"
	}
	return map[string]any{"sent": sent, "note": note}, nil
}
