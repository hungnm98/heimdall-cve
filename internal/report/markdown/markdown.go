// Package markdown renders a scan report as GitHub-flavoured Markdown, for PR
// comments, chat attachments and humans reading files.
package markdown

import (
	"bufio"
	"cmp"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/report"
)

func init() { report.Registry.Register("md", New) }

// New builds the reporter. It takes no options.
func New(cfg plugin.Config, _ plugin.Deps) (report.Reporter, error) {
	if err := cfg.Decode(&struct{}{}); err != nil {
		return nil, fmt.Errorf("report md: %w", err)
	}
	return Reporter{}, nil
}

// Reporter implements report.Reporter.
type Reporter struct{}

// Format implements report.Reporter.
func (Reporter) Format() string { return "md" }

// FileExtension implements report.Reporter.
func (Reporter) FileExtension() string { return ".md" }

// Render implements report.Reporter. Output depends only on r.
func (Reporter) Render(w io.Writer, r *model.Report) error {
	bw := bufio.NewWriter(w)
	p := func(format string, a ...any) { fmt.Fprintf(bw, format, a...) }
	writeHeader(p, r)
	writeSources(p, r.Run.Sources)
	writeSummary(p, r)
	writeDiff(p, r.Diff)
	repos := slices.SortedFunc(slices.Values(r.Repos), func(a, b model.RepoReport) int {
		return cmp.Compare(a.Repo.FullName(), b.Repo.FullName())
	})
	if len(repos) == 0 {
		p("## Repositories\n\nNo repositories in this report.\n")
	}
	for _, rr := range repos {
		writeRepo(p, rr)
	}
	return bw.Flush()
}

type printer func(format string, a ...any)

func writeHeader(p printer, r *model.Report) {
	run := r.Run
	p("# Heimdall scan report — run #%d\n\n", run.ID)
	p("- **Generated:** %s\n", fmtTime(r.GeneratedAt))
	p("- **Status:** %s\n", statusLabel(run.Status))
	if !run.StartedAt.IsZero() {
		p("- **Started:** %s\n", fmtTime(run.StartedAt))
	}
	if !run.FinishedAt.IsZero() && !run.StartedAt.IsZero() {
		p("- **Duration:** %s\n", run.FinishedAt.Sub(run.StartedAt).Round(time.Second))
	}
	p("- **Repos scanned:** %d · **failed:** %d\n", len(run.ReposScanned), len(run.ReposFailed))
	if len(run.ReposFailed) > 0 {
		p("- **Failed repos:** %s\n", joinEsc(sorted(run.ReposFailed)))
	}
	if run.Error != "" {
		p("- **Run error:** %s\n", esc(run.Error))
	}
	p("\n")
}

func writeSources(p printer, sources []model.SourceHealth) {
	p("## Source health\n\n")
	if len(sources) == 0 {
		p("No sources recorded.\n\n")
		return
	}
	sources = slices.SortedFunc(slices.Values(sources), func(a, b model.SourceHealth) int { return cmp.Compare(a.Name, b.Name) })
	var unhealthy []string
	for _, s := range sources {
		if !s.Healthy {
			unhealthy = append(unhealthy, esc(s.Name))
		}
	}
	if len(unhealthy) > 0 {
		p("> [!WARNING]\n> Unhealthy sources: **%s**. Results may be incomplete.\n\n", strings.Join(unhealthy, ", "))
	}
	p("| Source | Status | Calls | Duration | Error |\n|---|---|---:|---:|---|\n")
	for _, s := range sources {
		status := "✅ healthy"
		if !s.Healthy {
			status = "❌ **unhealthy**"
		}
		p("| %s | %s | %d | %s | %s |\n", esc(s.Name), status, s.Calls, s.Duration.Round(time.Millisecond), esc(s.Error))
	}
	p("\n")
}

func writeSummary(p printer, r *model.Report) {
	counts := map[model.Severity]int{}
	total, kev, mal := 0, 0, 0
	for _, rr := range r.Repos {
		for _, f := range rr.Findings {
			counts[f.Severity]++
			total++
			if f.InKEV {
				kev++
			}
			if f.Malicious {
				mal++
			}
		}
	}
	p("## Summary\n\n| Severity | Findings |\n|---|---:|\n")
	for _, s := range severities {
		p("| %s %s | %d |\n", severityEmoji(s), s, counts[s])
	}
	p("| **Total** | **%d** |\n\n", total)
	p("- **Known exploited (CISA KEV):** %d\n- **Malicious packages:** %d\n\n", kev, mal)
}

func writeDiff(p printer, d *model.Diff) {
	p("## New since previous run\n\n")
	if d == nil {
		p("No previous run to compare against.\n\n")
		return
	}
	p("Run #%d → #%d: **%d new**, %d fixed, %d still open.\n\n", d.FromRun, d.ToRun, len(d.New), len(d.Fixed), len(d.StillOpen))
	if len(d.New) == 0 {
		return
	}
	p("| Repo | Package | Current → Recommended | Bump | Severity | Advisory |\n|---|---|---|---|---|---|\n")
	for _, f := range sortFindings(d.New) {
		p("| %s | %s | %s | %s | %s | %s |\n", esc(f.Repo), esc(f.Package.Name),
			versions(f.Package.Version, f.RecommendedVersion), bumpLabel(f.Bump), severityCell(f.Severity), advisoryLink(f.AdvisoryID))
	}
	p("\n")
}

func writeRepo(p printer, rr model.RepoReport) {
	p("## %s\n\n", esc(rr.Repo.FullName()))
	var meta []string
	if u := safeURL(rr.Repo.HTMLURL); u != "" {
		meta = append(meta, fmt.Sprintf("[repository](%s)", u))
	}
	if rr.Repo.Ref != "" {
		meta = append(meta, "ref "+esc(rr.Repo.Ref))
	}
	if rr.HeadSHA != "" {
		meta = append(meta, "commit "+esc(shortSHA(rr.HeadSHA)))
	}
	meta = append(meta, fmt.Sprintf("%d findings", len(rr.Findings)))
	p("%s\n\n", strings.Join(meta, " · "))

	p("### Upgrade plan\n\n")
	if len(rr.UpgradePlan) == 0 {
		p("Nothing to upgrade.\n\n")
	} else {
		items := slices.SortedFunc(slices.Values(rr.UpgradePlan), func(a, b model.UpgradeItem) int {
			return cmp.Or(
				cmp.Compare(b.Severity.Rank(), a.Severity.Rank()),
				cmp.Compare(a.Package.Name, b.Package.Name),
				cmp.Compare(a.Manifest, b.Manifest),
				cmp.Compare(a.Recommended, b.Recommended),
			)
		})
		p("| Package | Manifest | Current → Recommended | Bump | Severity | Advisories |\n|---|---|---|---|---|---|\n")
		for _, it := range items {
			name := esc(it.Package.Name)
			if !it.Direct {
				name += " (transitive)"
			}
			links := make([]string, 0, len(it.Advisories))
			for _, id := range sorted(it.Advisories) {
				links = append(links, advisoryLink(id))
			}
			p("| %s | %s | %s | %s | %s | %s |\n", name, esc(it.Manifest), versions(it.Package.Version, it.Recommended),
				bumpLabel(it.Bump), severityCell(it.Severity), strings.Join(links, ", "))
		}
		p("\n")
	}

	p("### Runtimes\n\n")
	if len(rr.Runtimes) == 0 {
		p("No runtimes detected.\n\n")
	} else {
		rts := slices.SortedFunc(slices.Values(rr.Runtimes), func(a, b model.RuntimeStatus) int {
			return cmp.Or(
				cmp.Compare(a.Runtime.Name, b.Runtime.Name),
				cmp.Compare(a.Runtime.Origin, b.Runtime.Origin),
				cmp.Compare(a.Runtime.Version, b.Runtime.Version),
				cmp.Compare(a.Runtime.Via, b.Runtime.Via),
			)
		})
		p("| Runtime | Version | Declared in | Cycle | Support | EOL date | Latest patch | Latest cycle |\n|---|---|---|---|---|---|---|---|\n")
		for _, rt := range rts {
			origin := esc(rt.Runtime.Origin)
			if rt.Runtime.Via != "" {
				origin += " (" + esc(rt.Runtime.Via) + ")"
			}
			eol := ""
			if rt.EOLDate != nil {
				eol = rt.EOLDate.UTC().Format(time.DateOnly)
			}
			p("| %s | %s | %s | %s | %s | %s | %s | %s |\n", esc(rt.Runtime.Name), esc(rt.Runtime.Version), origin,
				esc(rt.Cycle), supportLabel(rt.Status), eol, esc(rt.LatestPatch), esc(rt.LatestCycle))
		}
		p("\n")
	}

	if len(rr.Errors) > 0 {
		p("### Errors\n\n")
		for _, e := range sorted(rr.Errors) {
			p("- %s\n", esc(e))
		}
		p("\n")
	}
}

var severities = []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityUnknown}

func severityEmoji(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "🔴"
	case model.SeverityHigh:
		return "🟠"
	case model.SeverityMedium:
		return "🟡"
	case model.SeverityLow:
		return "🔵"
	}
	return "⚪"
}

func severityCell(s model.Severity) string {
	if s == "" {
		s = model.SeverityUnknown
	}
	return severityEmoji(s) + " " + esc(string(s))
}

func supportLabel(s model.SupportStatus) string {
	switch s {
	case model.SupportEOL:
		return "🔴 **EOL**"
	case model.SupportEOLSoon:
		return "🟠 **EOL soon**"
	case model.SupportSecurityOnly:
		return "🟡 security-only"
	case model.SupportSupported:
		return "🟢 supported"
	}
	return "⚪ unknown"
}

func statusLabel(s model.RunStatus) string {
	switch s {
	case model.RunSucceeded:
		return "✅ succeeded"
	case model.RunPartial:
		return "⚠️ partial"
	case model.RunFailed:
		return "❌ failed"
	case model.RunRunning:
		return "⏳ running"
	}
	return "unknown"
}

func bumpLabel(b model.BumpType) string {
	switch b {
	case model.BumpMajor:
		return "⚠️ major"
	case model.BumpNone:
		return ""
	}
	return esc(string(b))
}

func versions(current, recommended string) string {
	cur := esc(current)
	if cur == "" {
		cur = "?"
	}
	if recommended == "" {
		return cur + " → no fix"
	}
	return cur + " → " + esc(recommended)
}

// advisoryLink links an advisory id to its OSV page.
func advisoryLink(id string) string {
	if id == "" {
		return ""
	}
	return fmt.Sprintf("[%s](https://osv.dev/vulnerability/%s)", esc(id), url.PathEscape(id))
}

func sortFindings(fs []model.Finding) []model.Finding {
	return slices.SortedFunc(slices.Values(fs), func(a, b model.Finding) int {
		return cmp.Or(
			cmp.Compare(b.Severity.Rank(), a.Severity.Rank()),
			cmp.Compare(a.Repo, b.Repo),
			cmp.Compare(a.Package.Name, b.Package.Name),
			cmp.Compare(a.AdvisoryID, b.AdvisoryID),
			cmp.Compare(a.ManifestPath, b.ManifestPath),
			cmp.Compare(a.ID, b.ID),
		)
	})
}

func sorted(s []string) []string { return slices.Sorted(slices.Values(s)) }

func joinEsc(s []string) string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = esc(v)
	}
	return strings.Join(out, ", ")
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format(time.RFC3339)
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// safeURL returns u when it is an absolute http(s) URL, with characters that
// would end a Markdown link escaped; otherwise "".
func safeURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return ""
	}
	return strings.NewReplacer(" ", "%20", "(", "%28", ")", "%29", "<", "%3C", ">", "%3E", "|", "%7C").Replace(parsed.String())
}

// mdEscaper neutralises characters that would change Markdown structure
// (tables, emphasis, links, HTML) inside user-controlled strings.
var mdEscaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`,
	"<", `\<`, ">", `\>`, "|", `\|`, "#", `\#`, "~", `\~`, "!", `\!`,
	"\r\n", " ", "\n", " ", "\r", " ",
)

func esc(s string) string { return mdEscaper.Replace(s) }
