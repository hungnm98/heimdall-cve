package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

// notify sends what changed, never the same thing twice: every event has an
// idempotency key recorded with Store.MarkNotified before delivery
// (at-most-once, so a failing channel never causes daily spam).
//
//   - scan.summary once per run
//   - finding.new for new CRITICAL, KEV or malicious findings
//   - finding.sla_breached when an open finding outlives policy.sla_days
//   - runtime.eol_soon for new end-of-life runtime findings
func (p *Pipeline) notify(ctx context.Context, rep *model.Report, all []model.Finding, prog Progress) {
	if len(p.Notifiers) == 0 || rep.Diff == nil {
		return
	}
	run := rep.Run
	open := append(append([]model.Finding{}, rep.Diff.New...), rep.Diff.StillOpen...)
	sort.SliceStable(open, func(i, j int) bool { return open[i].Priority > open[j].Priority })

	var events []keyed
	summary := model.NotificationEvent{
		Type: model.EventScanSummary, Run: &run, Diff: rep.Diff, Findings: open,
		Title:    fmt.Sprintf("Heimdall scan #%d: %d new, %d fixed, %d open", run.ID, len(rep.Diff.New), len(rep.Diff.Fixed), len(open)),
		Severity: worst(open),
	}
	if p.UIBaseURL != "" {
		summary.Links = []string{fmt.Sprintf("%s/#/runs/%d", p.UIBaseURL, run.ID)}
	}
	events = append(events, keyed{fmt.Sprintf("scan.summary:%d", run.ID), summary})

	for _, f := range rep.Diff.New {
		switch {
		case f.Kind == model.KindRuntime:
			events = append(events, keyed{"runtime.eol_soon:" + f.ID, p.single(model.EventRuntimeEOLSoon, f, f.Summary)})
		case f.Severity == model.SeverityCritical || f.InKEV || f.Malicious:
			title := fmt.Sprintf("New %s finding in %s: %s %s", label(f), f.Repo, f.Package.Name, f.AdvisoryID)
			events = append(events, keyed{"finding.new:" + f.ID, p.single(model.EventFindingNew, f, title)})
		}
	}
	now := p.now()
	for _, f := range open {
		days, ok := p.Policy.SLADays[string(f.Severity)]
		if !ok || days <= 0 || f.FirstSeen.IsZero() || now.Sub(f.FirstSeen) <= time.Duration(days)*24*time.Hour {
			continue
		}
		title := fmt.Sprintf("SLA breached (%dd for %s) in %s: %s %s", days, f.Severity, f.Repo, f.Package.Name, f.AdvisoryID)
		events = append(events, keyed{"finding.sla_breached:" + f.ID, p.single(model.EventFindingSLABreach, f, title)})
	}

	sent := 0
	for _, e := range events {
		first, err := p.Store.MarkNotified(ctx, e.key, now)
		if err != nil {
			p.log().Warn("notification idempotency", "key", e.key, "err", err)
			continue
		}
		if !first {
			continue
		}
		for _, n := range p.Notifiers {
			if err := n.Notify(ctx, e.ev); err != nil {
				prog.Event("warn", "", fmt.Sprintf("notifier %s: %v", n.Name(), err))
				continue
			}
			sent++
		}
	}
	if sent > 0 {
		prog.Event("info", "", fmt.Sprintf("sent %d notifications", sent))
	}
}

type keyed struct {
	key string
	ev  model.NotificationEvent
}

func (p *Pipeline) single(t model.EventType, f model.Finding, title string) model.NotificationEvent {
	ev := model.NotificationEvent{Type: t, Title: title, Severity: f.Severity, Findings: []model.Finding{f}}
	if p.UIBaseURL != "" {
		ev.Links = []string{fmt.Sprintf("%s/#/findings/%s", p.UIBaseURL, f.ID)}
	}
	return ev
}

func label(f model.Finding) string {
	switch {
	case f.Malicious:
		return "MALICIOUS"
	case f.InKEV:
		return "KEV"
	}
	return string(f.Severity)
}

func worst(fs []model.Finding) model.Severity {
	w := model.SeverityUnknown
	for _, f := range fs {
		if f.Severity.Rank() > w.Rank() {
			w = f.Severity
		}
	}
	return w
}

// writeReports renders every format to ReportDir/run-<id><ext> and
// latest<ext>. Report failures are logged, never fatal.
func (p *Pipeline) writeReports(rep *model.Report, prog Progress) {
	if p.ReportDir == "" || len(p.Reporters) == 0 {
		return
	}
	if err := os.MkdirAll(p.ReportDir, 0o755); err != nil {
		prog.Event("warn", "", fmt.Sprintf("report dir: %v", err))
		return
	}
	for _, r := range p.Reporters {
		for _, name := range []string{fmt.Sprintf("run-%d%s", rep.Run.ID, r.FileExtension()), "latest" + r.FileExtension()} {
			if err := writeFileAtomic(filepath.Join(p.ReportDir, name), func(f *os.File) error { return r.Render(f, rep) }); err != nil {
				prog.Event("warn", "", fmt.Sprintf("report %s: %v", r.Format(), err))
			}
		}
	}
	prog.Event("info", "", fmt.Sprintf("reports written to %s", p.ReportDir))
}

func writeFileAtomic(path string, write func(*os.File) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	if err := write(tmp); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
