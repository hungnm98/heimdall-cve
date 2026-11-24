// Package notifytest is the contract test kit for notify.Notifier.
package notifytest

import (
	"context"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/notify"
)

// Events returns one sample event of every type, for contract and golden tests.
func Events() []model.NotificationEvent {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	f := model.Finding{
		ID: "f1", Kind: model.KindDependency, Repo: "acme/api", ManifestPath: "go.mod",
		Package:    model.NewPackage(model.EcosystemGo, "golang.org/x/net", "v0.20.0"),
		AdvisoryID: "GO-2024-2687", Aliases: []string{"CVE-2023-45288"}, Summary: "HTTP/2 CONTINUATION flood",
		Severity: model.SeverityHigh, RecommendedVersion: "v0.23.0", Bump: model.BumpMinor,
		Sources: []string{"osv"}, FirstSeen: at, LastSeen: at, Status: model.StatusOpen,
	}
	run := &model.ScanRun{ID: 7, StartedAt: at, FinishedAt: at.Add(time.Minute), Status: model.RunSucceeded, ReposScanned: []string{"acme/api"}}
	diff := &model.Diff{FromRun: 6, ToRun: 7, New: []model.Finding{f}}
	return []model.NotificationEvent{
		{Type: model.EventScanSummary, Title: "Daily scan", Run: run, Diff: diff, Findings: []model.Finding{f}},
		{Type: model.EventFindingNew, Title: "New HIGH finding", Severity: model.SeverityHigh, Findings: []model.Finding{f}},
		{Type: model.EventFindingSLABreach, Title: "SLA breached", Severity: model.SeverityHigh, Findings: []model.Finding{f}},
		{Type: model.EventRuntimeEOLSoon, Title: "Go 1.24 EOL soon", Body: "acme/api declares go 1.24"},
		{Type: model.EventAgentMessage, Title: "Agent note", Body: "golang.org/x/net looks unmaintained", Links: []string{"https://example.com"}},
	}
}

// Run sends every sample event and checks delivered() counts one delivery per event.
// delivered reads the fake endpoint the notifier was wired to.
func Run(t *testing.T, n notify.Notifier, delivered func() int) {
	t.Helper()
	if n.Name() == "" {
		t.Fatal("Name() must not be empty")
	}
	ctx := context.Background()
	evs := Events()
	for _, ev := range evs {
		if err := n.Notify(ctx, ev); err != nil {
			t.Errorf("Notify(%s): %v", ev.Type, err)
		}
	}
	if got := delivered(); got != len(evs) {
		t.Errorf("delivered %d messages, want %d", got, len(evs))
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := n.Notify(canceled, evs[0]); err == nil {
		t.Error("Notify with a canceled context must fail")
	}
}
