package slackwebhook

import (
	"cmp"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

// Slack Block Kit limits (https://api.slack.com/reference/block-kit/blocks).
const (
	maxBlocks      = 50
	maxText        = 3000 // section / context text
	maxField       = 2000 // one section field
	maxFields      = 10
	maxHeader      = 150
	maxButtons     = 25
	maxButtonLabel = 75
	maxURL         = 3000
	maxFallback    = 3000
)

// message is the JSON body of an Incoming Webhook post.
type message struct {
	Text   string  `json:"text"` // notification / accessibility fallback
	Blocks []block `json:"blocks"`
}

type textObj struct {
	Type  string `json:"type"` // "plain_text" | "mrkdwn"
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
}

type block struct {
	Type     string    `json:"type"`
	Text     *textObj  `json:"text,omitempty"`
	Fields   []textObj `json:"fields,omitempty"`
	Elements []any     `json:"elements,omitempty"` // textObj (context) or button (actions)
}

type button struct {
	Type     string  `json:"type"` // "button"
	Text     textObj `json:"text"`
	URL      string  `json:"url"`
	ActionID string  `json:"action_id"`
}

type link struct{ label, url string }

type renderer struct {
	cfg    Config
	blocks []block
	links  []link
}

// render turns ev into a Slack message within Slack's size limits. It only
// reads ev and cfg, so the same input always yields the same payload.
func render(ev model.NotificationEvent, cfg Config) message {
	r := &renderer{cfg: cfg}
	switch ev.Type {
	case model.EventScanSummary:
		r.scanSummary(ev)
	case model.EventFindingNew, model.EventFindingSLABreach:
		r.findingAlert(ev)
	case model.EventRuntimeEOLSoon:
		r.runtimeEOL(ev)
	case model.EventAgentMessage:
		r.agentMessage(ev)
	default:
		r.header(":bell:", ev.Title, string(ev.Type))
		r.body(ev.Body)
		r.findingList("*Findings*", ev.Findings)
	}
	for _, l := range ev.Links {
		r.link(linkLabel(l), l)
	}
	r.actions()
	footer := []string{"Heimdall", "`" + mrkdwn(string(ev.Type)) + "`"}
	if cfg.ChannelLabel != "" {
		footer = append(footer, mrkdwn(cfg.ChannelLabel))
	}
	r.context(strings.Join(footer, " · "))
	if len(r.blocks) > maxBlocks {
		omitted := len(r.blocks) - (maxBlocks - 1)
		r.blocks = append(r.blocks[:maxBlocks-1], contextBlock(fmt.Sprintf("…and %d more blocks omitted", omitted)))
	}
	return message{Text: fallback(ev), Blocks: r.blocks}
}

func (r *renderer) scanSummary(ev model.NotificationEvent) {
	r.header(":shield:", ev.Title, "Heimdall scan summary")
	run := ev.Run
	if run == nil {
		run = &model.ScanRun{}
	}
	runLabel := fmt.Sprintf("#%d", run.ID)
	if u := r.uiURL("runs", strconv.FormatInt(run.ID, 10)); u != "" && run.ID != 0 {
		runLabel = slackLink(u, runLabel)
		r.link("Open run in Heimdall", u)
	}
	fields := []string{
		"*Run*\n" + runLabel,
		"*Status*\n" + runStatus(run.Status),
		fmt.Sprintf("*Repos scanned*\n%d", len(run.ReposScanned)),
		fmt.Sprintf("*Repos failed*\n%d", len(run.ReposFailed)),
	}
	if d := ev.Diff; d != nil {
		fields = append(fields,
			fmt.Sprintf("*New*\n%d", len(d.New)),
			fmt.Sprintf("*Fixed*\n%d", len(d.Fixed)),
			fmt.Sprintf("*Still open*\n%d", len(d.StillOpen)))
	} else {
		fields = append(fields, fmt.Sprintf("*New*\n%d", run.Stats.New), fmt.Sprintf("*Fixed*\n%d", run.Stats.Fixed))
	}
	if !run.FinishedAt.IsZero() {
		fields = append(fields, "*Finished*\n"+run.FinishedAt.UTC().Format("2006-01-02 15:04 UTC"))
	}
	r.fields(fields...)

	deps, runtimes := splitFindings(ev.Findings)
	counts := run.Stats.OpenBySeverity
	if len(counts) == 0 {
		counts = map[model.Severity]int{}
		for _, f := range deps {
			counts[f.Severity]++
		}
	}
	parts := make([]string, 0, len(severities))
	for _, s := range severities {
		parts = append(parts, fmt.Sprintf("%s %s *%d*", severityEmoji(s), s, counts[s]))
	}
	kev, mal := 0, 0
	for _, f := range ev.Findings {
		if f.InKEV {
			kev++
		}
		if f.Malicious {
			mal++
		}
	}
	r.section(fmt.Sprintf("*Open by severity*\n%s\n:fire: Known exploited (KEV) *%d* · :skull: Malicious *%d*",
		strings.Join(parts, "   "), kev, mal))
	r.body(ev.Body)

	top := deps
	if len(top) == 0 && ev.Diff != nil {
		top, _ = splitFindings(ev.Diff.New)
	}
	r.findingList("*Top findings*", top)
	r.runtimeList("*End-of-life runtimes*", runtimes)
	if len(run.ReposFailed) > 0 {
		lines := make([]string, 0, len(run.ReposFailed))
		for _, name := range slices.Sorted(slices.Values(run.ReposFailed)) {
			lines = append(lines, "• "+mrkdwn(name))
		}
		r.section(listText(":x: *Repos that failed to scan*", lines, 0))
	}
	var unhealthy []string
	for _, s := range slices.SortedFunc(slices.Values(run.Sources), func(a, b model.SourceHealth) int { return cmp.Compare(a.Name, b.Name) }) {
		if !s.Healthy {
			line := "• *" + mrkdwn(s.Name) + "*"
			if s.Error != "" {
				line += " — " + mrkdwn(s.Error)
			}
			unhealthy = append(unhealthy, line)
		}
	}
	if len(unhealthy) > 0 {
		r.section(listText(":warning: *Unhealthy sources* (results may be incomplete)", unhealthy, 0))
	}
}

func (r *renderer) findingAlert(ev model.NotificationEvent) {
	if ev.Type == model.EventFindingSLABreach {
		r.header(":alarm_clock:", ev.Title, "Finding past its SLA")
	} else {
		sev := ev.Severity
		if sev == "" && len(ev.Findings) > 0 {
			sev = sortFindings(ev.Findings)[0].Severity
		}
		r.header(severityEmoji(sev), ev.Title, "New finding")
	}
	r.body(ev.Body)
	deps, runtimes := splitFindings(ev.Findings)
	if len(deps) != 1 || len(runtimes) > 0 {
		r.findingList("*Findings*", deps)
		r.runtimeList("*Runtimes*", runtimes)
		return
	}
	f := ev.Findings[0]
	head := r.advisory(f.AdvisoryID)
	if f.Summary != "" {
		head += " — " + mrkdwn(f.Summary)
	}
	if b := badges(f); b != "" {
		head += "\n" + b
	}
	if head = strings.TrimPrefix(head, " — "); head != "" {
		r.section(head)
	}
	fields := []string{
		"*Repository*\n" + mrkdwn(f.Repo),
		"*Package*\n`" + code(f.Package.Name) + "`",
		"*Current → recommended*\n" + versions(f.Package.Version, f.RecommendedVersion),
		"*Upgrade*\n" + bumpLabel(f.Bump),
		"*Severity*\n" + severityLabel(f.Severity),
		"*Manifest*\n" + mrkdwn(f.ManifestPath),
	}
	if len(f.Aliases) > 0 {
		fields = append(fields, "*Aliases*\n"+mrkdwn(strings.Join(slices.Sorted(slices.Values(f.Aliases)), ", ")))
	}
	if !f.FirstSeen.IsZero() {
		fields = append(fields, "*Open since*\n"+f.FirstSeen.UTC().Format(time.DateOnly))
	}
	r.fields(fields...)
	if f.Advice != "" {
		r.section("*How to fix*\n```" + code(f.Advice) + "```")
	}
	if u := r.uiURL("findings", f.ID); u != "" && f.ID != "" {
		r.link("View in Heimdall", u)
	}
	if f.AdvisoryID != "" {
		r.link("Advisory "+f.AdvisoryID, osvURL(f.AdvisoryID))
	}
}

func (r *renderer) runtimeEOL(ev model.NotificationEvent) {
	r.header(":hourglass_flowing_sand:", ev.Title, "Runtime reaching end of life")
	r.body(ev.Body)
	deps, runtimes := splitFindings(ev.Findings)
	r.runtimeList("*Runtimes*", runtimes)
	r.findingList("*Findings*", deps)
}

func (r *renderer) agentMessage(ev model.NotificationEvent) {
	r.header(":robot_face:", ev.Title, "Message from an AI agent")
	unverified := 0
	for _, f := range ev.Findings {
		if !f.Verified {
			unverified++
		}
	}
	switch {
	case len(ev.Findings) == 0 || unverified > 0:
		msg := ":warning: *AI agent — unverified.* Posted by an AI agent; not confirmed by a trusted vulnerability source."
		if unverified > 0 {
			msg += fmt.Sprintf(" %d of %d findings are unverified.", unverified, len(ev.Findings))
		}
		r.section(msg)
	default:
		r.context(":robot_face: Posted by an AI agent. All findings are confirmed by a trusted source.")
	}
	r.body(ev.Body)
	deps, runtimes := splitFindings(ev.Findings)
	r.findingList("*Findings*", deps)
	r.runtimeList("*Runtimes*", runtimes)
}

// findingList renders up to MaxFindings findings, worst first.
func (r *renderer) findingList(title string, fs []model.Finding) {
	if len(fs) == 0 {
		return
	}
	sorted := sortFindings(fs)
	shown := sorted[:min(len(sorted), r.cfg.MaxFindings)]
	lines := make([]string, 0, len(shown))
	for _, f := range shown {
		lines = append(lines, r.findingLine(f))
	}
	r.section(listText(title, lines, len(sorted)-len(shown)))
}

func (r *renderer) runtimeList(title string, fs []model.Finding) {
	if len(fs) == 0 {
		return
	}
	sorted := slices.SortedFunc(slices.Values(fs), func(a, b model.Finding) int {
		return cmp.Or(
			cmp.Compare(supportRank(b.Runtime), supportRank(a.Runtime)),
			cmp.Compare(a.Repo, b.Repo),
			cmp.Compare(a.Runtime.Runtime.Name, b.Runtime.Runtime.Name),
			cmp.Compare(a.Runtime.Runtime.Origin, b.Runtime.Runtime.Origin),
		)
	})
	shown := sorted[:min(len(sorted), r.cfg.MaxFindings)]
	lines := make([]string, 0, len(shown))
	for _, f := range shown {
		rt := f.Runtime
		line := fmt.Sprintf("%s `%s %s` in %s", supportEmoji(rt.Status), code(rt.Runtime.Name), code(rt.Runtime.Version), mrkdwn(f.Repo))
		if rt.Runtime.Origin != "" {
			line += " (" + mrkdwn(rt.Runtime.Origin) + ")"
		}
		line += " — *" + supportLabel(rt.Status) + "*"
		if rt.EOLDate != nil {
			line += " " + rt.EOLDate.UTC().Format(time.DateOnly)
		}
		if rt.LatestCycle != "" {
			line += " → upgrade to " + mrkdwn(rt.LatestCycle)
		}
		lines = append(lines, line)
	}
	r.section(listText(title, lines, len(sorted)-len(shown)))
}

func (r *renderer) findingLine(f model.Finding) string {
	var sb strings.Builder
	sb.WriteString(severityEmoji(f.Severity) + " *" + string(orUnknown(f.Severity)) + "* ")
	if f.AdvisoryID != "" {
		sb.WriteString(r.advisory(f.AdvisoryID) + " · ")
	}
	sb.WriteString("`" + code(f.Package.Name) + "` " + versions(f.Package.Version, f.RecommendedVersion))
	if f.Bump != model.BumpNone && f.Bump != model.BumpNoFix {
		sb.WriteString(" (" + bumpLabel(f.Bump) + ")")
	}
	sb.WriteString(" · " + mrkdwn(f.Repo))
	if b := badges(f); b != "" {
		sb.WriteString(" " + b)
	}
	if u := r.uiURL("findings", f.ID); u != "" && f.ID != "" {
		sb.WriteString(" · " + slackLink(u, "details"))
	}
	return sb.String()
}

func (r *renderer) advisory(id string) string {
	if id == "" {
		return ""
	}
	return slackLink(osvURL(id), id)
}

// uiURL links into the web UI, or returns "" when ui_base_url is not set.
func (r *renderer) uiURL(kind, id string) string {
	if r.cfg.UIBaseURL == "" {
		return ""
	}
	return r.cfg.UIBaseURL + "/" + kind + "/" + url.PathEscape(id)
}

func (r *renderer) header(emoji, title, fallbackTitle string) {
	if title == "" {
		title = fallbackTitle
	}
	t := truncate(strings.TrimSpace(emoji+" "+title), maxHeader)
	r.blocks = append(r.blocks, block{Type: "header", Text: &textObj{Type: "plain_text", Text: t, Emoji: true}})
}

func (r *renderer) body(s string) {
	if s = strings.TrimSpace(s); s != "" {
		r.section(mrkdwn(s))
	}
}

func (r *renderer) section(s string) {
	r.blocks = append(r.blocks, block{Type: "section", Text: &textObj{Type: "mrkdwn", Text: truncate(s, maxText)}})
}

func (r *renderer) fields(fs ...string) {
	out := make([]textObj, 0, min(len(fs), maxFields))
	for _, f := range fs[:min(len(fs), maxFields)] {
		out = append(out, textObj{Type: "mrkdwn", Text: truncate(f, maxField)})
	}
	r.blocks = append(r.blocks, block{Type: "section", Fields: out})
}

func (r *renderer) context(s string) { r.blocks = append(r.blocks, contextBlock(s)) }

func contextBlock(s string) block {
	return block{Type: "context", Elements: []any{textObj{Type: "mrkdwn", Text: truncate(s, maxText)}}}
}

// link queues a link button; invalid or oversized URLs are dropped.
func (r *renderer) link(label, raw string) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || len(raw) > maxURL {
		return
	}
	r.links = append(r.links, link{label: label, url: raw})
}

func (r *renderer) actions() {
	if len(r.links) == 0 {
		return
	}
	els := make([]any, 0, min(len(r.links), maxButtons))
	for i, l := range r.links[:min(len(r.links), maxButtons)] {
		els = append(els, button{Type: "button", Text: textObj{Type: "plain_text", Text: truncate(l.label, maxButtonLabel), Emoji: true},
			URL: l.url, ActionID: fmt.Sprintf("link-%d", i)})
	}
	r.blocks = append(r.blocks, block{Type: "actions", Elements: els})
}

// listText joins lines under title, keeping the result within maxText and
// ending with "…and N more" when lines were dropped or more were not given.
func listText(title string, lines []string, more int) string {
	const reserve = 32 // room for the "…and N more" line
	var sb strings.Builder
	sb.WriteString(title)
	shown := 0
	for _, l := range lines {
		l = truncate(l, maxText-reserve-len(title)-1)
		if sb.Len()+1+len(l) > maxText-reserve {
			break
		}
		sb.WriteString("\n" + l)
		shown++
	}
	if omitted := len(lines) - shown + more; omitted > 0 {
		fmt.Fprintf(&sb, "\n…and %d more", omitted)
	}
	return sb.String()
}

func fallback(ev model.NotificationEvent) string {
	title := ev.Title
	if title == "" {
		title = "Heimdall " + string(ev.Type)
	}
	if ev.Severity != "" {
		title = "[" + string(ev.Severity) + "] " + title
	}
	if ev.Type == model.EventAgentMessage {
		title = "[AI agent] " + title
	}
	return truncate(title, maxFallback)
}

// splitFindings separates dependency-like findings from runtime ones.
func splitFindings(fs []model.Finding) (deps, runtimes []model.Finding) {
	for _, f := range fs {
		if f.Kind == model.KindRuntime && f.Runtime != nil {
			runtimes = append(runtimes, f)
		} else {
			deps = append(deps, f)
		}
	}
	return deps, runtimes
}

func sortFindings(fs []model.Finding) []model.Finding {
	return slices.SortedFunc(slices.Values(fs), func(a, b model.Finding) int {
		return cmp.Or(
			cmp.Compare(b.Severity.Rank(), a.Severity.Rank()),
			cmp.Compare(boolRank(b.InKEV), boolRank(a.InKEV)),
			cmp.Compare(boolRank(b.Malicious), boolRank(a.Malicious)),
			cmp.Compare(b.Priority, a.Priority),
			cmp.Compare(a.Repo, b.Repo),
			cmp.Compare(a.Package.Name, b.Package.Name),
			cmp.Compare(a.AdvisoryID, b.AdvisoryID),
			cmp.Compare(a.ID, b.ID),
		)
	})
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

var severities = []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityUnknown}

func orUnknown(s model.Severity) model.Severity {
	if s == "" {
		return model.SeverityUnknown
	}
	return s
}

func severityEmoji(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return ":red_circle:"
	case model.SeverityHigh:
		return ":large_orange_circle:"
	case model.SeverityMedium:
		return ":large_yellow_circle:"
	case model.SeverityLow:
		return ":large_blue_circle:"
	}
	return ":white_circle:"
}

func severityLabel(s model.Severity) string {
	s = orUnknown(s)
	return severityEmoji(s) + " " + string(s)
}

func badges(f model.Finding) string {
	var b []string
	if f.InKEV {
		b = append(b, ":fire: *KEV*")
	}
	if f.Malicious {
		b = append(b, ":skull: *malicious package*")
	}
	if !f.Verified {
		b = append(b, "_unverified_")
	}
	return strings.Join(b, " ")
}

func bumpLabel(b model.BumpType) string {
	switch b {
	case model.BumpMajor:
		return ":warning: *major* (breaking)"
	case model.BumpNone:
		return "—"
	case model.BumpNoFix:
		return "no fix available"
	}
	return mrkdwn(string(b))
}

func versions(current, recommended string) string {
	if current == "" {
		current = "?"
	}
	if recommended == "" {
		return mrkdwn(current) + " → no fix"
	}
	return mrkdwn(current) + " → *" + mrkdwn(recommended) + "*"
}

func runStatus(s model.RunStatus) string {
	switch s {
	case model.RunSucceeded:
		return ":white_check_mark: succeeded"
	case model.RunPartial:
		return ":warning: partial"
	case model.RunFailed:
		return ":x: failed"
	case model.RunRunning:
		return ":hourglass: running"
	}
	return "unknown"
}

func supportRank(rt *model.RuntimeStatus) int {
	switch rt.Status {
	case model.SupportEOL:
		return 3
	case model.SupportEOLSoon:
		return 2
	case model.SupportSecurityOnly:
		return 1
	}
	return 0
}

func supportEmoji(s model.SupportStatus) string {
	switch s {
	case model.SupportEOL:
		return ":red_circle:"
	case model.SupportEOLSoon:
		return ":large_orange_circle:"
	case model.SupportSecurityOnly:
		return ":large_yellow_circle:"
	case model.SupportSupported:
		return ":large_green_circle:"
	}
	return ":white_circle:"
}

func supportLabel(s model.SupportStatus) string {
	switch s {
	case model.SupportEOL:
		return "EOL"
	case model.SupportEOLSoon:
		return "EOL soon"
	case "":
		return "unknown"
	}
	return mrkdwn(string(s))
}

func osvURL(id string) string { return "https://osv.dev/vulnerability/" + url.PathEscape(id) }

// slackLink builds <url|label>; label must not contain '|' or '>'.
func slackLink(u, label string) string {
	return "<" + u + "|" + strings.ReplaceAll(mrkdwn(label), "|", "¦") + ">"
}

func linkLabel(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return "Open " + u.Host
	}
	return "Open link"
}

// mrkdwn escapes the three characters Slack treats as control sequences.
var mrkdwnEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func mrkdwn(s string) string { return mrkdwnEscaper.Replace(s) }

// code escapes s for use inside a `code` span.
func code(s string) string { return strings.ReplaceAll(mrkdwn(s), "`", "'") }

// truncate shortens s to at most n bytes (never splitting a rune), ending with "…".
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const ell = "…"
	cut := n - len(ell)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + ell
}
