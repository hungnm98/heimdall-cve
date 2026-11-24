package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

// DefaultNotifyDailyLimit applies when mcp.notify_daily_limit is not positive.
const DefaultNotifyDailyLimit = 20

const (
	maxMessageTitle = 200
	maxMessageBody  = 4000
	maxMessageRefs  = 20
)

// messengerSvc sends agent messages. All its state lives in the store's
// notification keys (Store.MarkNotified), so limits hold across processes:
//   - dedup: key "agent.message:<sha256(title|body|refs)>"; marked before
//     delivery (at most once), so an identical message is never resent, even
//     after a delivery failure;
//   - daily limit: the n-th message of a UTC day claims the slot key
//     "agent.message.count:<YYYY-MM-DD>:<n>" (n = 1..limit, first free slot
//     wins). When every slot is taken the call fails with ErrRateLimited.
//     The slot is claimed before the dedup check, so duplicates count too.
type messengerSvc struct{ *base }

func (s *messengerSvc) NotifyUser(ctx context.Context, actor Actor, in MessageInput) (bool, error) {
	if s.d.Config == nil || !s.d.Config.MCP.AllowNotify {
		return false, fmt.Errorf("notify (mcp.allow_notify): %w", ErrForbidden)
	}
	fe := fieldErrors{}
	title, body := strings.TrimSpace(in.Title), strings.TrimSpace(in.Body)
	if n := len([]rune(title)); n == 0 || n > maxMessageTitle {
		fe.add("title", fmt.Sprintf("1 to %d characters", maxMessageTitle))
	}
	if n := len([]rune(body)); n == 0 || n > maxMessageBody {
		fe.add("body", fmt.Sprintf("1 to %d characters", maxMessageBody))
	}
	sev := model.SeverityUnknown
	if strings.TrimSpace(string(in.Severity)) != "" {
		if sev = model.ParseSeverity(string(in.Severity)); sev == model.SeverityUnknown && !strings.EqualFold(strings.TrimSpace(string(in.Severity)), "unknown") {
			fe.add("severity", "must be CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN")
		}
	}
	var refs []string
	for _, r := range in.Refs {
		if r = strings.TrimSpace(r); r == "" {
			continue
		}
		if len(r) > 500 {
			fe.add("refs", "each ref at most 500 characters")
			continue
		}
		refs = append(refs, r)
	}
	if len(refs) > maxMessageRefs {
		fe.add("refs", fmt.Sprintf("at most %d refs", maxMessageRefs))
	}
	if err := fe.err(); err != nil {
		return false, err
	}
	if len(s.d.Notifiers) == 0 {
		return false, fmt.Errorf("no notifier is configured: %w", ErrUnavailable)
	}

	now := s.now()
	limit := s.d.Config.MCP.NotifyDailyLimit
	if limit <= 0 {
		limit = DefaultNotifyDailyLimit
	}
	day := now.Format("2006-01-02")
	slot := 0
	for n := 1; n <= limit; n++ {
		ok, err := s.d.Store.MarkNotified(ctx, fmt.Sprintf("agent.message.count:%s:%d", day, n), now)
		if err != nil {
			return false, err
		}
		if ok {
			slot = n
			break
		}
	}
	details := map[string]any{"title": title, "severity": string(sev), "refs": refs}
	if slot == 0 {
		details["result"] = "rate_limited"
		s.audit(ctx, actor, "agent.notify", "message", "", details)
		return false, fmt.Errorf("daily limit of %d agent messages reached for %s (UTC): %w", limit, day, ErrRateLimited)
	}

	h := sha256.Sum256([]byte(title + "|" + body + "|" + strings.Join(refs, "\n")))
	hash := hex.EncodeToString(h[:])
	first, err := s.d.Store.MarkNotified(ctx, "agent.message:"+hash, now)
	if err != nil {
		return false, err
	}
	if !first {
		details["result"] = "duplicate"
		s.audit(ctx, actor, "agent.notify", "message", hash[:16], details)
		return false, nil
	}

	ev := s.event(ctx, title, body, sev, refs)
	var errs []error
	delivered := 0
	for _, n := range s.d.Notifiers {
		if err := n.Notify(ctx, ev); err != nil {
			s.d.Logger.Warn("agent message delivery failed", "notifier", n.Name(), "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", n.Name(), err))
			continue
		}
		delivered++
	}
	details["result"], details["delivered"], details["daily_count"] = "sent", delivered, slot
	if delivered == 0 {
		details["result"] = "failed"
	}
	s.audit(ctx, actor, "agent.notify", "message", hash[:16], details)
	if delivered == 0 {
		return false, &UpstreamError{Err: fmt.Errorf("no notifier delivered the message (it will not be resent; change the title to retry): %w", errors.Join(errs...))}
	}
	return true, nil
}

// event builds the notification: URL refs become links, refs naming a
// finding attach it, other refs (advisory ids...) are listed in the body.
func (s *messengerSvc) event(ctx context.Context, title, body string, sev model.Severity, refs []string) model.NotificationEvent {
	ev := model.NotificationEvent{Type: model.EventAgentMessage, Title: title, Severity: sev}
	var other []string
	for _, r := range refs {
		if isWebURL(r, false) {
			ev.Links = append(ev.Links, r)
			continue
		}
		if f, err := s.d.Store.GetFinding(ctx, r); err == nil {
			ev.Findings = append(ev.Findings, *f)
			continue
		}
		other = append(other, r)
	}
	if len(other) > 0 {
		body += "\n\nRefs: " + strings.Join(other, ", ")
	}
	ev.Body = body
	return ev
}
