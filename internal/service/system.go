package service

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/notify"
)

type systemSvc struct{ *base }

func (s *systemSvc) Sources(ctx context.Context) ([]SourceStatus, error) {
	last, err := s.d.Store.LatestRun(ctx, 0)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	names := make([]string, 0, len(s.d.SourceKinds))
	for n := range s.d.SourceKinds {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]SourceStatus, 0, len(names))
	for _, n := range names {
		st := SourceStatus{Name: n, Kinds: append([]string{}, s.d.SourceKinds[n]...), Healthy: true}
		if last != nil {
			for _, h := range last.Sources {
				if h.Name == n {
					at := last.FinishedAt
					st.Healthy, st.Error, st.LastSeen = h.Healthy, h.Error, &at
				}
			}
		}
		out = append(out, st)
	}
	return out, nil
}

func (s *systemSvc) Notifiers(context.Context) ([]NotifierStatus, error) {
	out := make([]NotifierStatus, 0, len(s.d.Notifiers))
	for _, n := range s.d.Notifiers {
		typ := n.Name()
		if s.d.Config != nil {
			if p, ok := s.d.Config.Notify[n.Name()]; ok {
				typ = p.TypeOr(n.Name())
			}
		}
		out = append(out, NotifierStatus{Name: n.Name(), Type: typ})
	}
	return out, nil
}

func (s *systemSvc) TestNotifier(ctx context.Context, actor Actor, name string) error {
	var target notify.Notifier
	for _, n := range s.d.Notifiers {
		if n.Name() == name {
			target = n
		}
	}
	if target == nil {
		return fmt.Errorf("notifier %q: %w", name, ErrNotFound)
	}
	err := target.Notify(ctx, model.NotificationEvent{
		Type:  model.EventScanSummary,
		Title: "Heimdall test message",
		Body:  "This is a test notification sent from Heimdall by " + actorName(actor) + ".",
	})
	s.audit(ctx, actor, "notifier.test", "notifier", name, map[string]any{"ok": err == nil})
	if err != nil {
		return &UpstreamError{Err: err}
	}
	return nil
}

func (s *systemSvc) Audit(ctx context.Context, beforeID int64, limit int) (*Page[model.AuditEntry], error) {
	limit = ClampLimit(limit)
	items, err := s.d.Catalog.ListAudit(ctx, beforeID, limit+1)
	if err != nil {
		return nil, err
	}
	page := &Page[model.AuditEntry]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = itoa(items[limit-1].ID)
	}
	return page, nil
}
