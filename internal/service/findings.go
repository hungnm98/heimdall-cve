package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// MaxSuppression is the longest a finding can be suppressed.
const MaxSuppression = 365 * 24 * time.Hour

type findingsSvc struct{ *base }

func (s *findingsSvc) List(ctx context.Context, f store.FindingFilter) (*Page[model.Finding], error) {
	if f.After != "" {
		if _, _, _, err := store.ParseFindingCursor(f.After); err != nil {
			return nil, invalid("cursor", "invalid cursor")
		}
	}
	limit := ClampLimit(f.Limit)
	f.Limit = limit + 1
	items, err := s.d.Store.ListFindings(ctx, f)
	if err != nil {
		return nil, err
	}
	page := &Page[model.Finding]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = store.FindingCursor(items[limit-1])
	}
	return page, nil
}

func (s *findingsSvc) Get(ctx context.Context, id string) (*FindingDetail, error) {
	f, err := s.d.Store.GetFinding(ctx, id)
	if err != nil {
		return nil, err
	}
	d := &FindingDetail{Finding: *f}
	sp, err := s.d.Catalog.GetSuppression(ctx, id)
	if err == nil {
		d.Suppression = sp
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return d, nil
}

func (s *findingsSvc) Suppress(ctx context.Context, actor Actor, id, reason string, expiresAt time.Time) error {
	reason = strings.TrimSpace(reason)
	now := s.now()
	fe := fieldErrors{}
	if len([]rune(reason)) < 3 || len([]rune(reason)) > 1000 {
		fe.add("reason", "a reason of 3 to 1000 characters is required")
	}
	if !expiresAt.After(now) || expiresAt.After(now.Add(MaxSuppression)) {
		fe.add("expires_at", "must be in the future and at most 1 year ahead")
	}
	if err := fe.err(); err != nil {
		return err
	}
	sp := &model.Suppression{FindingID: id, Reason: reason, ExpiresAt: expiresAt.UTC(), Actor: actorName(actor), CreatedAt: now}
	if err := s.d.Catalog.SaveSuppression(ctx, sp); err != nil {
		return err
	}
	s.audit(ctx, actor, "finding.suppress", "finding", id, map[string]any{"reason": reason, "expires_at": sp.ExpiresAt.Format(time.RFC3339)})
	return nil
}

func (s *findingsSvc) Unsuppress(ctx context.Context, actor Actor, id string) error {
	if err := s.d.Catalog.DeleteSuppression(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, actor, "finding.unsuppress", "finding", id, nil)
	return nil
}

// eachFinding walks every finding matching f page by page (bounded memory).
func eachFinding(ctx context.Context, st store.Store, f store.FindingFilter, fn func(model.Finding)) error {
	const pageSize = 1000
	f.Limit, f.After = pageSize, ""
	for {
		items, err := st.ListFindings(ctx, f)
		if err != nil {
			return err
		}
		for _, it := range items {
			fn(it)
		}
		if len(items) < pageSize {
			return nil
		}
		f.After = store.FindingCursor(items[len(items)-1])
	}
}
