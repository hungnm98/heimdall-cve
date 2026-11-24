package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

type runsSvc struct{ *base }

// List pages runs newest first. store.Store.ListRuns has no keyset cursor, so
// runs before beforeID are filtered here; runs are few (one per scan), so this
// stays cheap, but a ListRuns(before, limit) store method would remove the scan.
func (s *runsSvc) List(ctx context.Context, beforeID int64, limit int) (*Page[model.ScanRun], error) {
	limit = ClampLimit(limit)
	fetch := limit + 1
	if beforeID > 0 {
		fetch = 0 // all: the cursor cannot be pushed down
	}
	runs, err := s.d.Store.ListRuns(ctx, fetch)
	if err != nil {
		return nil, err
	}
	items := make([]model.ScanRun, 0, limit)
	page := &Page[model.ScanRun]{}
	for _, r := range runs {
		if beforeID > 0 && r.ID >= beforeID {
			continue
		}
		if len(items) == limit {
			page.NextCursor = itoa(items[limit-1].ID)
			break
		}
		items = append(items, r)
	}
	page.Items = items
	return page, nil
}

func (s *runsSvc) Get(ctx context.Context, id int64) (*model.ScanRun, error) {
	return s.d.Store.GetRun(ctx, id)
}

func (s *runsSvc) Diff(ctx context.Context, id, against int64) (*model.Diff, error) {
	if _, err := s.d.Store.GetRun(ctx, id); err != nil {
		return nil, err
	}
	if against == 0 {
		prev, err := s.d.Store.LatestRun(ctx, id)
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("run %d has no earlier finished run to compare with: %w", id, ErrNotFound)
		}
		if err != nil {
			return nil, err
		}
		against = prev.ID
	}
	return s.d.Store.DiffRuns(ctx, against, id)
}
