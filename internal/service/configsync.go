package service

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sort"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// SyncConfig mirrors the config file's auth profiles and targets into the
// catalog with origin "config" (read-only in the UI): missing ones are
// created, changed ones updated, and config targets no longer in the file
// deleted. A UI profile with the same name as a config profile is left alone
// and reported. Config profiles are never deleted here (a UI target may use one).
// Run it at startup, before serving.
func SyncConfig(ctx context.Context, d Deps) error {
	if d.Config == nil || d.Catalog == nil {
		return nil
	}
	var errs []error
	names := make([]string, 0, len(d.Config.AuthProfiles))
	for n := range d.Config.AuthProfiles {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		cp := d.Config.AuthProfiles[name]
		p, err := d.Catalog.GetAuthProfile(ctx, name)
		switch {
		case errors.Is(err, ErrNotFound):
			p = &model.AuthProfile{Name: name, Origin: model.OriginConfig}
		case err != nil:
			errs = append(errs, err)
			continue
		case p.Origin != model.OriginConfig:
			errs = append(errs, fmt.Errorf("auth profile %q exists in the UI and in the config file; the UI one is kept", name))
			continue
		}
		p.Type, p.Options = cp.Type, maps.Clone(map[string]any(cp.Options))
		if err := d.Catalog.SaveAuthProfile(ctx, p); err != nil {
			errs = append(errs, fmt.Errorf("auth profile %q: %w", name, err))
		}
	}

	existing, err := d.Catalog.ListTargets(ctx, store.TargetFilter{Origin: model.OriginConfig})
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	byKey := map[string]model.TargetSpec{}
	for _, t := range existing {
		byKey[configTargetKey(t.Target)] = t
	}
	for _, t := range d.Config.ModelTargets() {
		key := configTargetKey(t)
		spec, ok := byKey[key]
		delete(byKey, key)
		if !ok {
			spec = model.TargetSpec{Origin: model.OriginConfig, Enabled: true}
		}
		spec.Target = t
		if err := d.Catalog.SaveTarget(ctx, &spec); err != nil {
			errs = append(errs, fmt.Errorf("target %s: %w", t, err))
		}
	}
	for _, stale := range byKey {
		if err := d.Catalog.DeleteTarget(ctx, stale.ID); err != nil {
			errs = append(errs, fmt.Errorf("remove target %s: %w", stale.Target, err))
		}
	}
	err = d.Catalog.AppendAudit(ctx, &model.AuditEntry{
		Actor: "config", Action: "config.sync", ObjectType: "config",
		Details: map[string]any{"auth_profiles": len(names), "targets": len(d.Config.Targets), "removed_targets": len(byKey)},
	})
	return errors.Join(append(errs, err)...)
}

func configTargetKey(t model.Target) string {
	return t.Provider + "|" + t.BaseURL + "|" + t.String()
}
