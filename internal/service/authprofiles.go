package service

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"sort"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

var profileNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// defaultSecretKind is the secret a profile type carries.
var defaultSecretKind = map[string]string{"token": "token", "app": "private_key", "ssh": "ssh_key"}

// secretOptionKeys may never appear in Options: values belong in Secret.
var secretOptionKeys = map[string]bool{
	"token": true, "private_key": true, "ssh_key": true, "key": true,
	"password": true, "passphrase": true, "secret": true,
}

// IsSecretRefOption reports whether an option key is a "<kind>_ref" set by
// the service to point at a sealed secret. Such keys are managed by the
// service: they are rejected in input and hidden from API output.
func IsSecretRefOption(key string) bool { return strings.HasSuffix(key, "_ref") }

type authProfilesSvc struct{ *base }

func (s *authProfilesSvc) SecretsEnabled() bool { return s.d.Keys != nil }

func (s *authProfilesSvc) List(ctx context.Context) ([]model.AuthProfile, error) {
	return s.d.Catalog.ListAuthProfiles(ctx)
}

func (s *authProfilesSvc) Create(ctx context.Context, actor Actor, in AuthProfileInput) (*model.AuthProfile, error) {
	kind, err := s.validate(in)
	if err != nil {
		return nil, err
	}
	if _, err := s.d.Catalog.GetAuthProfile(ctx, in.Name); err == nil {
		return nil, fmt.Errorf("auth profile %q already exists: %w", in.Name, ErrConflict)
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	p := &model.AuthProfile{Name: in.Name, Type: in.Type, Options: cleanOptions(in.Options), Origin: model.OriginUI}
	var rec *store.SecretRecord
	if in.Secret != nil {
		if rec, err = s.seal(ctx, nil, kind, *in.Secret); err != nil {
			return nil, err
		}
		attachSecret(p, rec)
	}
	if err := s.d.Catalog.SaveAuthProfile(ctx, p); err != nil {
		if rec != nil {
			s.dropSecret(ctx, rec.ID)
		}
		return nil, err
	}
	s.audit(ctx, actor, "auth_profile.create", "auth_profile", p.Name, profileDetails(p, in.Secret != nil))
	return p, nil
}

func (s *authProfilesSvc) Update(ctx context.Context, actor Actor, name string, in AuthProfileInput) (*model.AuthProfile, error) {
	p, err := s.d.Catalog.GetAuthProfile(ctx, name)
	if err != nil {
		return nil, err
	}
	if p.Origin == model.OriginConfig {
		return nil, ErrReadOnly
	}
	kind, err := s.validate(in)
	if err != nil {
		return nil, err
	}
	if in.Secret == nil && p.SecretID != nil && in.Type != p.Type {
		// The stored secret is of the old type's kind (e.g. a token for an app profile).
		return nil, invalid("secret", "a new secret is required when changing the profile type")
	}
	if in.Name != name { // check before touching the secret
		if _, err := s.d.Catalog.GetAuthProfile(ctx, in.Name); err == nil {
			return nil, fmt.Errorf("auth profile %q already exists: %w", in.Name, ErrConflict)
		} else if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}
	refs := map[string]any{} // keep the current secret reference unless replaced
	for k, v := range p.Options {
		if IsSecretRefOption(k) {
			refs[k] = v
		}
	}
	p.Name, p.Type, p.Options = in.Name, in.Type, cleanOptions(in.Options)
	if in.Secret != nil {
		rec, err := s.seal(ctx, p.SecretID, kind, *in.Secret)
		if err != nil {
			return nil, err
		}
		attachSecret(p, rec)
	} else if len(refs) > 0 {
		if p.Options == nil {
			p.Options = map[string]any{}
		}
		maps.Copy(p.Options, refs)
	}
	if err := s.d.Catalog.SaveAuthProfile(ctx, p); err != nil {
		return nil, err
	}
	d := profileDetails(p, in.Secret != nil)
	if name != p.Name {
		d["renamed_from"] = name
	}
	s.audit(ctx, actor, "auth_profile.update", "auth_profile", p.Name, d)
	return p, nil
}

func (s *authProfilesSvc) Delete(ctx context.Context, actor Actor, name string) error {
	p, err := s.d.Catalog.GetAuthProfile(ctx, name)
	if err != nil {
		return err
	}
	if p.Origin == model.OriginConfig {
		return ErrReadOnly
	}
	if err := s.d.Catalog.DeleteAuthProfile(ctx, name); err != nil {
		return err
	}
	if p.SecretID != nil {
		s.dropSecret(ctx, *p.SecretID)
	}
	s.audit(ctx, actor, "auth_profile.delete", "auth_profile", name, map[string]any{"type": p.Type})
	return nil
}

func (s *authProfilesSvc) Test(ctx context.Context, name string) (*ConnectionTest, error) {
	p, err := s.d.Catalog.GetAuthProfile(ctx, name)
	if err != nil {
		return nil, err
	}
	if s.d.ProviderFor == nil {
		return nil, ErrUnavailable
	}
	// Test against a target that uses the profile, so listing is meaningful.
	targets, err := s.d.Catalog.ListTargets(ctx, store.TargetFilter{})
	if err != nil {
		return nil, err
	}
	var target *model.Target
	for i := range targets {
		if targets[i].Auth == p.Name || targets[i].ListAuth == p.Name {
			target = &targets[i].Target
			break
		}
	}
	if target == nil {
		t := model.Target{Provider: "github", Auth: p.Name, ListAuth: p.Name}
		if v, ok := p.Options["base_url"].(string); ok {
			t.BaseURL = v
		}
		if _, err := s.d.ProviderFor(ctx, t); err != nil {
			return &ConnectionTest{OK: false, Message: "credentials cannot be loaded: " + err.Error()}, nil
		}
		return &ConnectionTest{OK: true, Message: "credentials loaded; no target uses this profile yet, so listing was not tried"}, nil
	}
	prov, err := s.d.ProviderFor(ctx, *target)
	if err != nil {
		return &ConnectionTest{OK: false, Message: "credentials cannot be loaded: " + err.Error()}, nil
	}
	repos, err := prov.ListRepos(ctx, *target)
	if err != nil {
		return &ConnectionTest{OK: false, Message: fmt.Sprintf("listing %s failed: %v", target, err)}, nil
	}
	return &ConnectionTest{OK: true, Message: fmt.Sprintf("%d repos visible for %s", len(repos), target)}, nil
}

// validate checks in and returns the secret kind to use.
func (s *authProfilesSvc) validate(in AuthProfileInput) (string, error) {
	fe := fieldErrors{}
	if !profileNamePattern.MatchString(in.Name) {
		fe.add("name", "must match ^[a-z0-9][a-z0-9_-]{0,62}$")
	}
	kind := in.SecretKind
	if def, ok := defaultSecretKind[in.Type]; !ok {
		fe.add("type", "must be token, app or ssh")
	} else if kind == "" {
		kind = def
	}
	if in.SecretKind != "" && !map[string]bool{"token": true, "private_key": true, "ssh_key": true}[in.SecretKind] {
		fe.add("secret_kind", "must be token, private_key or ssh_key")
	}
	for k := range in.Options {
		if secretOptionKeys[k] || IsSecretRefOption(k) {
			fe.add("options", fmt.Sprintf("option %q is not allowed: send secret values in `secret`", k))
		}
	}
	if in.Secret != nil && strings.TrimSpace(*in.Secret) == "" {
		fe.add("secret", "must not be empty; omit it to keep the current secret")
	}
	if err := fe.err(); err != nil {
		return "", err
	}
	if in.Secret != nil && s.d.Keys == nil {
		return "", fmt.Errorf("secret storage needs a master key (secrets.master_key_env): %w", ErrUnavailable)
	}
	return kind, nil
}

// seal stores value under id (nil = new record) following the SecretAAD scheme.
func (s *authProfilesSvc) seal(ctx context.Context, id *int64, kind, value string) (*store.SecretRecord, error) {
	rec := &store.SecretRecord{Kind: kind, Fingerprint: secret.Fingerprint(value)}
	fresh := id == nil
	if fresh {
		// Reserve an ID: the AAD binds the sealed value to it.
		rec.Sealed = secret.Sealed{KEKID: s.d.Keys.CurrentID(), WrappedDEK: []byte{}, Ciphertext: []byte{}}
		if err := s.d.Catalog.SaveSecret(ctx, rec); err != nil {
			return nil, err
		}
	} else {
		rec.ID = *id
	}
	sealed, err := s.d.Keys.Seal([]byte(value), SecretAAD(rec.ID))
	if err == nil {
		rec.Sealed = sealed
		err = s.d.Catalog.SaveSecret(ctx, rec)
	}
	if err != nil {
		if fresh {
			s.dropSecret(ctx, rec.ID)
		}
		return nil, fmt.Errorf("store secret: %w", err)
	}
	return rec, nil
}

func (s *authProfilesSvc) dropSecret(ctx context.Context, id int64) {
	if err := s.d.Catalog.DeleteSecret(ctx, id); ignoreNotFound(err) != nil {
		s.d.Logger.Warn("delete secret failed", "secret_id", id, "err", err)
	}
}

func attachSecret(p *model.AuthProfile, rec *store.SecretRecord) {
	id := rec.ID
	p.SecretID, p.SecretFingerprint = &id, rec.Fingerprint
	if p.Options == nil {
		p.Options = map[string]any{}
	}
	for k := range p.Options {
		if IsSecretRefOption(k) {
			delete(p.Options, k)
		}
	}
	p.Options[rec.Kind+"_ref"] = itoa(id)
}

// cleanOptions copies opts without secret references (managed by the service).
func cleanOptions(opts map[string]any) map[string]any {
	if len(opts) == 0 {
		return nil
	}
	out := make(map[string]any, len(opts))
	for k, v := range opts {
		if !IsSecretRefOption(k) {
			out[k] = v
		}
	}
	return out
}

func profileDetails(p *model.AuthProfile, secretChanged bool) map[string]any {
	keys := make([]string, 0, len(p.Options))
	for k := range p.Options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	d := map[string]any{"type": p.Type, "option_keys": keys, "secret_changed": secretChanged}
	if p.SecretFingerprint != "" {
		d["secret_fingerprint"] = p.SecretFingerprint
	}
	return d
}
