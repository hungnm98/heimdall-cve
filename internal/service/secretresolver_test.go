package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strconv"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/hungnm98/heimdall-cve/internal/store/memstore"
)

func newMasterKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// seal stores value the way the AuthProfiles service does: insert to get the
// id, then seal with that id's AAD.
func seal(t *testing.T, cat store.Catalog, keys *secret.KeyRing, value string) int64 {
	t.Helper()
	ctx := context.Background()
	rec := &store.SecretRecord{Kind: "token", Fingerprint: secret.Fingerprint(value)}
	if err := cat.SaveSecret(ctx, rec); err != nil {
		t.Fatal(err)
	}
	s, err := keys.Seal([]byte(value), SecretAAD(rec.ID))
	if err != nil {
		t.Fatal(err)
	}
	rec.Sealed = s
	if err := cat.SaveSecret(ctx, rec); err != nil {
		t.Fatal(err)
	}
	return rec.ID
}

func TestSecretResolver(t *testing.T) {
	ctx := context.Background()
	cat := memstore.New()
	keys, err := secret.NewKeyRing(newMasterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	id := seal(t, cat, keys, "ghp_value")
	r := NewSecretResolver(cat, keys)
	if v, err := r.Resolve(ctx, secret.Ref{ID: strconv.FormatInt(id, 10)}); err != nil || v != "ghp_value" {
		t.Fatalf("Resolve = %q, %v", v, err)
	}
	if v, err := (secret.Chain{Store: r}).Resolve(ctx, secret.Ref{ID: strconv.FormatInt(id, 10)}); err != nil || v != "ghp_value" {
		t.Fatalf("Chain.Resolve = %q, %v", v, err)
	}
	if _, err := r.Resolve(ctx, secret.Ref{Env: "X"}); !errors.Is(err, secret.ErrUnsupported) {
		t.Fatalf("env ref: %v", err)
	}
	if _, err := r.Resolve(ctx, secret.Ref{ID: "abc"}); err == nil {
		t.Fatal("non-numeric id must fail")
	}
	if _, err := r.Resolve(ctx, secret.Ref{ID: "999"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing secret: %v", err)
	}
	// A sealed value moved to another row must not open (AAD = row id).
	other := &store.SecretRecord{Kind: "token"}
	rec, _ := cat.GetSecret(ctx, id)
	other.Sealed = rec.Sealed
	if err := cat.SaveSecret(ctx, other); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(ctx, secret.Ref{ID: strconv.FormatInt(other.ID, 10)}); !errors.Is(err, secret.ErrDecrypt) {
		t.Fatalf("copied ciphertext: %v", err)
	}
	if _, err := NewSecretResolver(cat, nil).Resolve(ctx, secret.Ref{ID: "1"}); err == nil {
		t.Fatal("no master key must fail")
	}
}

func TestRotateKEK(t *testing.T) {
	ctx := context.Background()
	cat := memstore.New()
	oldKey, newKey := newMasterKey(t), newMasterKey(t)
	oldRing, _ := secret.NewKeyRing(oldKey)
	a := seal(t, cat, oldRing, "value-a")
	b := seal(t, cat, oldRing, "value-b")

	ring, err := secret.NewKeyRing(newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	n, err := RotateKEK(ctx, cat, ring)
	if err != nil || n != 2 {
		t.Fatalf("RotateKEK = %d, %v", n, err)
	}
	onlyNew, _ := secret.NewKeyRing(newKey)
	r := NewSecretResolver(cat, onlyNew)
	for id, want := range map[int64]string{a: "value-a", b: "value-b"} {
		if v, err := r.Resolve(ctx, secret.Ref{ID: strconv.FormatInt(id, 10)}); err != nil || v != want {
			t.Fatalf("after rotation secret %d = %q, %v", id, v, err)
		}
		if rec, _ := cat.GetSecret(ctx, id); rec.RotatedAt == nil || rec.Sealed.KEKID != onlyNew.CurrentID() {
			t.Fatalf("secret %d not marked rotated: %+v", id, rec)
		}
	}
	if n, err := RotateKEK(ctx, cat, ring); err != nil || n != 0 {
		t.Fatalf("second rotation = %d, %v (want nothing to do)", n, err)
	}

	// A secret wrapped by a key that is not loaded is reported, others still rotate.
	stranger, _ := secret.NewKeyRing(newMasterKey(t))
	seal(t, cat, stranger, "lost")
	seal(t, cat, oldRing, "value-c")
	n, err = RotateKEK(ctx, cat, ring)
	if n != 1 || !errors.Is(err, secret.ErrDecrypt) {
		t.Fatalf("partial rotation = %d, %v", n, err)
	}
}
