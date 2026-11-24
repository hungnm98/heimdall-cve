package secret

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func newKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestSealOpen(t *testing.T) {
	kr, err := NewKeyRing(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	s, err := kr.Seal([]byte("ghp_supersecret"), []byte("secret-1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(s.Ciphertext, []byte("supersecret")) {
		t.Fatal("ciphertext contains plaintext")
	}
	v, err := kr.Open(s, []byte("secret-1"))
	if err != nil || string(v) != "ghp_supersecret" {
		t.Fatalf("Open = %q, %v", v, err)
	}
	if _, err := kr.Open(s, []byte("secret-2")); !errors.Is(err, ErrDecrypt) {
		t.Fatal("a sealed value must not open under another record's aad")
	}
	s.Ciphertext[len(s.Ciphertext)-1] ^= 1
	if _, err := kr.Open(s, []byte("secret-1")); !errors.Is(err, ErrDecrypt) {
		t.Fatal("tampered ciphertext must fail")
	}
	other, _ := NewKeyRing(newKey(t))
	if _, err := other.Open(s, []byte("secret-1")); !errors.Is(err, ErrDecrypt) {
		t.Fatal("wrong master key must fail")
	}
}

func TestRotation(t *testing.T) {
	oldKey, newKeyB64 := newKey(t), newKey(t)
	oldRing, _ := NewKeyRing(oldKey)
	s, _ := oldRing.Seal([]byte("v"), nil)

	ring, err := NewKeyRing(newKeyB64, oldKey) // new current, old retired
	if err != nil {
		t.Fatal(err)
	}
	if v, err := ring.Open(s, nil); err != nil || string(v) != "v" {
		t.Fatal("retired key must still decrypt")
	}
	r, err := ring.Rewrap(s)
	if err != nil || r.KEKID != ring.CurrentID() || !bytes.Equal(r.Ciphertext, s.Ciphertext) {
		t.Fatalf("Rewrap: %+v %v", r, err)
	}
	onlyNew, _ := NewKeyRing(newKeyB64)
	if v, err := onlyNew.Open(r, nil); err != nil || string(v) != "v" {
		t.Fatal("rewrapped secret must open with the new key alone")
	}
}

func TestKeyRingValidation(t *testing.T) {
	if _, err := NewKeyRing(); err == nil {
		t.Fatal("empty ring")
	}
	if _, err := NewKeyRing(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("short key")
	}
}

func TestFingerprint(t *testing.T) {
	fp := Fingerprint("ghp_abcdefghijklmnop")
	if !strings.HasSuffix(fp, "…mnop") || strings.Contains(fp, "abcdef") {
		t.Fatalf("fingerprint %q", fp)
	}
	if strings.Contains(Fingerprint("short"), "short") {
		t.Fatal("short values must not leak a suffix")
	}
}

func TestChainResolver(t *testing.T) {
	t.Setenv("HEIMDALL_TEST_TOKEN", "tok")
	c := Chain{}
	if v, err := c.Resolve(context.Background(), Ref{Env: "HEIMDALL_TEST_TOKEN"}); err != nil || v != "tok" {
		t.Fatal(v, err)
	}
	if _, err := c.Resolve(context.Background(), Ref{ID: "1"}); err == nil {
		t.Fatal("ID ref without store must fail")
	}
	if _, err := (EnvFile{}).Resolve(context.Background(), Ref{ID: "1"}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}
