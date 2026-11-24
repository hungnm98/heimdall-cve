package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Envelope encryption for secrets entered in the web UI.
//
// Each secret gets a random 256-bit data key (DEK). The value is sealed with
// the DEK (AES-256-GCM) and the DEK is sealed with the key-encryption key
// (KEK, the master key). Only Sealed is stored; the KEK lives in env/file/KMS.
// Rotating the KEK re-wraps DEKs without touching values.

// ErrDecrypt hides why decryption failed (wrong key, tampering...).
var ErrDecrypt = errors.New("secret: cannot decrypt")

// Sealed is what the store persists.
type Sealed struct {
	KEKID      string // which master key wrapped the DEK
	WrappedDEK []byte // nonce || GCM(KEK, DEK)
	Ciphertext []byte // nonce || GCM(DEK, value)
}

// KeyRing holds the current master key and older ones still needed to decrypt.
type KeyRing struct {
	current string
	keys    map[string][]byte
}

// KeyID is a short, non-secret fingerprint of a key.
func KeyID(key []byte) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:4])
}

// NewKeyRing builds a ring from base64 32-byte keys. The first is current;
// the rest are retired keys kept for decryption during rotation.
func NewKeyRing(keysB64 ...string) (*KeyRing, error) {
	if len(keysB64) == 0 {
		return nil, errors.New("secret: no master key")
	}
	kr := &KeyRing{keys: map[string][]byte{}}
	for i, k := range keysB64 {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k))
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("secret: master key #%d must be 32 bytes, base64-encoded", i+1)
		}
		id := KeyID(raw)
		kr.keys[id] = raw
		if i == 0 {
			kr.current = id
		}
	}
	return kr, nil
}

// CurrentID is the id of the key used for new seals.
func (k *KeyRing) CurrentID() string { return k.current }

// Seal encrypts value. aad binds the ciphertext to its owner (e.g. the
// secret's id) so a sealed value cannot be swapped onto another record.
func (k *KeyRing) Seal(value, aad []byte) (Sealed, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return Sealed{}, err
	}
	ct, err := gcmSeal(dek, value, aad)
	if err != nil {
		return Sealed{}, err
	}
	wrapped, err := gcmSeal(k.keys[k.current], dek, []byte(k.current))
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{KEKID: k.current, WrappedDEK: wrapped, Ciphertext: ct}, nil
}

// Open decrypts s with the key named by s.KEKID.
func (k *KeyRing) Open(s Sealed, aad []byte) ([]byte, error) {
	kek, ok := k.keys[s.KEKID]
	if !ok {
		return nil, fmt.Errorf("%w: master key %s not loaded", ErrDecrypt, s.KEKID)
	}
	dek, err := gcmOpen(kek, s.WrappedDEK, []byte(s.KEKID))
	if err != nil {
		return nil, ErrDecrypt
	}
	v, err := gcmOpen(dek, s.Ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return v, nil
}

// Rewrap re-seals the DEK with the current key (KEK rotation).
func (k *KeyRing) Rewrap(s Sealed) (Sealed, error) {
	if s.KEKID == k.current {
		return s, nil
	}
	old, ok := k.keys[s.KEKID]
	if !ok {
		return Sealed{}, fmt.Errorf("%w: master key %s not loaded", ErrDecrypt, s.KEKID)
	}
	dek, err := gcmOpen(old, s.WrappedDEK, []byte(s.KEKID))
	if err != nil {
		return Sealed{}, ErrDecrypt
	}
	wrapped, err := gcmSeal(k.keys[k.current], dek, []byte(k.current))
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{KEKID: k.current, WrappedDEK: wrapped, Ciphertext: s.Ciphertext}, nil
}

// Fingerprint identifies a secret value without revealing it: 8 hex chars of
// sha256 plus the last 4 characters (for values longer than 12 characters).
func Fingerprint(value string) string {
	h := sha256.Sum256([]byte(value))
	fp := hex.EncodeToString(h[:4])
	if len(value) > 12 {
		fp += "…" + value[len(value)-4:]
	}
	return fp
}

func gcmSeal(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func gcmOpen(key, sealed, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, ErrDecrypt
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], aad)
}
