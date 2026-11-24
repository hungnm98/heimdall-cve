package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// secretAAD binds a sealed value to its secrets row, so a ciphertext copied
// into another row does not open.
//
// It must produce the same bytes as SecretAAD in secret_aad.go (owned by the
// AuthProfiles service, which seals the secrets this resolver opens).
func secretAAD(id int64) []byte {
	return []byte("heimdall-secret:" + strconv.FormatInt(id, 10))
}

// catalogSecrets resolves secret.Ref{ID} from the encrypted secrets table.
type catalogSecrets struct {
	cat  store.Catalog
	keys *secret.KeyRing
}

// NewSecretResolver returns a secret.Resolver for ID references backed by the
// catalog's sealed secrets. Use it as secret.Chain.Store. Env/file references
// return secret.ErrUnsupported. The plaintext is returned to the caller only;
// it is never logged.
func NewSecretResolver(cat store.Catalog, keys *secret.KeyRing) secret.Resolver {
	return catalogSecrets{cat: cat, keys: keys}
}

func (r catalogSecrets) Resolve(ctx context.Context, ref secret.Ref) (string, error) {
	if ref.ID == "" {
		return "", secret.ErrUnsupported
	}
	if r.keys == nil {
		return "", errors.New("secret store disabled: no master key configured")
	}
	id, err := strconv.ParseInt(ref.ID, 10, 64)
	if err != nil || id <= 0 {
		return "", fmt.Errorf("secret ref %q: not a secret id", ref.ID)
	}
	rec, err := r.cat.GetSecret(ctx, id)
	if err != nil {
		return "", fmt.Errorf("secret %d: %w", id, err)
	}
	v, err := r.keys.Open(rec.Sealed, secretAAD(id))
	if err != nil {
		return "", fmt.Errorf("secret %d: %w", id, err)
	}
	return string(v), nil
}

// RotateKEK re-wraps every secret's data key under keys' current master key
// (`heimdall secrets rotate-kek`). keys must also hold the retired keys the
// secrets are still wrapped with. The values themselves are not decrypted or
// re-encrypted. It keeps going past a failing secret and returns how many
// secrets were re-wrapped along with every error.
func RotateKEK(ctx context.Context, cat store.Catalog, keys *secret.KeyRing) (int, error) {
	if keys == nil {
		return 0, errors.New("rotate kek: no master key")
	}
	all, err := cat.ListSecrets(ctx)
	if err != nil {
		return 0, fmt.Errorf("rotate kek: %w", err)
	}
	n := 0
	var errs []error
	for _, rec := range all {
		if rec.Sealed.KEKID == keys.CurrentID() {
			continue
		}
		sealed, err := keys.Rewrap(rec.Sealed)
		if err != nil {
			errs = append(errs, fmt.Errorf("secret %d: %w", rec.ID, err))
			continue
		}
		now := time.Now().UTC()
		rec.Sealed, rec.RotatedAt = sealed, &now
		if err := cat.SaveSecret(ctx, &rec); err != nil {
			errs = append(errs, fmt.Errorf("secret %d: %w", rec.ID, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}
