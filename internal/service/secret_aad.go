package service

import "strconv"

// Secret sealing scheme (shared by AuthProfiles and the job worker that opens
// secrets to build credentials):
//
//   - Every secret entered in the UI is one store.SecretRecord. Its value is
//     sealed with Deps.Keys.Seal(value, SecretAAD(record.ID)), so a sealed value
//     copied onto another row fails to open.
//   - The AAD needs the record's ID, which the store assigns on insert. A new
//     secret is therefore written twice: first a placeholder record (empty,
//     non-nil ciphertext) to reserve the ID, then the sealed value under that
//     ID (Catalog.SaveSecret replaces by ID). If sealing or the second write
//     fails, the placeholder is deleted. A placeholder can never be opened: GCM
//     rejects an empty ciphertext with secret.ErrDecrypt.
//   - Replacing a profile's secret reuses its record ID, so the AAD is stable
//     and renaming a profile never invalidates its secret.
//   - The profile references the record with the option "<kind>_ref" set to
//     the decimal ID (e.g. token_ref: "12"); auth plugins resolve it through
//     secret.Ref{ID: "12"}. To open:
//
//     rec, _ := catalog.GetSecret(ctx, id)
//     value, err := keys.Open(rec.Sealed, service.SecretAAD(rec.ID))

// SecretAAD is the additional authenticated data binding a sealed value to
// its secret record.
func SecretAAD(secretID int64) []byte {
	return []byte("heimdall/secret/" + strconv.FormatInt(secretID, 10))
}
