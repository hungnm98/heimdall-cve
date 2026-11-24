package store

import (
	"cmp"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

// RepoSort is the key ListRepos orders by.
//
//	name          full name (the default, ascending)
//	last_scanned  LastScannedAt, never-scanned repos counting as the oldest,
//	              then full name, both in the requested order
//
// Open finding counts are computed per page by the service, so they cannot
// be a sort key.
type RepoSort string

const (
	RepoSortName        RepoSort = "name"
	RepoSortLastScanned RepoSort = "last_scanned"
)

// ResolveRepoSort applies the defaults (name asc; last_scanned desc) and
// validates both values.
func ResolveRepoSort(sort RepoSort, order SortOrder) (RepoSort, SortOrder, error) {
	switch sort {
	case "":
		sort = RepoSortName
	case RepoSortName, RepoSortLastScanned:
	default:
		return "", "", &SortError{Field: "sort", Msg: "must be name or last_scanned"}
	}
	switch {
	case order == "" && sort == RepoSortName:
		order = OrderAsc
	case order == "":
		order = OrderDesc
	case order != OrderAsc && order != OrderDesc:
		return "", "", &SortError{Field: "order", Msg: "must be asc or desc"}
	}
	return sort, order, nil
}

// RepoKey is a repo's position in one sort order: the decoded form of a cursor.
type RepoKey struct {
	Sort    RepoSort
	Order   SortOrder
	Scanned *time.Time // last_scanned; nil = never
	Name    string     // full name
}

// RepoKeyOf returns r's key in the given (resolved) order.
func RepoKeyOf(r model.RepoRecord, sort RepoSort, order SortOrder) RepoKey {
	k := RepoKey{Sort: sort, Order: order, Name: r.FullName()}
	if sort == RepoSortLastScanned {
		k.Scanned = r.LastScannedAt
	}
	return k
}

// Compare orders two keys of the same sort: < 0 when a is listed before b.
func (a RepoKey) Compare(b RepoKey) int {
	c := 0
	if a.Sort == RepoSortLastScanned {
		switch {
		case a.Scanned == nil && b.Scanned == nil:
		case a.Scanned == nil:
			c = -1
		case b.Scanned == nil:
			c = 1
		default:
			c = a.Scanned.Compare(*b.Scanned)
		}
	}
	if c == 0 {
		c = cmp.Compare(a.Name, b.Name)
	}
	if a.Order == OrderDesc {
		c = -c
	}
	return c
}

const repoCursorVersion = "r2"

// RepoCursor returns the keyset cursor positioned after r in f's order. For
// the default order (name asc) it is the repo's full name, as before sorting
// existed; other orders get an opaque cursor.
func RepoCursor(r model.RepoRecord, f RepoFilter) string {
	sort, order, _ := ResolveRepoSort(f.Sort, f.Order)
	if sort == RepoSortName && order == OrderAsc {
		return r.FullName()
	}
	scanned := ""
	if sort == RepoSortLastScanned && r.LastScannedAt != nil {
		scanned = r.LastScannedAt.UTC().Format(time.RFC3339Nano)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join(
		[]string{repoCursorVersion, string(sort), string(order), scanned, r.FullName()}, "\x00")))
}

// ParseRepoCursor decodes f.After. It fails when the cursor is malformed or
// was issued for another sort or order than f's (ErrStaleCursor).
func ParseRepoCursor(f RepoFilter) (RepoKey, error) {
	sort, order, err := ResolveRepoSort(f.Sort, f.Order)
	if err != nil {
		return RepoKey{}, err
	}
	k := RepoKey{Sort: sort, Order: order}
	// A full name (owner/name) never decodes as base64url: it holds a '/'.
	if strings.Contains(f.After, "/") {
		if sort != RepoSortName || order != OrderAsc {
			return RepoKey{}, ErrStaleCursor
		}
		k.Name = f.After
		return k, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(f.After)
	if err != nil {
		return RepoKey{}, errors.New("malformed cursor")
	}
	parts := strings.Split(string(b), "\x00")
	if len(parts) != 5 || parts[0] != repoCursorVersion {
		return RepoKey{}, errors.New("malformed cursor")
	}
	if parts[1] != string(sort) || parts[2] != string(order) {
		return RepoKey{}, ErrStaleCursor
	}
	if parts[3] != "" {
		t, err := time.Parse(time.RFC3339Nano, parts[3])
		if err != nil {
			return RepoKey{}, errors.New("malformed cursor")
		}
		k.Scanned = &t
	}
	k.Name = parts[4]
	return k, nil
}
