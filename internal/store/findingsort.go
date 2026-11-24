package store

import (
	"cmp"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

// FindingSort is the key ListFindings orders by. Every order ends with the
// finding ID, so it is total and keyset pagination is stable.
//
//	severity   severity rank, then repo, then id. desc (the default) is worst
//	           first with repo and id ascending; asc is its exact reverse
//	           (repo and id descending), so one index serves both.
//	priority   Finding.Priority (0–100), then id, both in the requested order.
//	name       FindingSortName (lower-cased, byte-wise), then id.
//	first_seen FirstSeen, then id.
//	repo       Repo (byte-wise), then id.
type FindingSort string

const (
	SortSeverity  FindingSort = "severity"
	SortPriority  FindingSort = "priority"
	SortName      FindingSort = "name"
	SortFirstSeen FindingSort = "first_seen"
	SortRepo      FindingSort = "repo"
)

// FindingSorts lists the valid sort keys.
var FindingSorts = []FindingSort{SortSeverity, SortPriority, SortName, SortFirstSeen, SortRepo}

// SortOrder is ascending or descending.
type SortOrder string

const (
	OrderAsc  SortOrder = "asc"
	OrderDesc SortOrder = "desc"
)

// DefaultOrder is the order used when only a sort key is given: descending
// for severity, priority and first_seen (worst / newest first), ascending for
// name and repo (alphabetical).
func (s FindingSort) DefaultOrder() SortOrder {
	if s == SortName || s == SortRepo {
		return OrderAsc
	}
	return OrderDesc
}

// SortError reports an invalid sort or order value.
type SortError struct{ Field, Msg string }

func (e *SortError) Error() string { return e.Field + ": " + e.Msg }

// ResolveFindingSort applies the defaults (severity, then the key's default
// order) and validates both values.
func ResolveFindingSort(sort FindingSort, order SortOrder) (FindingSort, SortOrder, error) {
	if sort == "" {
		sort = SortSeverity
	}
	valid := false
	for _, s := range FindingSorts {
		valid = valid || s == sort
	}
	if !valid {
		return "", "", &SortError{Field: "sort", Msg: "must be severity, priority, name, first_seen or repo"}
	}
	if order == "" {
		order = sort.DefaultOrder()
	}
	if order != OrderAsc && order != OrderDesc {
		return "", "", &SortError{Field: "order", Msg: "must be asc or desc"}
	}
	return sort, order, nil
}

// FindingSortName is the "name" sort key: the package name, else the runtime
// name (runtime findings), else the advisory ID — the first one set, so every
// kind of finding has one. It is lower-cased so the order is case-insensitive.
func FindingSortName(f model.Finding) string {
	n := f.Package.Name
	if n == "" && f.Runtime != nil {
		n = f.Runtime.Runtime.Name
	}
	if n == "" {
		n = f.AdvisoryID
	}
	return strings.ToLower(n)
}

// FindingKey is a finding's position in one sort order: the decoded form of a
// cursor. Only the fields of Sort are set.
type FindingKey struct {
	Sort      FindingSort
	Order     SortOrder
	Rank      int     // severity
	Repo      string  // severity, repo
	Priority  float64 // priority
	Name      string  // name
	FirstSeen time.Time
	ID        string
}

// KeyOf returns f's key in the given (resolved) order.
func KeyOf(f model.Finding, sort FindingSort, order SortOrder) FindingKey {
	k := FindingKey{Sort: sort, Order: order, ID: f.ID}
	switch sort {
	case SortSeverity:
		k.Rank, k.Repo = f.Severity.Rank(), f.Repo
	case SortPriority:
		k.Priority = f.Priority
	case SortName:
		k.Name = FindingSortName(f)
	case SortFirstSeen:
		k.FirstSeen = f.FirstSeen
	case SortRepo:
		k.Repo = f.Repo
	}
	return k
}

// Compare orders two keys of the same sort: < 0 when a is listed before b.
func (a FindingKey) Compare(b FindingKey) int {
	var c int
	switch a.Sort {
	case SortSeverity:
		// Ascending form: rank asc, repo desc, id desc (desc is the reverse).
		c = cmp.Compare(a.Rank, b.Rank)
		if c == 0 {
			c = -cmp.Compare(a.Repo, b.Repo)
		}
		if c == 0 {
			c = -cmp.Compare(a.ID, b.ID)
		}
	default:
		switch a.Sort {
		case SortPriority:
			c = cmp.Compare(a.Priority, b.Priority)
		case SortName:
			c = cmp.Compare(a.Name, b.Name)
		case SortFirstSeen:
			c = a.FirstSeen.Compare(b.FirstSeen)
		case SortRepo:
			c = cmp.Compare(a.Repo, b.Repo)
		}
		if c == 0 {
			c = cmp.Compare(a.ID, b.ID)
		}
	}
	if a.Order == OrderDesc {
		c = -c
	}
	return c
}

// cursorVersion prefixes every finding cursor. Cursors of the old format
// (severity order only) fail to parse with ErrStaleCursor.
const cursorVersion = "f2"

// ErrStaleCursor is returned for a cursor issued by an older version or for
// another sort or order: the client must restart from the first page.
var ErrStaleCursor = errors.New("cursor does not match this sort order (it may be from an older version): restart from the first page")

// FindingCursor returns the keyset cursor positioned after f in flt's order.
// flt.Sort and flt.Order must be valid (see ResolveFindingSort).
func FindingCursor(f model.Finding, flt FindingFilter) string {
	sort, order, _ := ResolveFindingSort(flt.Sort, flt.Order)
	k := KeyOf(f, sort, order)
	parts := []string{cursorVersion, string(sort), string(order)}
	switch sort {
	case SortSeverity:
		parts = append(parts, strconv.Itoa(k.Rank), k.Repo)
	case SortPriority:
		parts = append(parts, strconv.FormatFloat(k.Priority, 'g', -1, 64))
	case SortName:
		parts = append(parts, k.Name)
	case SortFirstSeen:
		parts = append(parts, k.FirstSeen.UTC().Format(time.RFC3339Nano))
	case SortRepo:
		parts = append(parts, k.Repo)
	}
	parts = append(parts, k.ID)
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join(parts, "\x00")))
}

// ParseFindingCursor decodes flt.After. It fails when the cursor is malformed
// or was issued for another sort or order than flt's.
func ParseFindingCursor(flt FindingFilter) (FindingKey, error) {
	sort, order, err := ResolveFindingSort(flt.Sort, flt.Order)
	if err != nil {
		return FindingKey{}, err
	}
	b, err := base64.RawURLEncoding.DecodeString(flt.After)
	if err != nil {
		return FindingKey{}, errors.New("malformed cursor")
	}
	parts := strings.Split(string(b), "\x00")
	if len(parts) < 3 || parts[0] != cursorVersion || parts[1] != string(sort) || parts[2] != string(order) {
		return FindingKey{}, ErrStaleCursor
	}
	k := FindingKey{Sort: sort, Order: order}
	vals, want := parts[3:], 2
	if sort == SortSeverity {
		want = 3
	}
	if len(vals) != want {
		return FindingKey{}, errors.New("malformed cursor")
	}
	k.ID = vals[len(vals)-1]
	switch sort {
	case SortSeverity:
		k.Rank, err = strconv.Atoi(vals[0])
		k.Repo = vals[1]
	case SortPriority:
		k.Priority, err = strconv.ParseFloat(vals[0], 64)
	case SortName:
		k.Name = vals[0]
	case SortFirstSeen:
		k.FirstSeen, err = time.Parse(time.RFC3339Nano, vals[0])
	case SortRepo:
		k.Repo = vals[0]
	}
	if err != nil {
		return FindingKey{}, errors.New("malformed cursor")
	}
	return k, nil
}
