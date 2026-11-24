package version

import (
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"golang.org/x/mod/semver"
)

// NPM implements Comparator for npm (semver 2.0: prerelease sorts before the
// release, build metadata is ignored).
type NPM struct{}

var _ Comparator = NPM{}

// Canonical adds the "v" golang.org/x/mod/semver expects and strips a leading
// "=" or "v" and build metadata.
func (NPM) Canonical(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "=v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return ""
	}
	return "v" + v
}

func (n NPM) Valid(v string) bool { return semver.IsValid(n.Canonical(v)) }

func (n NPM) Compare(a, b string) int { return semver.Compare(n.Canonical(a), n.Canonical(b)) }

// Bump follows semver; like Go, a minor bump on 0.x is breaking.
func (n NPM) Bump(from, to string) model.BumpType {
	return Go{}.Bump(n.Canonical(from), n.Canonical(to))
}
