// Package endoflife is the runtime support source backed by endoflife.date.
//
// GET {base_url}/api/{product}.json returns one entry per release cycle; "eol"
// is either a boolean or an ISO date. Responses are cached (24h by default).
package endoflife

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/source"
)

// Name is the source name.
const Name = "endoflife"

func init() { source.Runtime.Register(Name, New) }

// products maps runtime names (model.Runtime.Name) to endoflife.date products.
var products = map[string]string{"go": "go", "node": "nodejs", "ruby": "ruby"}

// Config is the plugin's config block (`sources.endoflife`).
type Config struct {
	BaseURL        string        `mapstructure:"base_url"`         // default https://endoflife.date
	EOLWarningDays int           `mapstructure:"eol_warning_days"` // eol-soon threshold (default 90)
	CacheTTL       time.Duration `mapstructure:"cache_ttl"`        // default 24h
}

// Validate implements plugin.Validator.
func (c *Config) Validate() error {
	if _, err := url.ParseRequestURI(c.BaseURL); err != nil {
		return fmt.Errorf("base_url: %w", err)
	}
	if c.EOLWarningDays < 0 {
		return errors.New("eol_warning_days must be >= 0")
	}
	if c.CacheTTL < 0 {
		return errors.New("cache_ttl must be >= 0")
	}
	return nil
}

// Source implements source.RuntimeSource.
type Source struct {
	cfg   Config
	http  *httpx.Client
	cache *httpx.Cache
	now   func() time.Time // injectable clock
}

var _ source.RuntimeSource = (*Source)(nil)

// New is the registry factory.
func New(raw plugin.Config, deps plugin.Deps) (source.RuntimeSource, error) {
	cfg := Config{BaseURL: "https://endoflife.date", EOLWarningDays: 90, CacheTTL: 24 * time.Hour}
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("endoflife: %w", err)
	}
	if deps.HTTP == nil {
		return nil, errors.New("endoflife: deps.HTTP is required")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &Source{cfg: cfg, http: deps.HTTP, cache: deps.Cache, now: time.Now}, nil
}

func (s *Source) Name() string { return Name }

func (s *Source) Supports(runtime string) bool {
	_, ok := products[runtime]
	return ok
}

// eolField is endoflife.date's "eol": false, true or "YYYY-MM-DD".
type eolField struct {
	Bool bool
	Date *time.Time
}

func (e *eolField) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	switch {
	case string(b) == "null":
		return nil
	case len(b) > 0 && b[0] == '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		t, err := time.Parse(time.DateOnly, s)
		if err != nil {
			return fmt.Errorf("eol date %q: %w", s, err)
		}
		e.Date = &t
		return nil
	}
	return json.Unmarshal(b, &e.Bool)
}

// cycle is one entry of /api/{product}.json. "cycle" and "latest" may be
// numbers in some products, hence json.Number-tolerant decoding.
type cycle struct {
	Cycle  flexString `json:"cycle"`
	EOL    eolField   `json:"eol"`
	Latest flexString `json:"latest"`
}

type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flexString(n.String())
	return nil
}

func (s *Source) cycles(ctx context.Context, product string) ([]cycle, error) {
	u := s.cfg.BaseURL + "/api/" + url.PathEscape(product) + ".json"
	b, err := s.cache.Fetch(ctx, "endoflife:"+u, s.cfg.CacheTTL, func(ctx context.Context) ([]byte, error) {
		var raw json.RawMessage
		if err := s.http.GetJSON(ctx, u, nil, &raw); err != nil {
			return nil, fmt.Errorf("endoflife %s: %w", product, err)
		}
		return raw, nil
	})
	if err != nil {
		return nil, err
	}
	var out []cycle
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("endoflife %s: decode: %w", product, err)
	}
	return out, nil
}

// Evaluate implements source.RuntimeSource. A version whose cycle is not
// listed yields status unknown, not an error.
func (s *Source) Evaluate(ctx context.Context, rt model.Runtime) (*model.RuntimeStatus, error) {
	product, ok := products[rt.Name]
	if !ok {
		return nil, fmt.Errorf("endoflife: unsupported runtime %q", rt.Name)
	}
	cycles, err := s.cycles(ctx, product)
	if err != nil {
		return nil, err
	}
	now := s.now()
	st := &model.RuntimeStatus{Runtime: rt, Status: model.SupportUnknown, Source: Name}

	sort.SliceStable(cycles, func(i, j int) bool { return compareDotted(string(cycles[i].Cycle), string(cycles[j].Cycle)) > 0 })
	for _, c := range cycles {
		if s.status(c, now) == model.SupportSupported {
			st.LatestCycle = string(c.Cycle)
			break
		}
	}
	for _, want := range candidateCycles(rt.Version) {
		for _, c := range cycles {
			if string(c.Cycle) != want {
				continue
			}
			st.Cycle = want
			st.Status = s.status(c, now)
			st.EOLDate = c.EOL.Date
			st.LatestPatch = string(c.Latest)
			return st, nil
		}
	}
	return st, nil
}

func (s *Source) status(c cycle, now time.Time) model.SupportStatus {
	switch {
	case c.EOL.Date != nil:
		if !now.Before(*c.EOL.Date) {
			return model.SupportEOL
		}
		if c.EOL.Date.Sub(now) <= time.Duration(s.cfg.EOLWarningDays)*24*time.Hour {
			return model.SupportEOLSoon
		}
		return model.SupportSupported
	case c.EOL.Bool:
		return model.SupportEOL
	}
	return model.SupportSupported
}

// candidateCycles returns the cycles a declared version may belong to, most
// specific first: "1.22.5" → ["1.22", "1"]; "go1.22" → ["1.22", "1"]; "20" → ["20"].
// Range operators ("^", ">=", "~>") and suffixes ("rc1", "-alpine") are ignored.
func candidateCycles(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "^~<>=! \tvgo")
	end := 0
	for end < len(v) && (v[end] == '.' || (v[end] >= '0' && v[end] <= '9')) {
		end++
	}
	parts := strings.Split(strings.Trim(v[:end], "."), ".")
	if parts[0] == "" {
		return nil
	}
	if len(parts) >= 2 {
		return []string{parts[0] + "." + parts[1], parts[0]}
	}
	return []string{parts[0]}
}

// compareDotted compares dotted numeric versions ("1.22" < "1.3" is false).
func compareDotted(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(as), len(bs)); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
