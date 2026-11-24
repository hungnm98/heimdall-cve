//go:build live

package endoflife

import (
	"context"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
)

// TestLive checks the response shape of endoflife.date:
// go test -tags=live ./internal/source/endoflife/
func TestLive(t *testing.T) {
	s, err := New(plugin.Config{}, plugin.Deps{HTTP: httpx.New(httpx.Options{})})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []model.Runtime{{Name: "go", Version: "1.20.1"}, {Name: "node", Version: "16.0.0"}, {Name: "ruby", Version: "2.7.8"}} {
		st, err := s.Evaluate(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		if st.Status != model.SupportEOL || st.LatestPatch == "" || st.LatestCycle == "" {
			t.Errorf("%+v: %+v; want eol with latest patch and cycle", r, st)
		}
	}
}
