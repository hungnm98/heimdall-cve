package markdown

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/report"
	"github.com/hungnm98/heimdall-cve/internal/report/reporttest"
)

func TestContract(t *testing.T) {
	factory, err := report.Registry.Get("md")
	if err != nil {
		t.Fatal(err)
	}
	r, err := factory(plugin.Config{}, plugin.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	reporttest.Run(t, r)
}

func TestUnknownOption(t *testing.T) {
	if _, err := New(plugin.Config{"bogus": 1}, plugin.Deps{}); err == nil {
		t.Fatal("unknown option must fail")
	}
}

func TestEscapesUserStrings(t *testing.T) {
	rep := reporttest.Sample()
	rep.Repos[0].Errors = []string{"bad | pipe\nnew *line* <script>"}
	rep.Run.Sources = append(rep.Run.Sources, model.SourceHealth{Name: "nvd", Error: "HTTP 503"})
	var b bytes.Buffer
	if err := (Reporter{}).Render(&b, rep); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		`- bad \| pipe new \*line\* \<script\>`,
		"❌ **unhealthy**",
		"Unhealthy sources: **nvd**",
		"[GO-2024-2687](https://osv.dev/vulnerability/GO-2024-2687)",
		"🔴 **EOL**",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
}

func TestDoesNotMutateInput(t *testing.T) {
	rep := reporttest.Sample()
	rep.Run.Sources = []model.SourceHealth{{Name: "z"}, {Name: "a"}}
	if err := (Reporter{}).Render(&bytes.Buffer{}, rep); err != nil {
		t.Fatal(err)
	}
	if rep.Run.Sources[0].Name != "z" {
		t.Fatal("Render reordered the caller's slice")
	}
}
