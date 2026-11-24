package json

import (
	"bytes"
	encjson "encoding/json"
	"strings"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/report"
	"github.com/hungnm98/heimdall-cve/internal/report/reporttest"
)

func TestContract(t *testing.T) {
	factory, err := report.Registry.Get("json")
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

func TestEmptyReportShape(t *testing.T) {
	var b bytes.Buffer
	if err := (Reporter{}).Render(&b, &model.Report{}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(b.String(), "}\n") {
		t.Error("output must end with a newline")
	}
	var got map[string]any
	if err := encjson.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if repos, ok := got["repos"].([]any); !ok || len(repos) != 0 {
		t.Errorf("repos = %#v, want []", got["repos"])
	}
	if got["diff"] != nil || got["generated_at"] != nil {
		t.Errorf("diff and generated_at must be null on an empty report: %v", got)
	}
}

func TestOrderIndependent(t *testing.T) {
	a, b := reporttest.Sample(), reporttest.Sample()
	extra := a.Repos[0]
	extra.Repo.Name = "web"
	extra.Findings = nil
	a.Repos = append(a.Repos, extra)
	b.Repos = append([]model.RepoReport{extra}, b.Repos...)
	a.Run.Sources = append(a.Run.Sources, model.SourceHealth{Name: "ghsa"})
	b.Run.Sources = append([]model.SourceHealth{{Name: "ghsa"}}, b.Run.Sources...)
	var ba, bb bytes.Buffer
	if err := (Reporter{}).Render(&ba, a); err != nil {
		t.Fatal(err)
	}
	if err := (Reporter{}).Render(&bb, b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ba.Bytes(), bb.Bytes()) {
		t.Error("output depends on input order")
	}
}
