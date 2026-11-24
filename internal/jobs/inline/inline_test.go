package inline

import (
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/jobs"
	"github.com/hungnm98/heimdall-cve/internal/jobs/jobstest"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
)

func TestContract(t *testing.T) {
	jobstest.Run(t, func(t *testing.T) jobs.Backend {
		b, err := New(plugin.Config{}, plugin.Deps{})
		if err != nil {
			t.Fatal(err)
		}
		return b
	})
}
