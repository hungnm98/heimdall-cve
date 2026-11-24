package postgres

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/hungnm98/heimdall-cve/internal/store/storetest"
	"github.com/jackc/pgx/v5"
)

// Set HEIMDALL_TEST_PG_DSN (e.g. postgres://localhost/heimdall_test?sslmode=disable)
// to run the contract against a real database. Each test uses its own schema.
const dsnEnv = "HEIMDALL_TEST_PG_DSN"

func TestContract(t *testing.T) {
	storetest.Run(t, newTestStore(t))
}

func TestCatalogContract(t *testing.T) {
	storetest.RunCatalog(t, newTestStore(t))
}

// newTestStore skips without a database and returns a factory that opens a
// store in a fresh schema, dropped when the test ends.
func newTestStore(t *testing.T) func(t *testing.T) store.Store {
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("%s not set", dsnEnv)
	}
	return func(t *testing.T) store.Store {
		ctx := context.Background()
		schema := fmt.Sprintf("heimdall_test_%d", rand.Uint32())
		s, err := Open(ctx, dsn, schema, 4)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			conn, err := pgx.Connect(ctx, dsn)
			if err != nil {
				t.Errorf("cleanup connect: %v", err)
				return
			}
			defer conn.Close(ctx)
			if _, err := conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
				t.Errorf("drop schema: %v", err)
			}
		})
		return s
	}
}

func TestConfig(t *testing.T) {
	if _, err := New(plugin.Config{"dsn": "postgres://u:p@h/db"}, plugin.Deps{}); err == nil || !strings.Contains(err.Error(), "dsn") {
		t.Fatalf("inline dsn must be rejected, got %v", err)
	}
	if _, err := New(plugin.Config{"dsn_env": "HEIMDALL_UNSET_DSN"}, plugin.Deps{}); !errors.Is(err, secret.ErrMissing) {
		t.Fatalf("missing dsn: %v", err)
	}
	if _, err := New(plugin.Config{"dsn_env": "X", "schema": "Bad-Schema"}, plugin.Deps{}); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("bad schema must be rejected, got %v", err)
	}
	t.Setenv("HEIMDALL_TEST_BAD_DSN", "postgres://user:s3cret@[bad")
	_, err := New(plugin.Config{"dsn_env": "HEIMDALL_TEST_BAD_DSN"}, plugin.Deps{})
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("bad DSN must fail without leaking the password, got %v", err)
	}
}

// A queued job whose target is deleted must not turn into an "every target"
// job (scan_jobs.target_id is ON DELETE SET NULL).
func TestDeleteTargetCancelsActiveJobs(t *testing.T) {
	s := newTestStore(t)(t).(*Store)
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.SaveAuthProfile(ctx, &model.AuthProfile{Name: "pat", Type: "token", Origin: model.OriginUI}); err != nil {
		t.Fatal(err)
	}
	tg := &model.TargetSpec{Target: model.Target{Kind: model.TargetOrg, Provider: "github", Owner: "acme", Auth: "pat", ListAuth: "pat"},
		Enabled: true, Origin: model.OriginUI}
	if err := s.SaveTarget(ctx, tg); err != nil {
		t.Fatal(err)
	}
	all := &model.Job{Trigger: model.TriggerManual}
	tj := &model.Job{TargetID: &tg.ID, Trigger: model.TriggerManual}
	for _, j := range []*model.Job{all, tj} {
		if _, err := s.CreateJob(ctx, j); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteTarget(ctx, tg.ID); err != nil {
		t.Fatalf("DeleteTarget with an active job: %v", err)
	}
	got, err := s.GetJob(ctx, tj.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.JobCanceled || got.FinishedAt == nil {
		t.Fatalf("job of a deleted target = %+v, want canceled", got)
	}
	if got, _ := s.GetJob(ctx, all.ID); got.Status != model.JobQueued {
		t.Fatalf("unrelated job = %s, want queued", got.Status)
	}
}
