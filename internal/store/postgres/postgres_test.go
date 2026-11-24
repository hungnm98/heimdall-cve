package postgres

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"testing"

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
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("%s not set", dsnEnv)
	}
	storetest.Run(t, func(t *testing.T) store.Store {
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
	})
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
