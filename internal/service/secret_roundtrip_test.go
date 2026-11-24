package service_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/hungnm98/heimdall-cve/internal/service"
)

// A secret sealed by the AuthProfiles service must open through the resolver
// the job worker uses: both sides must agree on SecretAAD.
func TestSecretSealedByProfilesOpensWithResolver(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, true)
	const value = "ghp_roundtrip_0123456789"
	if _, err := e.svc.AuthProfiles.Create(ctx, "alice", service.AuthProfileInput{
		Name: "pat", Type: "token", Secret: strp(value),
	}); err != nil {
		t.Fatal(err)
	}
	p, err := e.st.GetAuthProfile(ctx, "pat")
	if err != nil {
		t.Fatal(err)
	}
	if p.SecretID == nil {
		t.Fatal("profile has no secret id")
	}
	r := service.NewSecretResolver(e.st, e.keys)
	got, err := r.Resolve(ctx, secret.Ref{ID: strconv.FormatInt(*p.SecretID, 10)})
	if err != nil || got != value {
		t.Fatalf("Resolve = %q, %v; want the original value", got, err)
	}
}
