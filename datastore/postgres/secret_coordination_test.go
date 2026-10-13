package postgres_test

import (
	"errors"
	"testing"
	"time"

	"github.com/galaxy-io/filament"
	"github.com/galaxy-io/filament/datastore/postgres"
)

func TestSecretCoordinationFencesExpiredOwners(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	key := filament.SecretLeaseKey{Tenant: tenantA, Scope: "aws/account/region", Ref: filament.ConnectionSecretRef(tenantA, "connection", "token", 1)}
	_, ok, err := s.AcquireSecretLease(ctx, key, "one", time.Minute)
	if err != nil || !ok {
		t.Fatalf("claim: %v", err)
	}
	// A different Store/connection observes the same lease.
	other := postgres.New(s.Pool())
	if _, ok, err := other.AcquireSecretLease(ctx, key, "two", time.Minute); err != nil || ok {
		t.Fatalf("double claim: %v", err)
	}
	pending := filament.SecretVersionState{Version: "cloud-version", Pending: true}
	if err := s.SaveSecretVersion(ctx, key, "one", pending); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool().Exec(ctx, "UPDATE secret_coordination SET expires_at=0 WHERE tenant_id=$1 AND ref=$2", string(key.Tenant), key.Ref); err != nil {
		t.Fatal(err)
	}
	state, ok, err := other.AcquireSecretLease(ctx, key, "two", time.Minute)
	if err != nil || !ok || state != pending {
		t.Fatalf("lost crash marker: %+v %v", state, err)
	}
	if err := s.SaveSecretVersion(ctx, key, "one", filament.SecretVersionState{}); !errors.Is(err, filament.ErrSecretLeaseLost) {
		t.Fatalf("old owner wrote: %v", err)
	}
	if err := s.ReleaseSecretLease(ctx, key, "one"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.AcquireSecretLease(ctx, key, "three", time.Minute); err != nil || ok {
		t.Fatalf("stale release removed new lease: %v", err)
	}
	if err := other.ReleaseSecretLease(ctx, key, "two"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.AcquireSecretLease(ctx, key, "three", time.Minute); err != nil || !ok {
		t.Fatal(err)
	}
	key.Tenant = "22222222-2222-4222-8222-222222222222"
	if _, _, err := s.AcquireSecretLease(ctx, key, "other-tenant", time.Minute); err == nil {
		t.Fatal("cross tenant lease accepted")
	}
}
