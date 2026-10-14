package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/galaxy-io/filament"
	"github.com/galaxy-io/filament/datastore/postgres/sqlcgen"
)

var _ filament.SecretCoordinationStore = (*Store)(nil)

// AcquireSecretLease acquires an available lease and returns its version state.
func (s *Store) AcquireSecretLease(ctx context.Context, key filament.SecretLeaseKey, owner string, ttl time.Duration) (filament.SecretVersionState, bool, error) {
	if err := validateSecretLease(key, owner); err != nil {
		return filament.SecretVersionState{}, false, err
	}
	if ttl < time.Second || ttl > 5*time.Minute {
		return filament.SecretVersionState{}, false, fmt.Errorf("secret lease duration must be between one second and five minutes")
	}
	row, err := s.q.AcquireSecretLease(ctx, sqlcgen.AcquireSecretLeaseParams{TenantID: string(key.Tenant), Scope: key.Scope, Ref: key.Ref, Owner: owner, TtlMs: ttl.Milliseconds()})
	if errors.Is(err, pgx.ErrNoRows) {
		return filament.SecretVersionState{}, false, nil
	}
	if err != nil {
		return filament.SecretVersionState{}, false, err
	}
	return filament.SecretVersionState{Version: row.Version, Pending: row.Pending, Deleted: row.Deleted}, true, nil
}

// SaveSecretVersion updates version state while the owner holds the lease.
func (s *Store) SaveSecretVersion(ctx context.Context, key filament.SecretLeaseKey, owner string, state filament.SecretVersionState) error {
	if err := validateSecretLease(key, owner); err != nil {
		return err
	}
	count, err := s.q.SaveSecretVersion(ctx, sqlcgen.SaveSecretVersionParams{TenantID: string(key.Tenant), Scope: key.Scope, Ref: key.Ref, Owner: owner, Version: state.Version, Pending: state.Pending, Deleted: state.Deleted})
	if err != nil {
		return err
	}
	if count != 1 {
		return filament.ErrSecretLeaseLost
	}
	return nil
}

// ReleaseSecretLease releases the lease held by the given owner.
func (s *Store) ReleaseSecretLease(ctx context.Context, key filament.SecretLeaseKey, owner string) error {
	if err := validateSecretLease(key, owner); err != nil {
		return err
	}
	return s.q.ReleaseSecretLease(ctx, sqlcgen.ReleaseSecretLeaseParams{TenantID: string(key.Tenant), Scope: key.Scope, Ref: key.Ref, Owner: owner})
}

func validateSecretLease(key filament.SecretLeaseKey, owner string) error {
	if key.Tenant == "" || key.Scope == "" || key.Ref == "" || owner == "" {
		return fmt.Errorf("secret lease requires tenant, scope, reference, and owner")
	}
	return filament.ValidateConnectionSecretRef(key.Ref, key.Tenant)
}
