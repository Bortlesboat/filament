// Package coordinated adds datastore-backed coordination to versioned cloud
// secret managers. Credentials never enter the datastore. All participants must
// share its coordination records and access managed secrets through this wrapper.
package coordinated

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"maps"
	"strings"
	"time"

	"github.com/galaxy-io/filament"
)

// Versioned supports immutable reads of the exact version returned by a write.
// Empty read versions select the provider's current version only for initial
// adoption. A failed exact-version read must never fall back to current/latest.
type Versioned interface {
	filament.Secrets
	SecretScope() string
	ReadVersion(context.Context, string, string) (filament.Secret, string, error)
	WriteVersion(context.Context, string, filament.Secret) (string, error)
}

// Provider coordinates refreshes, replacement, deletion, and version selection.
type Provider struct {
	backend Versioned
	store   filament.SecretCoordinationStore
}

// New wraps a versioned backend with datastore-backed secret coordination.
func New(backend Versioned, store filament.SecretCoordinationStore) (*Provider, error) {
	if backend == nil || store == nil || backend.SecretScope() == "" {
		return nil, errors.New("external secrets require a versioned provider and datastore coordination")
	}
	return &Provider{backend: backend, store: store}, nil
}

// Name returns the underlying backend's name.
func (p *Provider) Name() string { return p.backend.Name() }

// Close closes the underlying backend if it supports closing.
func (p *Provider) Close() error {
	if c, ok := p.backend.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// Managed references carry the tenant used to isolate coordination state.
func keyFor(p *Provider, ref string) (filament.SecretLeaseKey, bool, error) {
	rest, managed := strings.CutPrefix(ref, filament.ConnectionSecretPrefix)
	if !managed {
		return filament.SecretLeaseKey{}, false, nil
	}
	tenant, tail, ok := strings.Cut(rest, "/")
	if !ok || tenant == "" || tail == "" {
		return filament.SecretLeaseKey{}, true, errors.New("malformed managed secret reference")
	}
	return filament.SecretLeaseKey{Tenant: filament.TenantID(tenant), Scope: p.backend.SecretScope(), Ref: ref}, true, nil
}

// withLease bounds network work to 35s inside a 60s lease. Expired owners cannot
// commit a pointer. Pending state persists after expiry, preventing another
// worker from repeating a possibly successful token rotation.
func (p *Provider) withLease(ctx context.Context, key filament.SecretLeaseKey, fn func(context.Context, string, filament.SecretVersionState) error) error {
	owner := rand.Text()
	var state filament.SecretVersionState
	for {
		var acquired bool
		var err error
		state, acquired, err = p.store.AcquireSecretLease(ctx, key, owner, time.Minute)
		if err != nil {
			return err
		}
		if acquired {
			break
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = p.store.ReleaseSecretLease(cleanup, key, owner)
	}()
	opCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	return fn(opCtx, owner, state)
}

func ready(state filament.SecretVersionState) error {
	if state.Deleted {
		return filament.ErrNotFound
	}
	if state.Pending {
		return filament.ErrSecretUpdateUncertain
	}
	return nil
}

func (p *Provider) read(ctx context.Context, key filament.SecretLeaseKey, owner string, state *filament.SecretVersionState) (filament.Secret, error) {
	if err := ready(*state); err != nil {
		return filament.Secret{}, err
	}
	value, version, err := p.backend.ReadVersion(ctx, key.Ref, state.Version)
	if err != nil {
		return filament.Secret{}, err
	}
	if version == "" || state.Version != "" && version != state.Version {
		return filament.Secret{}, errors.New("secret manager returned an unexpected version")
	}
	if value.Tenant != "" && value.Tenant != key.Tenant {
		return filament.Secret{}, errors.New("secret belongs to another tenant")
	}
	value.Tenant = key.Tenant
	if state.Version == "" {
		state.Version = version
		if err := p.store.SaveSecretVersion(ctx, key, owner, *state); err != nil {
			return filament.Secret{}, err
		}
	}
	return value, nil
}

func (p *Provider) Read(ctx context.Context, ref string) (filament.Secret, error) {
	key, managed, err := keyFor(p, ref)
	if err != nil {
		return filament.Secret{}, err
	}
	if !managed {
		return p.backend.Read(ctx, ref)
	}
	var result filament.Secret
	err = p.withLease(ctx, key, func(ctx context.Context, owner string, state filament.SecretVersionState) error {
		var err error
		result, err = p.read(ctx, key, owner, &state)
		return err
	})
	return result, err
}

func (p *Provider) Write(ctx context.Context, ref string, value filament.Secret) error {
	key, managed, err := keyFor(p, ref)
	if err != nil {
		return err
	}
	if !managed {
		return p.backend.Write(ctx, ref, value)
	}
	if value.Tenant != key.Tenant {
		return errors.New("secret tenant does not match reference")
	}
	return p.withLease(ctx, key, func(ctx context.Context, owner string, state filament.SecretVersionState) error {
		if err := ready(state); err != nil {
			return err
		}
		state.Pending = true
		if err := p.store.SaveSecretVersion(ctx, key, owner, state); err != nil {
			return err
		}
		return p.write(ctx, key, owner, value)
	})
}

func (p *Provider) write(ctx context.Context, key filament.SecretLeaseKey, owner string, value filament.Secret) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	version, err := p.backend.WriteVersion(ctx, key.Ref, value)
	if err != nil {
		return err
	}
	if version == "" {
		return errors.New("secret manager returned no version after writing")
	}
	return p.store.SaveSecretVersion(ctx, key, owner, filament.SecretVersionState{Version: version})
}

// UpdateSecret updates a tenant-owned secret under an exclusive lease.
func (p *Provider) UpdateSecret(ctx context.Context, tenant filament.TenantID, ref string, fn func(filament.Secret) (filament.Secret, error)) (filament.Secret, error) {
	key, managed, err := keyFor(p, ref)
	if err != nil {
		return filament.Secret{}, err
	}
	if !managed || tenant != key.Tenant {
		return filament.Secret{}, errors.New("atomic updates require a tenant-owned managed secret")
	}
	var result filament.Secret
	err = p.withLease(ctx, key, func(ctx context.Context, owner string, state filament.SecretVersionState) error {
		current, err := p.read(ctx, key, owner, &state)
		if err != nil {
			return err
		}
		state.Pending = true
		if err := p.store.SaveSecretVersion(ctx, key, owner, state); err != nil {
			return err
		}
		input := current
		input.Value = bytes.Clone(current.Value)
		input.Meta = maps.Clone(current.Meta)
		next, err := fn(input)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if next.Tenant != tenant {
			return errors.New("cannot change secret tenant")
		}
		if bytes.Equal(next.Value, current.Value) && maps.Equal(next.Meta, current.Meta) {
			state.Pending = false
			err = p.store.SaveSecretVersion(ctx, key, owner, state)
		} else {
			err = p.write(ctx, key, owner, next)
		}
		if err != nil {
			return err
		}
		result = next
		return nil
	})
	return result, err
}

// Delete tombstones a managed secret before deleting it from the backend.
func (p *Provider) Delete(ctx context.Context, ref string) error {
	key, managed, err := keyFor(p, ref)
	if err != nil {
		return err
	}
	if !managed {
		return p.backend.Delete(ctx, ref)
	}
	return p.withLease(ctx, key, func(ctx context.Context, owner string, _ filament.SecretVersionState) error {
		// Persist the tombstone first. Failed cloud deletion may be retried, but
		// stale workers must never make that reference usable again.
		if err := p.store.SaveSecretVersion(ctx, key, owner, filament.SecretVersionState{Deleted: true}); err != nil {
			return err
		}
		return p.backend.Delete(ctx, ref)
	})
}
