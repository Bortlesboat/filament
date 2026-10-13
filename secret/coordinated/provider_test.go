package coordinated_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/galaxy-io/filament"
	"github.com/galaxy-io/filament/datastore/sqlite"
	"github.com/galaxy-io/filament/oauth"
	oauthsecrets "github.com/galaxy-io/filament/oauth/secrets"
	"github.com/galaxy-io/filament/secret/coordinated"
)

const tenant = filament.DefaultTenantID

// Deliberately serves the oldest version for unpinned reads, modelling a stale
// current/latest alias. Multiple wrapper instances share this remote manager.
type cloud struct {
	mu         sync.Mutex
	versions   map[string][]filament.Secret
	reads      []string
	failWrite  bool
	failDelete bool
}

func newCloud() *cloud             { return &cloud{versions: map[string][]filament.Secret{}} }
func (*cloud) Name() string        { return "cloud" }
func (*cloud) SecretScope() string { return "cloud/account/region" }
func (c *cloud) Read(ctx context.Context, ref string) (filament.Secret, error) {
	v, _, err := c.ReadVersion(ctx, ref, "")
	return v, err
}

func (c *cloud) Write(ctx context.Context, ref string, v filament.Secret) error {
	_, err := c.WriteVersion(ctx, ref, v)
	return err
}

func (c *cloud) ReadVersion(_ context.Context, ref, version string) (filament.Secret, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads = append(c.reads, version)
	n := 1
	if version != "" {
		if _, err := fmt.Sscanf(version, "%d", &n); err != nil {
			return filament.Secret{}, "", err
		}
	}
	values := c.versions[ref]
	if n < 1 || n > len(values) {
		return filament.Secret{}, "", filament.ErrNotFound
	}
	v := values[n-1]
	v.Value = append([]byte{}, v.Value...)
	v.Meta = maps.Clone(v.Meta)
	return v, fmt.Sprint(n), nil
}

func (c *cloud) WriteVersion(_ context.Context, ref string, v filament.Secret) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v.Value = append([]byte{}, v.Value...)
	v.Meta = maps.Clone(v.Meta)
	c.versions[ref] = append(c.versions[ref], v)
	if c.failWrite {
		return "", errors.New("response lost after cloud committed")
	}
	return fmt.Sprint(len(c.versions[ref])), nil
}

func (c *cloud) Delete(_ context.Context, ref string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failDelete {
		return errors.New("cloud unavailable")
	}
	delete(c.versions, ref)
	return nil
}

func fixture(t *testing.T) (*sqlite.Store, *cloud, *coordinated.Provider, string) {
	t.Helper()
	db := sqlite.NewMemory()
	t.Cleanup(func() { _ = db.Close() })
	c := newCloud()
	p, err := coordinated.New(c, db)
	if err != nil {
		t.Fatal(err)
	}
	ref := filament.ConnectionSecretRef(string(tenant), "connection", "refresh_token", 1)
	if err := p.Write(t.Context(), ref, filament.Secret{Tenant: tenant, Value: []byte("initial"), Meta: map[string]string{"field": "refresh_token"}}); err != nil {
		t.Fatal(err)
	}
	return db, c, p, ref
}

func binding(t *testing.T, p *coordinated.Provider, ref string) *oauthsecrets.Store {
	t.Helper()
	s, err := oauthsecrets.FromRefreshToken(p, tenant, ref, "client-account")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestConcurrentWorkersUseCommittedVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filament.db")
	db1, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db1.Close()
	db2, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	c := newCloud()
	p1, _ := coordinated.New(c, db1)
	p2, _ := coordinated.New(c, db2)
	ref := filament.ConnectionSecretRef(string(tenant), "connection", "refresh_token", 1)
	if err := p1.Write(t.Context(), ref, filament.Secret{Tenant: tenant, Value: []byte("initial")}); err != nil {
		t.Fatal(err)
	}
	s1, s2 := binding(t, p1, ref), binding(t, p2, ref)
	var exchanges atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	refresh := func(_ context.Context, current oauth.Token) (oauth.Token, error) {
		if current.AccessToken != "" {
			return current, nil
		}
		if exchanges.Add(1) == 1 {
			close(entered)
			<-release
		}
		return oauth.Token{AccessToken: "access", RefreshToken: "rotated", ExpiresAt: time.Now().Add(time.Hour).UTC()}, nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	results := make(chan error, 2)
	go func() { _, err := s1.Update(ctx, refresh); results <- err }()
	<-entered
	go func() { _, err := s2.Update(ctx, refresh); results <- err }()
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if exchanges.Load() != 1 {
		t.Fatalf("exchanged %d times", exchanges.Load())
	}
	reopened, _ := coordinated.New(c, db2)
	got, err := binding(t, reopened, ref).Update(ctx, func(_ context.Context, current oauth.Token) (oauth.Token, error) { return current, nil })
	if err != nil || got.RefreshToken != "rotated" {
		t.Fatalf("restart lost committed token: %v", err)
	}
	for _, version := range c.reads {
		if version == "" {
			t.Fatal("read latest instead of the committed version")
		}
	}
	// No credentials are stored in either database table.
	var count int
	if err := db1.DB().QueryRow("SELECT count(*) FROM secrets").Scan(&count); err != nil || count != 0 {
		t.Fatalf("credential rows=%d err=%v", count, err)
	}
	var version string
	var pending int
	if err := db1.DB().QueryRow("SELECT version,pending FROM secret_coordination WHERE ref=?", ref).Scan(&version, &pending); err != nil || version != "2" || pending != 0 {
		t.Fatalf("coordination metadata %s %d %v", version, pending, err)
	}
}

func TestAmbiguousWriteBlocksAnotherExchange(t *testing.T) {
	db, c, p, ref := fixture(t)
	c.failWrite = true
	_, err := binding(t, p, ref).Update(t.Context(), func(_ context.Context, current oauth.Token) (oauth.Token, error) {
		current.RefreshToken = "new"
		return current, nil
	})
	if err == nil {
		t.Fatal("ambiguous write succeeded")
	}
	c.failWrite = false
	restarted, _ := coordinated.New(c, db)
	_, err = binding(t, restarted, ref).Update(t.Context(), func(_ context.Context, current oauth.Token) (oauth.Token, error) {
		t.Error("replayed uncertain exchange")
		return current, nil
	})
	if !errors.Is(err, filament.ErrSecretUpdateUncertain) {
		t.Fatalf("expected uncertain update: %v", err)
	}
	if err := p.Write(t.Context(), ref, filament.Secret{Tenant: tenant, Value: []byte("replacement")}); !errors.Is(err, filament.ErrSecretUpdateUncertain) {
		t.Fatalf("reused uncertain reference: %v", err)
	}
	// Connection replacement supplies fresh credentials under a new reference.
	next := filament.ConnectionSecretRef(string(tenant), "connection", "refresh_token", 2)
	if err := p.Write(t.Context(), next, filament.Secret{Tenant: tenant, Value: []byte("fresh")}); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Read(t.Context(), ref); !errors.Is(err, filament.ErrNotFound) {
		t.Fatal("old reference resurrected")
	}
}

func TestExpiredOwnerCannotCommitOrReplay(t *testing.T) {
	db, c, p, ref := fixture(t)
	key := filament.SecretLeaseKey{Tenant: tenant, Scope: c.SecretScope(), Ref: ref}
	state, ok, err := db.AcquireSecretLease(t.Context(), key, "dead-worker", time.Minute)
	if err != nil || !ok {
		t.Fatal(err)
	}
	state.Pending = true
	if err := db.SaveSecretVersion(t.Context(), key, "dead-worker", state); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().Exec("UPDATE secret_coordination SET expires_at=0 WHERE ref=?", ref); err != nil {
		t.Fatal(err)
	}
	_, err = p.UpdateSecret(t.Context(), tenant, ref, func(v filament.Secret) (filament.Secret, error) { t.Error("replayed crashed refresh"); return v, nil })
	if !errors.Is(err, filament.ErrSecretUpdateUncertain) {
		t.Fatal(err)
	}
	if err := db.SaveSecretVersion(t.Context(), key, "dead-worker", filament.SecretVersionState{Version: "old"}); !errors.Is(err, filament.ErrSecretLeaseLost) {
		t.Fatalf("stale owner committed: %v", err)
	}
}

func TestReplacementAndDeletionSerializeWithRefresh(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprint(remove), func(t *testing.T) {
			db, c, p, ref := fixture(t)
			other, _ := coordinated.New(c, db)
			entered, release := make(chan struct{}), make(chan struct{})
			result := make(chan error, 2)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			go func() {
				_, err := p.UpdateSecret(ctx, tenant, ref, func(v filament.Secret) (filament.Secret, error) {
					close(entered)
					<-release
					v.Value = []byte("rotated")
					return v, nil
				})
				result <- err
			}()
			<-entered
			go func() {
				if remove {
					result <- other.Delete(ctx, ref)
				} else {
					result <- other.Write(ctx, ref, filament.Secret{Tenant: tenant, Value: []byte("replacement")})
				}
			}()
			close(release)
			for range 2 {
				if err := <-result; err != nil {
					t.Fatal(err)
				}
			}
			got, err := p.Read(ctx, ref)
			if remove {
				if !errors.Is(err, filament.ErrNotFound) {
					t.Fatal("deleted secret returned")
				}
				if err := p.Write(ctx, ref, filament.Secret{Tenant: tenant}); !errors.Is(err, filament.ErrNotFound) {
					t.Fatal("tombstone resurrected")
				}
			} else if err != nil || string(got.Value) != "replacement" {
				t.Fatalf("replacement overwritten: %v", err)
			}
		})
	}
}

func TestFailedDeleteLeavesTombstoneAndCanBeRetried(t *testing.T) {
	_, c, p, ref := fixture(t)
	c.failDelete = true
	if err := p.Delete(t.Context(), ref); err == nil {
		t.Fatal("delete failure lost")
	}
	if _, err := p.Read(t.Context(), ref); !errors.Is(err, filament.ErrNotFound) {
		t.Fatal("tombstone ignored")
	}
	c.failDelete = false
	if err := p.Delete(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
}

func TestTenantIsolationAndPinnedReadFailure(t *testing.T) {
	_, c, p, ref := fixture(t)
	if _, err := p.UpdateSecret(t.Context(), "another-tenant", ref, func(v filament.Secret) (filament.Secret, error) { t.Error("cross-tenant callback"); return v, nil }); err == nil {
		t.Fatal("cross-tenant update accepted")
	}
	if err := p.Write(t.Context(), ref, filament.Secret{Tenant: "another-tenant"}); err == nil {
		t.Fatal("cross-tenant write accepted")
	}
	if err := p.Write(t.Context(), ref, filament.Secret{Tenant: tenant, Value: []byte("second")}); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.versions[ref] = c.versions[ref][:1]
	c.mu.Unlock()
	if _, err := p.Read(t.Context(), ref); !errors.Is(err, filament.ErrNotFound) {
		t.Fatal("missing pinned version fell back to old current")
	}
}

func TestWaitingWorkerHonorsCancellation(t *testing.T) {
	db, c, p, ref := fixture(t)
	key := filament.SecretLeaseKey{Tenant: tenant, Scope: c.SecretScope(), Ref: ref}
	if _, ok, err := db.AcquireSecretLease(t.Context(), key, "active-worker", time.Minute); err != nil || !ok {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err := p.UpdateSecret(ctx, tenant, ref, func(v filament.Secret) (filament.Secret, error) {
		t.Error("waiter bypassed active owner")
		return v, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting operation ignored cancellation: %v", err)
	}
}

type failedMarkerStore struct {
	filament.SecretCoordinationStore
}

func (s failedMarkerStore) SaveSecretVersion(ctx context.Context, key filament.SecretLeaseKey, owner string, state filament.SecretVersionState) error {
	if state.Pending {
		return errors.New("database unavailable before exchange")
	}
	return s.SecretCoordinationStore.SaveSecretVersion(ctx, key, owner, state)
}

func TestExchangeRequiresDurablePendingMarker(t *testing.T) {
	db, c, _, ref := fixture(t)
	p, err := coordinated.New(c, failedMarkerStore{db})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpdateSecret(t.Context(), tenant, ref, func(v filament.Secret) (filament.Secret, error) {
		t.Error("exchange ran without a durable marker")
		return v, nil
	}); err == nil {
		t.Fatal("database error ignored")
	}
}
