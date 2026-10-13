package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/galaxy-io/filament"
	"github.com/galaxy-io/filament/oauth"
)

func TestSourceBindsOAuthStoreForConnectionProbe(t *testing.T) {
	var calls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer stored-access" {
			t.Error("source did not use the bound token store")
		}
		fmt.Fprint(w, `[]`)
	}))
	defer api.Close()
	source := NewManifest([]byte(fmt.Sprintf(`
version: 1
name: oauth-fixture
display_name: OAuth Fixture
description: Shared token storage fixture.
dark_logo_url: https://example.com/dark.svg
light_logo_url: https://example.com/light.svg
connection:
  base_url: %s
  auth:
    oauth2:
      token_url: https://unused.example.com/token
      client_id: id
      client_secret: secret
      grant_type: refresh_token
      refresh_token: stale-configured-token
resources:
  - name: items
    path: /items
`, api.URL)))
	source.SetOAuthStore(oauth.NewMemoryStore(oauth.Token{
		AccessToken: "stored-access", RefreshToken: "stored-refresh", ExpiresAt: time.Now().Add(time.Hour),
	}))
	config := filament.NewConfig(nil)
	if err := source.Configure(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Teardown(t.Context()) }()
	if err := source.connector.TestConnection(t.Context()); err != nil {
		t.Fatal(err)
	}
	// TestConnection constructs a fresh underlying connector. It must retain
	// the same store instead of falling back to the configured refresh token.
	if err := source.TestConnection(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("probes = %d", calls.Load())
	}
}
