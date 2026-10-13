package gcp

import (
	"context"
	"strings"
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"

	"github.com/galaxy-io/filament"
)

type fakeAPI struct {
	API
	ref  string
	read *secretmanagerpb.AccessSecretVersionRequest
	add  *secretmanagerpb.AddSecretVersionRequest
}

func (f *fakeAPI) GetSecret(_ context.Context, in *secretmanagerpb.GetSecretRequest, _ ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	return &secretmanagerpb.Secret{Name: in.Name, Labels: map[string]string{managedLabel: managedValue}, Annotations: map[string]string{refAnnotation: f.ref}}, nil
}

func (f *fakeAPI) AddSecretVersion(_ context.Context, in *secretmanagerpb.AddSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	f.add = in
	return &secretmanagerpb.SecretVersion{Name: in.Parent + "/versions/7"}, nil
}

func (f *fakeAPI) AccessSecretVersion(_ context.Context, in *secretmanagerpb.AccessSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	f.read = in
	return &secretmanagerpb.AccessSecretVersionResponse{Name: strings.Replace(f.add.Parent, "projects/project/", "projects/123456/", 1) + "/versions/7", Payload: f.add.Payload}, nil
}

func TestImmutableVersionsKeepSecretName(t *testing.T) {
	ref := filament.ConnectionSecretRef("tenant", "connection", "token", 1)
	api := &fakeAPI{ref: ref}
	p, err := New(api, "project", "us-central1")
	if err != nil {
		t.Fatal(err)
	}
	version, err := p.WriteVersion(t.Context(), ref, filament.Secret{Tenant: "tenant", Value: []byte("rotated"), Meta: map[string]string{"oauth_format": "v1"}})
	if err != nil || version != "7" {
		t.Fatalf("write version: %s %v", version, err)
	}
	if api.add.Parent != p.secretName(ref) {
		t.Fatal("secret identity changed")
	}
	value, got, err := p.ReadVersion(t.Context(), ref, version)
	if err != nil || got != version || value.Tenant != "tenant" || string(value.Value) != "rotated" || value.Meta["oauth_format"] != "v1" {
		t.Fatalf("roundtrip: %v", err)
	}
	if api.read.Name != p.secretName(ref)+"/versions/7" {
		t.Fatal("read latest instead of pinned version")
	}
	for _, invalid := range []string{"latest", "other/versions/7", "-1"} {
		if _, _, err := p.ReadVersion(t.Context(), ref, invalid); err == nil {
			t.Fatalf("accepted invalid version %s", invalid)
		}
	}
}
