package aws

import (
	"context"
	"testing"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/galaxy-io/filament"
)

type fakeAPI struct {
	API
	put     *secretsmanager.PutSecretValueInput
	get     *secretsmanager.GetSecretValueInput
	create  *secretsmanager.CreateSecretInput
	missing bool
	raw     string
}

func (f *fakeAPI) PutSecretValue(_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	f.put = in
	if f.missing {
		return nil, &smtypes.ResourceNotFoundException{}
	}
	f.raw = sdk.ToString(in.SecretString)
	return &secretsmanager.PutSecretValueOutput{VersionId: in.ClientRequestToken}, nil
}

func (f *fakeAPI) CreateSecret(_ context.Context, in *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	f.create = in
	f.raw = sdk.ToString(in.SecretString)
	return &secretsmanager.CreateSecretOutput{VersionId: in.ClientRequestToken}, nil
}

func (f *fakeAPI) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.get = in
	return &secretsmanager.GetSecretValueOutput{SecretString: sdk.String(f.raw), VersionId: in.VersionId}, nil
}

func TestImmutableVersionsKeepSecretName(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "update", true: "create"}[missing], func(t *testing.T) {
			api := &fakeAPI{missing: missing}
			p := New(api, WithPrefix("company"))
			ref := filament.ConnectionSecretRef("tenant", "connection", "token", 1)
			version, err := p.WriteVersion(t.Context(), ref, filament.Secret{Value: []byte("token"), Meta: map[string]string{"oauth_format": "v1"}})
			if err != nil {
				t.Fatal(err)
			}
			if len(version) < 32 || len(version) > 64 {
				t.Fatal("missing stable write request token")
			}
			if sdk.ToString(api.put.SecretId) != "company/tenant/connection/token/v1" {
				t.Fatal("secret name changed")
			}
			if missing && (sdk.ToString(api.create.Name) != sdk.ToString(api.put.SecretId) || sdk.ToString(api.create.ClientRequestToken) != version) {
				t.Fatal("create lost idempotency identity")
			}
			value, got, err := p.ReadVersion(t.Context(), ref, version)
			if err != nil || got != version || string(value.Value) != "token" || value.Meta["oauth_format"] != "v1" {
				t.Fatalf("version roundtrip: %v", err)
			}
			if sdk.ToString(api.get.VersionId) != version || api.get.VersionStage != nil {
				t.Fatal("exact read used mutable stage")
			}
		})
	}
}
