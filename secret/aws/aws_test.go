package aws

import (
	"context"
	"errors"
	"testing"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

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

type fakeIdentity struct {
	output *sts.GetCallerIdentityOutput
	err    error
}

func (f fakeIdentity) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return f.output, f.err
}

func TestCoordinationScopeUsesCloudNamespace(t *testing.T) {
	scope := func(partition, account, region, prefix, role string) string {
		t.Helper()
		p := New(&fakeAPI{}, WithPrefix(prefix))
		p.region = region
		err := p.resolveIdentity(t.Context(), fakeIdentity{output: &sts.GetCallerIdentityOutput{
			Account: sdk.String(account),
			Arn:     sdk.String("arn:" + partition + ":sts::" + account + ":assumed-role/" + role),
		}})
		if err != nil {
			t.Fatal(err)
		}
		return p.SecretScope()
	}
	base := scope("aws", "111111111111", "us-east-1", "", "worker/session-one")
	if base != "aws-secrets-manager/aws/111111111111/us-east-1/filament" {
		t.Fatalf("scope = %q", base)
	}
	if other := scope("aws", "111111111111", "us-east-1", "filament/", "server/session-two"); other != base {
		t.Fatal("roles, sessions, or equivalent prefixes split coordination")
	}
	for name, other := range map[string]string{
		"account":   scope("aws", "222222222222", "us-east-1", "", "worker/session-one"),
		"partition": scope("aws-us-gov", "111111111111", "us-east-1", "", "worker/session-one"),
		"region":    scope("aws", "111111111111", "us-west-2", "", "worker/session-one"),
		"prefix":    scope("aws", "111111111111", "us-east-1", "other", "worker/session-one"),
	} {
		if other == base {
			t.Fatalf("%s shares coordination", name)
		}
	}
	explicit := New(&fakeAPI{}, WithIdentity("aws", "111111111111", "us-east-1"))
	if explicit.SecretScope() != base {
		t.Fatal("explicit identity differs from discovered identity")
	}
}

func TestCoordinationRequiresResolvedIdentity(t *testing.T) {
	unavailable := errors.New("STS unavailable")
	for name, client := range map[string]fakeIdentity{
		"unavailable":        {err: unavailable},
		"empty":              {},
		"missing account":    {output: &sts.GetCallerIdentityOutput{Arn: sdk.String("arn:aws:iam::111111111111:root")}},
		"invalid ARN":        {output: &sts.GetCallerIdentityOutput{Account: sdk.String("111111111111"), Arn: sdk.String("invalid")}},
		"mismatched account": {output: &sts.GetCallerIdentityOutput{Account: sdk.String("222222222222"), Arn: sdk.String("arn:aws:iam::111111111111:root")}},
	} {
		t.Run(name, func(t *testing.T) {
			p := New(&fakeAPI{})
			p.region = "us-east-1"
			err := p.resolveIdentity(t.Context(), client)
			if err == nil {
				t.Fatal("accepted unresolved identity")
			}
			if client.err != nil && !errors.Is(err, unavailable) {
				t.Fatal("lost discovery error")
			}
			if p.SecretScope() != "" {
				t.Fatal("unresolved identity can coordinate")
			}
		})
	}
	if New(&fakeAPI{}, WithIdentity("aws", "111111111111", "")).SecretScope() != "" {
		t.Fatal("missing region can coordinate")
	}
}
