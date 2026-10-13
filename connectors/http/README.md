# HTTP manifests

Bundled connectors live at `manifests/<name>/<api-version>/manifest.yaml`.
Their `registry.json` selects the default upstream API version and maturity.
The manifest grammar is `manifest/grammar.v1.json`.

## Splitting a manifest

A root manifest can include resource and field-set files.

```yaml
version: 1
name: example
display_name: Example
description: Example records.
dark_logo_url: https://example.com/dark.svg
light_logo_url: https://example.com/light.svg
connection:
  base_url: https://api.example.com
includes:
  - fields/common.yaml
  - resources/items.yaml
```

`fields/common.yaml` can declare reusable fields.

```yaml
field_sets:
  identity:
    id: string
    updated_at: timestamptz
```

`resources/items.yaml` declares ordinary resources using the same grammar as
an inline `resources` list.

```yaml
resources:
  - name: items
    path: /items
    primary_key: [id]
    use_fields: [identity]
    fields:
      raw: {path: $, type: json, mode: remainder}
    response:
      records: $.items
```

Fragments may contain only `resources`, `field_sets`, and further `includes`.
Keep configuration, authentication, defaults, discovery, and metadata in the root.
Includes are relative to their containing file and must stay within the root
manifest directory. Remote URLs, included symlinks, cycles, repeated inclusions,
and duplicate resource or field-set names are rejected. YAML aliases do not
cross file boundaries. The loader limits nesting to 16 levels, files to 128,
and combined input to 32 MiB.

Root declarations come first, followed by includes in declaration order. Field
order is preserved. The first eligible resource is the connection probe, so list
that resource first. Includes never override existing declarations.

`manifest.Load` supports local files. `manifest.LoadFS` supports embedded or other
filesystems. `manifest.ReadFS` returns the expanded YAML for applications that
need immutable bytes. `manifest.Parse` and `NewManifest` accept expanded bytes
and reject unresolved includes. Catalog loading expands includes automatically
and validates the resulting manifest before registration. Both single-file and
composed manifests use the same runtime.

## Shared field definitions

`field_sets` define reusable ordered groups. A resource's `use_fields` list
concatenates those groups in order, followed by its own `fields`. Use
`exclude_fields` to omit inherited fields. Duplicate names are rejected.

`field_overrides` replaces an existing field in its original position. Each
override is a complete field declaration, so omitted properties use their normal
defaults. Unknown names are rejected. For example, a resource can require an
otherwise nullable timestamp without repeating the surrounding shared fields.

```yaml
use_fields: [identity]
field_overrides:
  updated_at: {path: MetaData.LastUpdatedTime, type: timestamptz}
fields:
  total: decimal
```

Expansion happens when loading the manifest, so schemas and runtime projections
retain their ordinary flat representation.

## Managed OAuth refresh

The `oauth2` strategy accepts `grant_type: refresh_token`,
`client_auth: client_secret_basic`, and `refresh_token: config.refresh_token`.
Use `managed_refresh: true` for providers that rotate refresh tokens. Supply a
`binding` list of literal or `config` template components identifying the provider,
account, environment, and OAuth client. Do not include the refresh token itself.
The list is hashed and bound to the connection-managed secret. Changing the bound
settings requires a new refresh secret.

Managed refresh uses the runner's configured secret manager, including PostgreSQL,
SQLite, AWS Secrets Manager, and Google Secret Manager. Cloud providers retain
the tokens and use datastore leases and version identifiers for coordination.
Without a bound store, extraction fails before exchanging tokens. Connection
validation checks configuration only when no store is bound. Direct Go callers can supply
an `oauth.Store`. A rejected access token triggers one coordinated refresh and
one replay. A second HTTP 401 fails the request.

An optional `fallback_token: config.access_token` allows manual access-token
connections when all refresh credentials are absent. Partial refresh credentials
are rejected. Initial browser authorization remains external to Filament.
