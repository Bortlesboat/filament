-- name: AcquireSecretLease :one
INSERT INTO secret_coordination (tenant_id, scope, ref, owner, expires_at)
VALUES (@tenant_id, @scope, @ref, @owner, (CAST(strftime('%s', 'now') AS INTEGER) * 1000) + CAST(@ttl_ms AS INTEGER))
ON CONFLICT (tenant_id, scope, ref) DO UPDATE SET
    owner = excluded.owner, expires_at = excluded.expires_at
WHERE secret_coordination.expires_at <= (CAST(strftime('%s', 'now') AS INTEGER) * 1000)
RETURNING version, pending, deleted;

-- name: SaveSecretVersion :execrows
UPDATE secret_coordination SET version = @version, pending = @pending, deleted = @deleted
WHERE tenant_id = @tenant_id AND scope = @scope AND ref = @ref
    AND owner = @owner AND expires_at > (CAST(strftime('%s', 'now') AS INTEGER) * 1000);

-- name: ReleaseSecretLease :exec
UPDATE secret_coordination SET owner = '', expires_at = 0
WHERE tenant_id = @tenant_id AND scope = @scope AND ref = @ref AND owner = @owner;
