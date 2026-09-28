-- Multi-tenancy foundation: tenant scoping on every data table.
--
-- WHY
-- ---
-- The schema had no tenant concept at all, and its UNIQUE constraints were
-- global. devices.ip_address was UNIQUE, so two customers scanning overlapping
-- RFC1918 space (the normal case) collided on the same address. The upsert in
-- api/scans.go is `ON CONFLICT (ip_address) DO UPDATE SET hostname,
-- vendor, device_type, risk_score = EXCLUDED.*`, so customer B's device scan
-- silently OVERWROTE customer A's device row. For a security product this
-- means a Critical camera (risk 9.5) is replaced by an unrelated asset
-- (risk 0.5) and the finding disappears. Verified against PostgreSQL 16
-- before writing this migration.
--
-- users.username and users.email were UNIQUE too, so the same person could not
-- hold an account in two tenants.
--
-- WHAT THIS MIGRATION DOES
-- ------------------------
-- Introduces a tenants table, adds tenant_id to every data table, backfills
-- existing rows to a single default tenant, and converts every global unique
-- constraint to a tenant-scoped composite. Cross-tenant references are then
-- rejected by composite foreign keys, so tenant integrity is enforced by the
-- database rather than by remembering a WHERE clause.
--
-- COMPATIBILITY
-- -------------
-- A single-tenant deployment is unaffected: every existing row is backfilled
-- to the default tenant, and tenant_id carries a DEFAULT of that same tenant
-- so existing INSERTs that do not mention it keep working. Row counts, ids and
-- query results are unchanged.
--
-- The DEFAULT is a transitional safety net. Once every write path sets
-- tenant_id explicitly it must be dropped, because a query that forgets it
-- would silently write into the default tenant instead of failing. See
-- docs/adr.md and the follow-up work tracked in the roadmap.
--
-- Row-Level Security is intentionally NOT enabled here: RLS with no
-- per-request tenant context denies everything, so it ships together with the
-- code that sets the tenant on each connection.

-- ---------------------------------------------------------------------------
-- 1. tenants
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    -- Device networks this tenant is authorised to scan. The operator is
    -- responsible for only populating networks they own or are permitted to
    -- test; there is no default that is safe for everyone.
    scan_scope  JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The default tenant every single-tenant deployment uses. A fixed UUID so the
-- DEFAULT clause below and any future bootstrap code agree on the value.
INSERT INTO tenants (id, slug, name, scan_scope)
VALUES ('00000000-0000-0000-0000-000000000001', 'default', 'Default Tenant', '[]'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. tenant_id on every data table
-- ---------------------------------------------------------------------------
-- Every table is backfilled to the default tenant before NOT NULL is applied,
-- so this is safe on a populated database.
DO $$
DECLARE
    t   TEXT;
    tbl TEXT[] := ARRAY[
        'devices', 'scans', 'vulnerabilities', 'firmware', 'alerts',
        'users', 'safelists', 'scan_profiles', 'scan_scopes',
        'webhooks', 'webhook_deliveries', 'refresh_tokens', 'audit_log'
    ];
BEGIN
    FOREACH t IN ARRAY tbl LOOP
        IF to_regclass('public.' || t) IS NULL THEN
            CONTINUE;
        END IF;

        EXECUTE format('ALTER TABLE public.%I ADD COLUMN IF NOT EXISTS tenant_id UUID', t);

        -- Backfill before enforcing NOT NULL.
        EXECUTE format(
            'UPDATE public.%I SET tenant_id = %L::uuid WHERE tenant_id IS NULL',
            t, '00000000-0000-0000-0000-000000000001');

        EXECUTE format(
            'ALTER TABLE public.%I ALTER COLUMN tenant_id SET DEFAULT %L::uuid',
            t, '00000000-0000-0000-0000-000000000001');

        EXECUTE format('ALTER TABLE public.%I ALTER COLUMN tenant_id SET NOT NULL', t);
    END LOOP;
END
$$;

-- tenant_id -> tenants(id). ON DELETE RESTRICT is deliberate: deleting a tenant
-- must not silently cascade-delete a customer's entire security history.
DO $$
DECLARE
    t   TEXT;
    tbl TEXT[] := ARRAY[
        'devices', 'scans', 'vulnerabilities', 'firmware', 'alerts',
        'users', 'safelists', 'scan_profiles', 'scan_scopes',
        'webhooks', 'webhook_deliveries', 'refresh_tokens', 'audit_log'
    ];
BEGIN
    FOREACH t IN ARRAY tbl LOOP
        IF to_regclass('public.' || t) IS NULL THEN
            CONTINUE;
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = format('public.%I', t)::regclass
              AND conname = t || '_tenant_id_fkey'
        ) THEN
            EXECUTE format(
                'ALTER TABLE public.%I ADD CONSTRAINT %I ' ||
                'FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT',
                t, t || '_tenant_id_fkey');
        END IF;
    END LOOP;
END
$$;

-- ---------------------------------------------------------------------------
-- 3. tenant-scoped uniqueness
-- ---------------------------------------------------------------------------
-- Each of these was globally UNIQUE and is now unique per tenant. The DROP
-- guards make the migration re-runnable; the constraint names are the ones
-- Postgres generated, verified against a live database.
ALTER TABLE devices         DROP CONSTRAINT IF EXISTS devices_ip_address_key;
ALTER TABLE users           DROP CONSTRAINT IF EXISTS users_username_key;
ALTER TABLE users           DROP CONSTRAINT IF EXISTS users_email_key;
ALTER TABLE safelists       DROP CONSTRAINT IF EXISTS safelists_entry_type_value_key;
ALTER TABLE scan_profiles   DROP CONSTRAINT IF EXISTS scan_profiles_name_key;
ALTER TABLE refresh_tokens  DROP CONSTRAINT IF EXISTS refresh_tokens_token_hash_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_tenant_ip          ON devices (tenant_id, ip_address);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_username      ON users (tenant_id, username);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email         ON users (tenant_id, email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_safelists_tenant_value     ON safelists (tenant_id, entry_type, value);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_profiles_tenant_name ON scan_profiles (tenant_id, name);
-- token_hash is 32 random bytes, so it is globally unique by construction;
-- scoping it is defence in depth: a hash from one tenant must not be
-- resolvable in another.
CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_tenant_hash ON refresh_tokens (tenant_id, token_hash);

-- Needed as the target of the composite foreign keys below.
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_tenant_id          ON devices (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_tenant_id            ON scans (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_tenant_id           ON alerts (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_id            ON users (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_firmware_tenant_id         ON firmware (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_profiles_tenant_id    ON scan_profiles (tenant_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_webhooks_tenant_id         ON webhooks (tenant_id, id);

-- ---------------------------------------------------------------------------
-- 4. Cross-tenant references are now impossible
-- ---------------------------------------------------------------------------
-- Each FK that pointed at a bare id becomes a composite FK on
-- (tenant_id, <ref>_id). A row can therefore no longer reference another
-- tenant's device, scan, user or alert, even if application code is wrong.
-- The original single-column constraints are dropped first.
ALTER TABLE scans              DROP CONSTRAINT IF EXISTS scans_device_id_fkey;
ALTER TABLE scans              DROP CONSTRAINT IF EXISTS scans_scan_profile_id_fkey;
ALTER TABLE vulnerabilities    DROP CONSTRAINT IF EXISTS vulnerabilities_device_id_fkey;
ALTER TABLE vulnerabilities    DROP CONSTRAINT IF EXISTS vulnerabilities_scan_id_fkey;
ALTER TABLE firmware           DROP CONSTRAINT IF EXISTS firmware_device_id_fkey;
ALTER TABLE alerts             DROP CONSTRAINT IF EXISTS alerts_device_id_fkey;
ALTER TABLE refresh_tokens     DROP CONSTRAINT IF EXISTS refresh_tokens_user_id_fkey;
ALTER TABLE safelists          DROP CONSTRAINT IF EXISTS safelists_created_by_fkey;
ALTER TABLE audit_log          DROP CONSTRAINT IF EXISTS audit_log_user_id_fkey;
ALTER TABLE webhook_deliveries DROP CONSTRAINT IF EXISTS webhook_deliveries_alert_id_fkey;
ALTER TABLE webhook_deliveries DROP CONSTRAINT IF EXISTS webhook_deliveries_webhook_id_fkey;

DO $$
DECLARE
    spec TEXT[] := ARRAY[
        -- child_table|child_column|parent_table|constraint_suffix
        'scans|device_id|devices|device',
        'scans|scan_profile_id|scan_profiles|scan_profile',
        'vulnerabilities|device_id|devices|device',
        'vulnerabilities|scan_id|scans|scan',
        'firmware|device_id|devices|device',
        'alerts|device_id|devices|device',
        'refresh_tokens|user_id|users|user',
        'safelists|created_by|users|created_by',
        'audit_log|user_id|users|user',
        'webhook_deliveries|alert_id|alerts|alert',
        'webhook_deliveries|webhook_id|webhooks|webhook'
    ];
    parts  TEXT[];
    tbl   TEXT;
    col   TEXT;
    parent TEXT;
    cname TEXT;
    entry TEXT;
BEGIN
    FOREACH entry IN ARRAY spec LOOP
        parts  := string_to_array(entry, '|');
        tbl    := parts[1];
        col    := parts[2];
        parent := parts[3];
        cname  := tbl || '_' || col || '_tenant_fkey';

        IF to_regclass('public.' || tbl) IS NULL THEN
            CONTINUE;
        END IF;

        EXECUTE format('ALTER TABLE public.%I DROP CONSTRAINT IF EXISTS %I', tbl, cname);
        EXECUTE format(
            'ALTER TABLE public.%I ADD CONSTRAINT %I ' ||
            'FOREIGN KEY (tenant_id, %I) REFERENCES public.%I (tenant_id, id) ' ||
            'ON DELETE CASCADE',
            tbl, cname, col, parent);
    END LOOP;
END
$$;

-- ---------------------------------------------------------------------------
-- 5. tenant-leading indexes for the access patterns
-- ---------------------------------------------------------------------------
-- Every query will be scoped by tenant, so tenant_id leads each index that
-- backs a list endpoint. tenant_id first also makes these usable by the
-- Row-Level Security policies added later.
CREATE INDEX IF NOT EXISTS idx_devices_tenant_last_seen        ON devices (tenant_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_scans_tenant_started_at         ON scans (tenant_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_tenant_disc     ON vulnerabilities (tenant_id, discovered_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_triggered        ON alerts (tenant_id, triggered_at DESC);
CREATE INDEX IF NOT EXISTS idx_firmware_tenant_analyzed       ON firmware (tenant_id, analyzed_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_created       ON audit_log (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_unacked         ON alerts (tenant_id, triggered_at DESC) WHERE is_acknowledged = FALSE;
