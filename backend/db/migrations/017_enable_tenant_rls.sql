-- Runtime tenant isolation (companion to 015_add_tenant_scoping.sql).
--
-- 015 created the tenant columns, composite keys and indexes but deliberately
-- did not enable RLS, because there was no request-scoped tenant context yet.
-- This migration enables it.
--
-- POLICY SEMANTICS
-- ----------------
--   * When the app has set app.tenant_id on the current connection, every row
--     is restricted to that tenant for both reads (USING) and writes
--     (WITH CHECK). A write that forgets tenant_id fails instead of silently
--     landing in the default tenant.
--   * When app.tenant_id is unset (background workers, migration tooling,
--     ad-hoc SQL), the policy is permissive. Those paths set tenant_id
--     explicitly in their queries; the transitional DEFAULT was kept so this
--     remains backward compatible.
--
-- FORCE ROW LEVEL SECURITY matters: without it the table owner (the account
-- the application connects as in development) bypasses RLS entirely.

CREATE OR REPLACE FUNCTION public.current_tenant_id() RETURNS uuid AS $$
    SELECT CASE
        WHEN current_setting('app.tenant_id', true) IS NULL
          OR current_setting('app.tenant_id', true) = '' THEN NULL
        ELSE current_setting('app.tenant_id', true)::uuid
    END
$$ LANGUAGE sql STABLE;

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

        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON public.%I', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON public.%I FOR ALL ' ||
            'USING (public.current_tenant_id() IS NULL OR tenant_id = public.current_tenant_id()) ' ||
            'WITH CHECK (public.current_tenant_id() IS NULL OR tenant_id = public.current_tenant_id())',
            t);
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    END LOOP;
END
$$;
