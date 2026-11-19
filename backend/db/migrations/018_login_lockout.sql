-- Per-account login lockout (companion to migration 017's tenant RLS).
--
-- Rate limiting by IP alone is not enough: an attacker can spread attempts
-- across IPs. This table records failed attempts per (tenant, username) and
-- locks the account for 15 minutes after 5 failures inside a 15-minute window.
-- Successful logins clear the counter.

CREATE TABLE IF NOT EXISTS public.login_attempts (
    tenant_id       uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001'::uuid,
    username        text        NOT NULL,
    failed_count    integer     NOT NULL DEFAULT 0,
    first_failed_at timestamptz NOT NULL DEFAULT NOW(),
    locked_until    timestamptz,
    PRIMARY KEY (tenant_id, username)
);

ALTER TABLE public.login_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.login_attempts FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON public.login_attempts FOR ALL
    USING (public.current_tenant_id() IS NULL OR tenant_id = public.current_tenant_id())
    WITH CHECK (public.current_tenant_id() IS NULL OR tenant_id = public.current_tenant_id());
