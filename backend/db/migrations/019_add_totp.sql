-- Optional TOTP multi-factor authentication (RFC 6238).
--
-- The shared secret is never stored in plaintext: it is sealed with
-- AES-256-GCM using TOTP_ENCRYPTION_KEY before it reaches the database.
-- totp_enabled stays FALSE until the user proves they can produce a valid
-- code, so a partially completed enrolment can never lock anyone out.

ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS totp_secret_enc BYTEA,
    ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;
