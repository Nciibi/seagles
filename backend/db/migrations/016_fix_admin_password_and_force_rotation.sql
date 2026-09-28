-- Repair the seeded admin account and require a password change on first login.
--
-- THE LOCKOUT BUG
-- --------------
-- 006_create_users.sql seeds the admin account with the comment
--     -- bcrypt hash for "changeme"
-- but the hash it actually contains does not verify against "changeme", nor
-- against any other plausible password. Verified with
-- bcrypt.CompareHashAndPassword over a candidate list: no match.
--
-- Consequence: on every fresh install the documented default credentials
-- (README: "Default credentials: admin / changeme") do not work. The single
-- seeded administrator cannot log in, and because there is no other account
-- and no password-reset flow, the deployment is unusable until an operator
-- edits the database by hand. Nothing caught this because the test suite never
-- ran against a real database.
--
-- THE FIX
-- -------
-- 1. Replace the hash, but ONLY when the stored value is still the known-bad
--    one. An operator who already changed the password on a running deployment
--    must not have it silently reset.
-- 2. Add must_change_password and set it for the seeded account, so the
--    "must be changed on first login" the original comment promised is
--    actually enforced by the API rather than being advisory.

-- ---------------------------------------------------------------------------
-- 1. must_change_password
-- ---------------------------------------------------------------------------
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;

-- ---------------------------------------------------------------------------
-- 2. Repair the seeded hash, guarded on the exact bad value
-- ---------------------------------------------------------------------------
-- The known-bad hash from 006_create_users.sql.
DO $$
DECLARE
    bad_hash  CONSTANT text := '$2a$12$LJ3VBRqPpE.yCLtRpUwOZ.1FxPOMJvT5q1RkGQxJJp.HYDHh3l2Oe';
    good_hash CONSTANT text := '$2a$12$9CIzQvGa5iFJpaMY4FFPwOzpj4CZRZC54/wjm37RMat4xgNGb9mh2';
BEGIN
    UPDATE users
       SET password_hash        = good_hash,
           must_change_password = TRUE,
           updated_at            = NOW()
     WHERE username = 'admin'
       AND password_hash = bad_hash;

    IF NOT FOUND THEN
        RAISE NOTICE 'seeded admin hash was already changed; leaving it alone';
    END IF;
END
$$;

-- Any other account predating this column should also be forced to rotate,
-- since their hashes predate the cost-12 policy. Only rows explicitly created
-- with a known-good password are left alone, and there are none of those yet.
UPDATE users
   SET must_change_password = TRUE
 WHERE must_change_password = FALSE
   AND username NOT IN ('admin');
