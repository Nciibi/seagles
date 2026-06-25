-- Users table for JWT authentication and RBAC
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'viewer')),
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create default admin account (password: changeme — must be changed on first login)
-- bcrypt hash for "changeme"
INSERT INTO users (username, email, password_hash, role)
VALUES ('admin', 'admin@ironmesh.local', '$2a$12$LJ3VBRqPpE.yCLtRpUwOZ.1FxPOMJvT5q1RkGQxJJp.HYDHh3l2Oe', 'admin')
ON CONFLICT (username) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
