-- Only the SHA-256 of each code is stored. used_by is the pseudonym that consumed it.
CREATE TABLE invitations (
    hash text PRIMARY KEY,
    note text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    used_by text,
    CHECK ((used_at IS NULL) = (used_by IS NULL))
);

-- Devices enrolled before invitations existed stay approved, so an upgrade locks nobody out.
ALTER TABLE devices
    ADD COLUMN state text NOT NULL DEFAULT 'approved' CHECK (state IN ('pending', 'approved', 'revoked')),
    ADD COLUMN invitation text REFERENCES invitations (hash);
ALTER TABLE devices ALTER COLUMN state DROP DEFAULT;
