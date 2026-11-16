CREATE TABLE manifest_versions (
    version bigserial PRIMARY KEY,
    toml text NOT NULL,
    hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    note text NOT NULL DEFAULT '',
    active bool NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX manifest_versions_one_active ON manifest_versions (active) WHERE active;
