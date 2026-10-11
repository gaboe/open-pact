CREATE TABLE gateway_secrets (
    name text PRIMARY KEY,
    value text NOT NULL
);

CREATE TABLE devices (
    pseudonym text NOT NULL,
    manifest_hash text NOT NULL,
    owner_key jsonb NOT NULL,
    owner_signature text NOT NULL,
    salt text NOT NULL,
    enrolled_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (pseudonym, manifest_hash)
);

CREATE TABLE log_entries (
    idx bigint PRIMARY KEY CHECK (idx >= 0),
    kind text NOT NULL,
    data jsonb NOT NULL,
    prev_hash text NOT NULL,
    hash text NOT NULL UNIQUE
);

CREATE FUNCTION log_entries_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'log_entries is append-only';
END
$$;

CREATE TRIGGER log_entries_no_update_or_delete BEFORE UPDATE OR DELETE ON log_entries
    FOR EACH ROW EXECUTE FUNCTION log_entries_append_only();

CREATE TRIGGER log_entries_no_truncate BEFORE TRUNCATE ON log_entries
    FOR EACH STATEMENT EXECUTE FUNCTION log_entries_append_only();
