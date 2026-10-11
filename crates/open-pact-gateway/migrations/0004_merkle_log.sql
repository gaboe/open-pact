-- The log is an RFC 9162 Merkle tree. Leaf hashes come from (kind, data), so the chain columns go.
ALTER TABLE log_entries DROP COLUMN prev_hash, DROP COLUMN hash;

CREATE TABLE log_cosignatures (
    size bigint NOT NULL CHECK (size > 0),
    root text NOT NULL,
    witness text NOT NULL,
    signature text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (size, root, witness)
);
