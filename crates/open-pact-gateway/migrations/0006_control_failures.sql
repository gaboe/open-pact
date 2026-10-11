-- When a required control of a device first failed or reported unknown. Grace runs from here.
CREATE TABLE control_failures (
    pseudonym text NOT NULL,
    manifest_hash text NOT NULL,
    control text NOT NULL,
    first_failed_at timestamptz NOT NULL,
    PRIMARY KEY (pseudonym, manifest_hash, control),
    FOREIGN KEY (pseudonym, manifest_hash) REFERENCES devices ON DELETE CASCADE
);
