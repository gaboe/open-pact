-- An owner who accepts a changed manifest moves the device row to the new hash. The device keeps
-- its state and salt, and its grace clocks move with it.
ALTER TABLE control_failures
    DROP CONSTRAINT control_failures_pseudonym_manifest_hash_fkey,
    ADD FOREIGN KEY (pseudonym, manifest_hash) REFERENCES devices ON DELETE CASCADE ON UPDATE CASCADE;

-- The statement the owner and the device signed to accept the current manifest. Null until then.
ALTER TABLE devices
    ADD COLUMN accept_owner_signature text,
    ADD COLUMN accept_device_signature text;
