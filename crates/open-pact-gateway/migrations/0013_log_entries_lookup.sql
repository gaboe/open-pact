-- translog::mine filters the log on one kind and one JSON field, so without these indexes every
-- lookup reads every log entry. Each index is partial on the kinds that the query names. Keep the
-- kind lists here equal to the ones in translog::mine, or the planner stops using the index.
--
-- The build holds a SHARE lock on log_entries, so appends wait until it ends. lock_timeout limits
-- how long this migration waits for that lock. If a writer holds it longer, the migration fails and
-- the gateway does not start.
SET LOCAL lock_timeout = '5s';
CREATE INDEX log_entries_commitment ON log_entries ((data->>'commitment'))
    WHERE kind IN ('device_enrolled', 'device_approved', 'device_revoked', 'manifest_accepted');
CREATE INDEX log_entries_manifest ON log_entries ((data->>'manifest'))
    WHERE kind = 'manifest_published';
