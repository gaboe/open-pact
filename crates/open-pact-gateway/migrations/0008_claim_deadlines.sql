-- Each claim keeps the deletion deadline of the manifest it was accepted under, so a later manifest
-- cannot extend it. New claims are sealed under the key of their deadline month. The gateway sets
-- the deadline of older rows on start from the current claim_retention.
ALTER TABLE claims ADD COLUMN delete_after timestamptz;

CREATE INDEX claims_delete_after ON claims (delete_after);
