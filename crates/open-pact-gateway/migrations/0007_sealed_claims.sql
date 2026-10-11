-- Claims are sealed per calendar month (UTC) with a data key that is itself sealed under the KEK.
-- Deleting a month's key leaves its claims unreadable in every backup (PAPER 4.8). The gateway
-- seals rows from earlier versions on start and clears device, claim and jws.
CREATE TABLE claim_keys (
    period date PRIMARY KEY CHECK (extract(day FROM period) = 1),
    wrapped_key text NOT NULL
);

ALTER TABLE claims
    ALTER COLUMN device DROP NOT NULL,
    ALTER COLUMN claim DROP NOT NULL,
    ADD COLUMN period date REFERENCES claim_keys,
    ADD COLUMN sealed text,
    ADD CHECK ((sealed IS NULL) = (period IS NULL));

CREATE INDEX claims_received_at ON claims (received_at);
