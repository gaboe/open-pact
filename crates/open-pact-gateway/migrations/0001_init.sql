CREATE TABLE nonces (
    nonce text PRIMARY KEY,
    expires_at timestamptz NOT NULL
);

CREATE TABLE claims (
    id bigserial PRIMARY KEY,
    device text NOT NULL,
    claim jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now()
);
