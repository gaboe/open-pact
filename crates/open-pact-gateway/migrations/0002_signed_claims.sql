-- Nullable because rows from 0001 are unsigned and have no decision.
ALTER TABLE claims
    ADD COLUMN jws text,
    ADD COLUMN allowed boolean;
