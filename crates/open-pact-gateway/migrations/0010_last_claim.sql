-- The last claim decision of each enrolment, for `devices list --json`. The claims table keeps a
-- device only inside its sealed body, and a claim that breaks the disclosure contract is not stored
-- at all, so the owner's device list could not tell whether a device was working. These columns
-- hold the facts of the decision and nothing else: when it happened, how it ended, and the
-- warnings or refusal reasons the gateway answered with. Null until the device sends a claim.
ALTER TABLE devices
    ADD COLUMN last_claim_at timestamptz,
    ADD COLUMN last_result text,
    ADD COLUMN last_reasons text[];
