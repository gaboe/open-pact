-- The end of the VPN certificate that the last claim of each enrolment got. `claims list` and
-- `claims show` derive a device's standing from it when they run, so no job writes it again.
-- Null until a claim gets a certificate, and after a denied claim.
ALTER TABLE devices
    ADD COLUMN last_access_until timestamptz;
