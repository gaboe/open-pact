-- The end of the VPN certificate that the last claim of each enrolment got. `claims list` and
-- `claims show` derive a device's standing from it when they run, so no job writes it again.
-- Null after a denied claim and for a row written before this column existed. The standing of such a
-- row is unknown until the device claims again.
ALTER TABLE devices
    ADD COLUMN last_access_until timestamptz;
