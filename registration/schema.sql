
PRAGMA journal_mode=WAL;

CREATE TABLE registrations (
    contract BLOB,
    operator BLOB NOT NULL,
    pubkey_bls BLOB NOT NULL,
    pubkey_ed25519 BLOB NOT NULL,
    sig_bls BLOB NOT NULL,
    sig_ed25519 BLOB NOT NULL,
    timestamp FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */

    CHECK(length(pubkey_ed25519) == 32),
    CHECK(length(pubkey_bls) == 64),
    CHECK(length(sig_ed25519) == 64),
    CHECK(length(sig_bls) == 128),
    CHECK(length(operator) == 20),
    CHECK(contract IS NULL OR length(contract) == 20)
);

CREATE INDEX registrations_timestamp_idx ON registrations(timestamp DESC);
CREATE INDEX registrations_operator_idx ON registrations(operator, timestamp DESC);
