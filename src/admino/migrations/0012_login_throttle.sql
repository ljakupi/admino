-- 0012_login_throttle.sql
-- Failed-attempt counters of the brute-force protection (GH-157).
-- admino.login_throttle counts failed logins per account and per client IP
-- address, so a progressive delay and a temporary lockout survive a restart.
-- The password reset and invitation link endpoints share the IP counter.
--
-- One row per (scope, subject):
-- - scope 'account': subject = sha256(convert_to(lower(<typed email>), 'UTF8')),
--   computed by PostgreSQL with the same lower() as the login lookup and the
--   users_email_lower_key index. An unknown email gets a row like a known one
--   (no user enumeration), so there is no foreign key to users.
-- - scope 'ip': subject = a SHA-256 digest of the IPv4 address, or of the /64
--   network of an IPv6 address (admino.login_throttle.ip_subject).
-- - failures: the failed attempts counted in the current window, in-flight
--   attempts included (each attempt reserves one before its check).
-- - window_started_at: the start of the 15-minute failure window.
-- - locked_until: the end of a lockout, NULL when the subject was never locked
--   in this window.
-- - expires_at: when the row stops having any effect,
--   max(window_started_at + 15 minutes, locked_until). The hourly purge
--   deletes rows with expires_at <= now(); the last CHECK means it can never
--   remove a live lock.
--
-- No email and no IP text: only digests and counts. The digests are unsalted,
-- so they are pseudonymous, not anonymous: whoever can read this table can
-- recover a digest's email or IPv4 address by guessing it. Rows are purged
-- soon after their last effect. No column has a default: the app sets every
-- value from its own clock. Nothing else changes (the audit action catalog
-- already holds login.lockout).

CREATE TABLE login_throttle (
    scope             TEXT        NOT NULL CHECK (scope IN ('account', 'ip')),
    subject           BYTEA       NOT NULL CHECK (octet_length(subject) = 32),
    failures          INTEGER     NOT NULL CHECK (failures >= 0),
    window_started_at TIMESTAMPTZ NOT NULL,
    locked_until      TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scope, subject),
    CHECK (expires_at > window_started_at),
    CHECK (locked_until IS NULL OR expires_at >= locked_until)
);

-- The purge deletes by expiry.
CREATE INDEX login_throttle_expires_at_idx ON login_throttle (expires_at);
