-- mailcow sign-in: the OAuth state while the user is at mailcow's login page,
-- and the app password + broker capability of each mailcow grant.
ALTER TABLE auth_requests ADD COLUMN mailcow_state_hash TEXT;
CREATE INDEX auth_requests_mailcow_state ON auth_requests (mailcow_state_hash);
ALTER TABLE grants ADD COLUMN app_password_id INTEGER;
ALTER TABLE grants ADD COLUMN capability_enc TEXT;

-- App passwords to delete through the broker after their grant ended.
CREATE TABLE deprovision_queue (
    id             INTEGER PRIMARY KEY,
    mailbox        TEXT    NOT NULL,
    capability_enc TEXT    NOT NULL,
    queued_at      INTEGER NOT NULL,
    attempts       INTEGER NOT NULL DEFAULT 0,
    last_error     TEXT
);
