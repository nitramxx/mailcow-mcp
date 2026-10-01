-- App passwords the broker created. A capability token is valid only while
-- its row here is active.
CREATE TABLE app_passwords (
    app_password_id   INTEGER PRIMARY KEY,
    mailbox           TEXT    NOT NULL,
    name              TEXT    NOT NULL,
    created_at        INTEGER NOT NULL,
    deprovisioned_at  INTEGER
);
CREATE INDEX app_passwords_mailbox ON app_passwords (mailbox);
