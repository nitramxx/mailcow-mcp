-- foreign_keys: off
-- A connection (grant) can reach several mailboxes: each with its own credential and,
-- in mailcow mode, its own app password and broker capability. The grant itself keeps
-- only what belongs to the OAuth client.
CREATE TABLE grant_mailboxes (
    id              INTEGER PRIMARY KEY,
    grant_id        INTEGER NOT NULL REFERENCES grants ON DELETE CASCADE,
    mailbox_id      INTEGER NOT NULL REFERENCES mailboxes ON DELETE CASCADE,
    login_method    TEXT    NOT NULL CHECK (login_method IN ('password', 'mailcow')),
    credential_enc  TEXT    NOT NULL, -- Fernet(ENC_KEY): password or app password
    app_password_id INTEGER,
    capability_enc  TEXT,
    added_at        INTEGER NOT NULL,
    UNIQUE (grant_id, mailbox_id)
);
INSERT INTO grant_mailboxes
    (grant_id, mailbox_id, login_method, credential_enc, app_password_id, capability_enc, added_at)
    SELECT id, mailbox_id, login_method, credential_enc, app_password_id, capability_enc, created_at
    FROM grants;
CREATE INDEX grant_mailboxes_mailbox ON grant_mailboxes (mailbox_id);

CREATE TABLE grants_new (
    id           INTEGER PRIMARY KEY,
    client_id    TEXT    NOT NULL REFERENCES clients ON DELETE CASCADE,
    scopes       TEXT    NOT NULL, -- space-separated
    resource     TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL
);
INSERT INTO grants_new (id, client_id, scopes, resource, created_at, last_used_at)
    SELECT id, client_id, scopes, resource, created_at, last_used_at FROM grants;
DROP TABLE grants;
ALTER TABLE grants_new RENAME TO grants;
CREATE INDEX grants_client ON grants (client_id);

-- Links from add_mailbox: open once in a browser to sign another mailbox into a grant.
CREATE TABLE connect_requests (
    id_hash            TEXT    PRIMARY KEY,
    grant_id           INTEGER NOT NULL REFERENCES grants ON DELETE CASCADE,
    csrf               TEXT    NOT NULL,
    mailcow_state_hash TEXT,
    expires_at         INTEGER NOT NULL
);
CREATE INDEX connect_requests_mailcow_state ON connect_requests (mailcow_state_hash);
CREATE INDEX connect_requests_grant ON connect_requests (grant_id);
