-- Mailboxes that have connected at least once.
CREATE TABLE mailboxes (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE,
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER NOT NULL
);

-- OAuth clients from dynamic client registration (RFC 7591).
CREATE TABLE clients (
    client_id         TEXT    PRIMARY KEY,
    client_name       TEXT,
    metadata          TEXT    NOT NULL, -- JSON, without the secret
    client_secret_enc TEXT,             -- Fernet(ENC_KEY)
    registered_ip     TEXT,
    created_at        INTEGER NOT NULL,
    last_used_at      INTEGER NOT NULL
);

-- /authorize requests waiting for the user to sign in.
CREATE TABLE auth_requests (
    id_hash    TEXT    PRIMARY KEY,
    client_id  TEXT    NOT NULL REFERENCES clients ON DELETE CASCADE,
    params     TEXT    NOT NULL, -- JSON AuthorizationParams
    csrf       TEXT    NOT NULL,
    expires_at INTEGER NOT NULL
);

-- One client's access to one mailbox, created at sign-in.
CREATE TABLE grants (
    id             INTEGER PRIMARY KEY,
    client_id      TEXT    NOT NULL REFERENCES clients ON DELETE CASCADE,
    mailbox_id     INTEGER NOT NULL REFERENCES mailboxes ON DELETE CASCADE,
    login_method   TEXT    NOT NULL CHECK (login_method IN ('password', 'mailcow')),
    credential_enc TEXT    NOT NULL, -- Fernet(ENC_KEY): password or app password
    scopes         TEXT    NOT NULL, -- space-separated
    resource       TEXT    NOT NULL,
    created_at     INTEGER NOT NULL,
    last_used_at   INTEGER NOT NULL
);
CREATE INDEX grants_mailbox ON grants (mailbox_id);
CREATE INDEX grants_client ON grants (client_id);

CREATE TABLE auth_codes (
    code_hash             TEXT    PRIMARY KEY,
    grant_id              INTEGER NOT NULL REFERENCES grants ON DELETE CASCADE,
    code_challenge        TEXT    NOT NULL,
    redirect_uri          TEXT    NOT NULL,
    redirect_uri_explicit INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    used_at               INTEGER
);

-- Access and refresh tokens, stored as SHA-256 hashes.
CREATE TABLE tokens (
    token_hash TEXT    PRIMARY KEY,
    grant_id   INTEGER NOT NULL REFERENCES grants ON DELETE CASCADE,
    kind       TEXT    NOT NULL CHECK (kind IN ('access', 'refresh')),
    expires_at INTEGER NOT NULL,
    used_at    INTEGER -- refresh tokens: when rotated; reuse revokes the grant
);
CREATE INDEX tokens_grant ON tokens (grant_id);
