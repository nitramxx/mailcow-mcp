-- Messages sent, for per-mailbox send limits. Kept by username so limits
-- survive reconnecting; rows older than a day are deleted.
CREATE TABLE sent_log (
    id         INTEGER PRIMARY KEY,
    mailbox    TEXT    NOT NULL,
    sent_at    INTEGER NOT NULL,
    recipients INTEGER NOT NULL
);
CREATE INDEX sent_log_mailbox ON sent_log (mailbox, sent_at);
