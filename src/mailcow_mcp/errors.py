"""Errors that tools report to the client as a plain message."""

from __future__ import annotations


class MailError(Exception):
    """An anticipated failure; the message is safe to show to the client."""


class InvalidInput(MailError):
    pass


class NotFound(MailError):
    pass


class LimitExceeded(MailError):
    pass


class ServerUnavailable(MailError):
    def __init__(self, what: str = "The mail server") -> None:
        super().__init__(f"{what} can't be reached right now. Try again in a few minutes.")


class CredentialsRejected(MailError):
    """The mail server refused the stored password or app password."""

    def __init__(self) -> None:
        super().__init__(
            "The mail server no longer accepts this connection's password (it may have been "
            "changed, or the app password deleted). This connection has been signed out: "
            "reconnect the app to sign in again."
        )


class ContactsAuthFailed(MailError):
    def __init__(self) -> None:
        super().__init__("The contacts server didn't accept this mailbox's credentials.")


class SendRejected(MailError):
    """The SMTP server refused the message, e.g. by its sender ACL."""
