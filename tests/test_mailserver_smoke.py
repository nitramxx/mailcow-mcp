import pytest

from mailserver_fixture import ALICE, MailServer

pytestmark = pytest.mark.integration


def test_mailserver_has_special_use_folders(mailserver: MailServer) -> None:
    conn = mailserver.imap(ALICE)
    _, folders = conn.list()
    names = b"\n".join(f for f in folders if isinstance(f, bytes))
    for flag in (rb"\Sent", rb"\Drafts", rb"\Junk", rb"\Trash"):
        assert flag in names
    conn.logout()
