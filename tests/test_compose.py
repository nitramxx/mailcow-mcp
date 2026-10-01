from __future__ import annotations

import base64
from email.message import EmailMessage
from email.policy import default as default_policy

import pytest

from mailcow_mcp.compose import (
    FileAttachment,
    Outgoing,
    compose,
    markdown_to_html,
    normalize_address,
    normalize_message_id,
    parse_address,
    render_pdf,
)
from mailcow_mcp.errors import InvalidInput, LimitExceeded
from mailcow_mcp.mime import (
    check_attachment,
    find_part,
    is_attachment,
    parse_message,
    part_bytes,
    safe_filename,
    sniff,
    walk_parts,
)

MB = 1024 * 1024


def build(**fields: object) -> Outgoing:
    values: dict[str, object] = {"to": ["bob@example.org"], "subject": "Hi", "body_text": "Hello"}
    values.update(fields)
    return Outgoing(**values)  # type: ignore[arg-type]


class TestAddresses:
    @pytest.mark.parametrize(
        ("value", "name", "addr"),
        [
            ("bob@example.org", "", "bob@example.org"),
            ("Bob <Bob@Example.ORG>", "Bob", "Bob@example.org"),
            ('"Novák, Jan" <jan@příklad.cz>', "Novák, Jan", "jan@xn--pklad-zsa96e.cz"),
        ],
    )
    def test_valid(self, value: str, name: str, addr: str) -> None:
        parsed = parse_address(value, "to")
        assert (parsed.display_name, parsed.addr_spec) == (name, addr)

    @pytest.mark.parametrize(
        "value",
        [
            "bob",
            "bob@",
            "@example.org",
            "a@b@example.org",
            "bob@example.org, eve@example.org",
            "bob@example.org\r\nBcc: eve@example.org",
            "bob@localhost",
            "b..ob@example.org",
            "žluť@example.org",
        ],
    )
    def test_invalid(self, value: str) -> None:
        with pytest.raises(InvalidInput):
            parse_address(value, "to")

    def test_normalize_address(self) -> None:
        assert normalize_address("x@EXAMPLE.org") == "x@example.org"
        assert normalize_address("x") is None

    def test_message_id(self) -> None:
        assert normalize_message_id("abc@example.org") == "<abc@example.org>"
        assert normalize_message_id("<abc@example.org>") == "<abc@example.org>"
        for bad in ["abc", "<a b@c>", "<abc@example.org>\r\nX: y"]:
            with pytest.raises(InvalidInput):
                normalize_message_id(bad)


class TestCompose:
    def test_plain_message(self) -> None:
        composed = compose(build(), username="alice@example.org", max_message_bytes=MB)
        message = parse_message(composed.as_bytes())
        assert message["From"] == "alice@example.org"
        assert message["To"] == "bob@example.org"
        assert message["Message-ID"] == composed.message_id
        assert composed.message_id.endswith("@example.org>")
        assert message["Date"]
        assert message.get_content_type() == "text/plain"
        assert composed.envelope_from == "alice@example.org"

    def test_bcc_only_in_copy(self) -> None:
        composed = compose(
            build(cc=["c@example.org"], bcc=["Secret <s@example.org>", "bob@example.org"]),
            username="alice@example.org",
            max_message_bytes=MB,
        )
        assert composed.recipients == ["bob@example.org", "c@example.org", "s@example.org"]
        assert b"s@example.org" not in composed.as_bytes()
        assert (
            parse_message(composed.copy_with_bcc)["Bcc"]
            == "Secret <s@example.org>, bob@example.org"
        )

    def test_markdown_alternative(self) -> None:
        composed = compose(
            build(body_text=None, body_markdown="**hi** <img src=x onerror=alert(1)>"),
            username="alice@example.org",
            max_message_bytes=MB,
        )
        message = parse_message(composed.as_bytes())
        assert message.get_content_type() == "multipart/alternative"
        html = message.get_body(("html",))
        assert html is not None
        assert "<strong>hi</strong>" in html.get_content()
        assert "<img" not in html.get_content()
        assert "&lt;img" in html.get_content()

    def test_reply_headers(self) -> None:
        composed = compose(
            build(in_reply_to="b@x.org", references=["<a@x.org>", "junk", "<b@x.org>"]),
            username="alice@example.org",
            max_message_bytes=MB,
        )
        message = parse_message(composed.as_bytes())
        assert message["In-Reply-To"] == "<b@x.org>"
        assert message["References"] == "<a@x.org> <b@x.org>"

    def test_non_ascii_headers_are_encoded(self) -> None:
        composed = compose(
            build(subject="Příliš žluťoučký kůň", from_name="Jan Novák"),
            username="jan@example.org",
            max_message_bytes=MB,
        )
        raw = composed.as_bytes()
        assert b"=?utf-8?" in raw
        message = parse_message(raw)
        assert message["Subject"] == "Příliš žluťoučký kůň"
        assert message["From"] == "Jan Novák <jan@example.org>"

    def test_attachments(self) -> None:
        composed = compose(
            build(attachments=[FileAttachment("a.txt", "text/plain", b"hello")]),
            username="alice@example.org",
            max_message_bytes=MB,
        )
        message = parse_message(composed.as_bytes())
        (attachment,) = list(message.iter_attachments())
        assert attachment.get_filename() == "a.txt"

    @pytest.mark.parametrize(
        ("fields", "error"),
        [
            ({"to": []}, InvalidInput),
            ({"to": [f"u{i}@example.org" for i in range(51)]}, LimitExceeded),
            ({"subject": "x\ny"}, InvalidInput),
            ({"subject": "x" * 501}, InvalidInput),
            ({"from_name": "x\r"}, InvalidInput),
            ({"body_markdown": "also"}, InvalidInput),
            ({"body_text": None}, InvalidInput),
            ({"body_text": "x" * 1_000_001}, LimitExceeded),
            ({"from_address": "not an address"}, InvalidInput),
            (
                {
                    "attachments": [
                        FileAttachment(f"{i}.txt", "text/plain", b"x") for i in range(11)
                    ]
                },
                LimitExceeded,
            ),
            (
                {"attachments": [FileAttachment("big.bin", "application/octet-stream", b"x" * MB)]},
                LimitExceeded,
            ),
        ],
    )
    def test_rejects(self, fields: dict[str, object], error: type[Exception]) -> None:
        with pytest.raises(error):
            compose(build(**fields), username="alice@example.org", max_message_bytes=MB)


class TestRendering:
    def test_markdown_is_sanitized(self) -> None:
        html = markdown_to_html(
            "[x](javascript:alert(1)) [y](https://ok.example) <script>bad()</script>\n\n![i](https://t.example/p.png)"
        )
        assert 'href="javascript:' not in html
        assert 'href="https://ok.example"' in html
        assert 'rel="noopener noreferrer"' in html
        assert "<script>" not in html
        assert "<img" not in html

    def test_tables(self) -> None:
        assert "<table>" in markdown_to_html("| a | b |\n|---|---|\n| 1 | 2 |")

    def test_pdf(self) -> None:
        pdf = render_pdf("# Příliš žluťoučký kůň\n\n- one\n- two", "Title")
        assert pdf.startswith(b"%PDF-")

    def test_pdf_never_fetches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import urllib.request

        def refuse(*args: object, **kwargs: object) -> None:
            raise AssertionError("network access during PDF rendering")

        monkeypatch.setattr(urllib.request, "urlopen", refuse)
        monkeypatch.setattr(urllib.request.OpenerDirector, "open", refuse)
        pdf = render_pdf("![x](http://169.254.169.254/latest/meta-data)\n\ntext", None)
        assert pdf.startswith(b"%PDF-")


PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)


class TestMime:
    def test_sniff(self) -> None:
        assert sniff(b"%PDF-1.7") == "application/pdf"
        assert sniff(PNG) == "image/png"
        assert sniff(b"RIFF\x00\x00\x00\x00WEBPVP8 ") == "image/webp"
        assert sniff(b"MZ\x90\x00") == "application/x-msdownload"
        assert sniff(b"hello") is None

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("../../etc/passwd", "passwd"),
            ("C:\\Users\\x\\report.pdf", "report.pdf"),
            ('a<b>:"c|?*.txt', "abc.txt"),
            ("  .hidden  ", "hidden"),
            ("", "attachment"),
            ("\x00\x01", "attachment"),
            ("x" * 200 + ".pdf", "x" * 146 + ".pdf"),
        ],
    )
    def test_safe_filename(self, name: str, expected: str) -> None:
        assert safe_filename(name) == expected

    def test_check_attachment(self) -> None:
        assert check_attachment("p.png", PNG, "image/png") == ("p.png", "image/png")
        assert check_attachment("p", PNG, None) == ("p", "image/png")
        assert check_attachment("x.bin", PNG, "application/octet-stream") == (
            "x.bin",
            "application/octet-stream",
        )
        assert check_attachment("a.txt", b"hello", "text/plain") == ("a.txt", "text/plain")
        for name, data, mime in [
            ("p.pdf", PNG, "application/pdf"),
            ("p.png", b"not png", "image/png"),
            ("p.txt", PNG, "text/plain"),
            ("setup.EXE", b"x", "application/octet-stream"),
            ("innocent.pdf", b"MZ\x90", None),
            ("x", b"x", "not a type"),
        ]:
            with pytest.raises(InvalidInput):
                check_attachment(name, data, mime)

    def test_part_numbering(self) -> None:
        message = EmailMessage(policy=default_policy)
        message.set_content("text")
        message.add_alternative("<p>html</p>", subtype="html")
        message.add_attachment(
            b"data", maintype="application", subtype="octet-stream", filename="a.bin"
        )
        inner = EmailMessage(policy=default_policy)
        inner["Subject"] = "inner"
        inner.set_content("inner body")
        message.add_attachment(inner)
        parts = walk_parts(parse_message(message.as_bytes()))
        assert [n for n, _ in parts] == ["1.1", "1.2", "2", "3"]
        attachments = [n for n, p in parts if is_attachment(p)]
        assert attachments == ["2", "3"]
        parsed = parse_message(message.as_bytes())
        assert part_bytes(find_part(parsed, "2")) == b"data"
        assert b"inner body" in part_bytes(find_part(parsed, "3"))

    def test_single_part_message(self) -> None:
        message = EmailMessage(policy=default_policy)
        message.set_content("only")
        assert [n for n, _ in walk_parts(message)] == ["1"]
