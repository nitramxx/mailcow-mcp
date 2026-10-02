"""SENDING=drafts_only: no tool sends mail; messages are saved as drafts for the user to send."""

from __future__ import annotations

import pytest

from mailcow_mcp.config import ConfigError, load_app_config

from conftest import Harness, app_config, make_harness, pkce_pair


def tool_names(harness: Harness) -> dict[str, str]:
    tools = harness.session().request("tools/list", {})["tools"]
    return {t["name"]: t["description"] for t in tools}


def test_no_send_tools() -> None:
    for harness in make_harness(app_config(SENDING="drafts_only")):
        tools = tool_names(harness)
        assert "send_email" not in tools and "send_draft" not in tools
        assert {"save_draft", "delete_draft", "list_messages"} <= tools.keys()
        assert "doesn't send mail" in tools["save_draft"]
        assert "send_email" not in tools["save_draft"]  # no mention of tools that aren't there


def test_sending_is_the_default(harness: Harness) -> None:
    tools = tool_names(harness)
    assert "send_email" in tools and "send_draft" in tools
    assert "send_draft" in tools["save_draft"]


def test_instructions_and_consent_page_say_so() -> None:
    for harness in make_harness(app_config(SENDING="drafts_only")):
        initialize = harness.mcp(harness.tokens()[1]["access_token"])
        assert "doesn't send mail" in initialize.text
        client_id = harness.register()["client_id"]
        _, challenge = pkce_pair()
        page = harness.client.get(harness.authorize(client_id, challenge))
        assert "this server doesn" in page.text and "send email and save" not in page.text


def test_invalid_value() -> None:
    with pytest.raises(ConfigError) as exc:
        load_app_config(
            {
                "MODE": "generic",
                "PUBLIC_URL": "https://mcp.example.org",
                "IMAP_HOST": "imap.example.org",
                "ENC_KEY": "x",
                "TRUSTED_PROXIES": "127.0.0.1",
                "SENDING": "never",
            }
        )
    assert any(e.startswith("SENDING:") for e in exc.value.errors)
