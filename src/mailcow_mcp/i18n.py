"""Translations for the sign-in pages (``locales/<lang>.json``)."""

from __future__ import annotations

import json
from functools import cache
from importlib import resources

from mailcow_mcp.config import LANGUAGES


@cache
def messages(lang: str) -> dict[str, str]:
    data: dict[str, str] = json.loads(
        resources.files("mailcow_mcp").joinpath("locales", f"{lang}.json").read_text("utf-8")
    )
    return data


def pick_language(accept_language: str | None, default: str) -> str:
    """The first supported language in an Accept-Language header, else ``default``."""
    if accept_language:
        ranked: list[tuple[float, int, str]] = []
        for index, item in enumerate(accept_language.split(",")):
            tag, _, params = item.strip().partition(";")
            quality = 1.0
            if params.strip().startswith("q="):
                try:
                    quality = float(params.strip()[2:])
                except ValueError:
                    continue
                if quality <= 0:
                    continue  # q=0: "not this one"
            ranked.append((-quality, index, tag.strip().lower().split("-")[0]))
        for _, _, lang in sorted(ranked):
            if lang in LANGUAGES:
                return lang
    return default


class Translator:
    def __init__(self, lang: str) -> None:
        self.lang = lang
        self._messages = messages(lang)

    def __call__(self, key: str, **values: str) -> str:
        text = self._messages[key]
        return text.format(**values) if values else text
