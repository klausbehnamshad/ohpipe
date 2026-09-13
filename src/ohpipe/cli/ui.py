"""Small bilingual layer for the interactive operator questions.

The machine contract and reason codes stay language independent.  Only text
shown inside a deliberately opened terminal dialog is selected here.
"""

from __future__ import annotations

import os


ENV_UI_LANG = "OHPIPE_UI_LANG"


def is_english() -> bool:
    return os.environ.get(ENV_UI_LANG, "de").strip().lower().replace("_", "-").startswith("en")


def text(german: str, english: str) -> str:
    return english if is_english() else german


def confirmation_word() -> str:
    return "CONFIRM" if is_english() else "BESTÄTIGEN"


def confirmed(answer: str) -> bool:
    return answer.strip() == confirmation_word()
