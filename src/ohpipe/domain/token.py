"""Zentrale B3b-Zeichen-, Token- und Labelgrenzen.

Die Regeln sind absichtlich lokal gebunden.  Weder die Python-Unicode-Version
noch eine zur Laufzeit gelesene UCD-Datei darf entscheiden, welche unsichtbaren
Zeichen unter ``unicode-default-ignorable-15.1.v1`` fallen.
"""

from __future__ import annotations

import re
import unicodedata
from bisect import bisect_right

__all__ = [
    "LABEL_RULE",
    "TOKEN_RE",
    "TOKEN_RULE",
    "InvalidLabel",
    "InvalidToken",
    "is_default_ignorable_15_1",
    "validate_label",
    "validate_model_value",
    "validate_token",
]

TOKEN_RULE = "b3b-ascii-token-v1"
LABEL_RULE = "unicode-default-ignorable-15.1.v1"
TOKEN_RE = re.compile(r"[A-Za-z0-9_.:@/+\-]{3,64}\Z")
_MODEL_RE = re.compile(r"[A-Za-z0-9_.:@/ +\-]{1,128}\Z")


class InvalidToken(ValueError):
    """Ein technischer B3b-Token ist nicht kanonisch."""


class InvalidLabel(ValueError):
    """Ein dauerhaft journalisierter Alias ist nicht sicher darstellbar."""


# DerivedCoreProperties-15.1.0, Default_Ignorable_Code_Point.  Die sortierten,
# geschlossenen Bereiche sind Produktbytes dieser Regelversion; sie werden
# nicht aus ``unicodedata`` abgeleitet.  Cf wird zusätzlich separat blockiert.
_DEFAULT_IGNORABLE_RANGES: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
_RANGE_STARTS = tuple(start for start, _ in _DEFAULT_IGNORABLE_RANGES)


def is_default_ignorable_15_1(char: str) -> bool:
    """Prueft genau einen Codepoint gegen die gebundene Unicode-15.1-Tabelle."""
    if not isinstance(char, str) or len(char) != 1:
        raise TypeError("genau ein Unicode-Codepoint erwartet")
    cp = ord(char)
    index = bisect_right(_RANGE_STARTS, cp) - 1
    return index >= 0 and cp <= _DEFAULT_IGNORABLE_RANGES[index][1]


def validate_token(value: object, *, field: str = "token") -> str:
    if not isinstance(value, str) or TOKEN_RE.fullmatch(value) is None:
        raise InvalidToken(f"{field} muss [A-Za-z0-9_.:@/+-]{{3,64}} vollstaendig entsprechen")
    return value


def validate_model_value(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _MODEL_RE.fullmatch(value) is None:
        raise InvalidToken(f"{field} muss ein sichtbarer ASCII-Wert mit 1 bis 128 Zeichen sein")
    return value


def validate_label(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise InvalidLabel("label muss 1 bis 128 Unicode-Codepoints tragen")
    if unicodedata.normalize("NFC", value) != value:
        raise InvalidLabel("label muss bereits NFC sein")
    if value.startswith(" ") or value.endswith(" ") or "  " in value:
        raise InvalidLabel(
            "label darf kein fuehrendes, folgendes oder doppeltes ASCII SPACE tragen"
        )

    has_visible_base = False
    for char in value:
        cp = ord(char)
        category = unicodedata.category(char)
        if 0xD800 <= cp <= 0xDFFF:
            raise InvalidLabel("label enthaelt einen Unicode-Surrogat")
        if category in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            raise InvalidLabel("label enthaelt ein Steuer-, Format- oder Zeilentrennzeichen")
        if is_default_ignorable_15_1(char):
            raise InvalidLabel("label enthaelt einen Default_Ignorable_Code_Point aus Unicode 15.1")
        if char != " " and char.isspace():
            raise InvalidLabel("label enthaelt Unicode-Whitespace ausser ASCII SPACE")
        has_visible_base |= category.startswith(("L", "N"))
    if not has_visible_base:
        raise InvalidLabel("label braucht mindestens eine sichtbare Unicode-L- oder N-Basis")
    return value
