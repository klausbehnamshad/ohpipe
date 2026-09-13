"""Kanonisches Hashing und Normalisierungsprofile.

Jeder Hash im System entsteht hier. Der Grund ist ADR 007: ein Anker, dessen
Bezugstext auf zwei Wegen unterschiedlich normalisiert wurde, driftet lautlos.

Ein Normalisierungsprofil ist versioniert und wird IM Artefakt mitgeführt.
Wird es geändert, ändert sich die Profil-ID — und alles, was auf dem alten
Profil beruht, wird sichtbar, statt still falsch zu werden.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from typing import Any

__all__ = [
    "NFC_STRICT",
    "PROFILES",
    "NormalizationProfile",
    "sha256_bytes",
    "sha256_json",
    "sha256_text",
    "short",
]


@dataclass(frozen=True)
class NormalizationProfile:
    """Wie Text kanonisiert wird, bevor er gehasht wird."""

    id: str
    unicode_form: str = "NFC"
    line_endings: str = "\n"
    strip_trailing_ws: bool = True
    ensure_final_newline: bool = True
    collapse_blank_runs: int = 0  # 0 = aus; sonst max. Anzahl aufeinanderfolgender Leerzeilen

    def apply(self, text: str) -> str:
        out = unicodedata.normalize(self.unicode_form, text)
        out = out.replace("\r\n", "\n").replace("\r", "\n")
        if self.strip_trailing_ws:
            out = "\n".join(line.rstrip() for line in out.split("\n"))
        if self.collapse_blank_runs:
            limit = self.collapse_blank_runs
            lines: list[str] = []
            blanks = 0
            for line in out.split("\n"):
                if line == "":
                    blanks += 1
                    if blanks > limit:
                        continue
                else:
                    blanks = 0
                lines.append(line)
            out = "\n".join(lines)
        if self.ensure_final_newline:
            out = out.rstrip("\n") + "\n"
        return out


#: Das Standardprofil. Bewusst konservativ: es verändert keine Zeichen innerhalb
#: einer Zeile außer Unicode-Normalisierung und rechtsseitigem Whitespace.
NFC_STRICT = NormalizationProfile(id="nfc-strict-v1")

PROFILES: dict[str, NormalizationProfile] = {NFC_STRICT.id: NFC_STRICT}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str, profile: NormalizationProfile = NFC_STRICT) -> str:
    """Hash über den NORMALISIERTEN Text. Nie über den Rohtext."""
    return sha256_bytes(profile.apply(text).encode("utf-8"))


def sha256_json(obj: Any) -> str:
    """Stabiler Hash über eine JSON-serialisierbare Struktur.

    ``sort_keys`` ist nicht Kosmetik: ohne sie hängt der Hash an der
    Einfügereihenfolge eines dicts — dieselbe Fehlerklasse wie der
    CSV-Zeilenreihenfolgen-Tie-Break (ADR 010).
    """
    blob = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return sha256_bytes(blob.encode("utf-8"))


def short(digest: str, n: int = 12) -> str:
    return digest[:n]
