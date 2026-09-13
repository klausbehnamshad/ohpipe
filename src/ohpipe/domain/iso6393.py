"""Kanonische ISO-639-3-Snapshotwerte ohne fest verdrahtete Release."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .token import validate_token

__all__ = ["IsoSnapshot", "IsoSnapshotError", "parse_iso6393_snapshot"]


class IsoSnapshotError(ValueError):
    pass


@dataclass(frozen=True)
class IsoSnapshot:
    release_id: str
    reference: str
    raw_bytes: bytes
    canonical_bytes: bytes
    source_sha256: str
    vocabulary_sha256: str
    codes: tuple[str, ...]

    def contains(self, language: str) -> bool:
        return language in self.codes


def parse_iso6393_snapshot(raw: bytes, *, release_id: str, reference: str) -> IsoSnapshot:
    release = validate_token(release_id, field="release_id")
    ref = validate_token(reference, field="reference")
    if raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw or not raw.endswith(b"\n"):
        raise IsoSnapshotError("Snapshot muss UTF-8 ohne BOM/CR sein und mit genau einem LF enden")
    if raw.endswith(b"\n\n"):
        raise IsoSnapshotError("Snapshot darf keine Leerzeile tragen")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IsoSnapshotError("Snapshot ist nicht UTF-8") from exc
    rows = text[:-1].split("\n")
    if not rows or any(not row for row in rows):
        raise IsoSnapshotError("Snapshot braucht mindestens eine nichtleere Codezeile")
    if len(rows) != len(set(rows)):
        raise IsoSnapshotError("doppelte ISO-Zeile vor Mengenbildung")
    if any(
        len(code) != 3 or not code.isascii() or not code.islower() or not code.isalpha()
        for code in rows
    ):
        raise IsoSnapshotError("jeder ISO-Code muss aus genau drei ASCII-Kleinbuchstaben bestehen")
    if not {"und", "zxx"}.issubset(rows):
        raise IsoSnapshotError("Snapshot muss und und zxx ausdruecklich enthalten")
    canonical = "".join(f"{code}\n" for code in sorted(rows)).encode("ascii")
    return IsoSnapshot(
        release_id=release,
        reference=ref,
        raw_bytes=raw,
        canonical_bytes=canonical,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        vocabulary_sha256=hashlib.sha256(canonical).hexdigest(),
        codes=tuple(sorted(rows)),
    )
