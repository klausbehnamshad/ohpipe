"""SRT-Ingest.

Bewusst streng: eine SRT-Datei, die nicht sauber parst, wird abgelehnt statt
teilweise gelesen. Ein halb gelesenes Transkript ist die Vorstufe zu einer
content-korrelierten Lücke — und die kostet später ein ganzes Korpus.

**Die Draftgrenze (B3a).** Eine SRT trägt keine Sprache, und einen Sprecher
nur dann, wenn ein Präfix ihn nennt. `load_srt` **erfindet dafür keinen
Ersatzwert** — kein ``speaker="unknown"``, kein ``language="und"`` und kein
``language="zxx"``. Ein erfundener Wert wäre eine Aussage, die niemand
getroffen hat, und er ginge über `projection_version` und die kanonischen
Bytes unmittelbar in die Revisionsidentität ein.

Das Ergebnis ist deshalb eine **Draftfassung**: sie trägt
`src/ohpipe/domain/transcript.py::TranscriptRevision.is_identity_draft` als
``True``, und jeder identitätserzeugende Zugriff fällt fail-closed am
konkreten fehlenden Feld. Wer die Fassung bestätigen will, ergänzt die
fehlenden Werte ausdrücklich.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path

from ...domain.hashing import sha256_bytes
from ...domain.revision_serialization import PROJECTION_VERSION
from ...domain.transcript import Segment, TranscriptRevision

__all__ = ["SrtParseError", "load_srt", "parse_srt"]

# Vollzeilen-Anker (^...$) statt `search`: Müll um den Zeitcode herum ist ein
# Formatfehler, kein Rauschen. Eine frühere Fassung nahm die Zeile
# "irgendwas 00:00:01,000 --> 00:00:04,000 undnochwas" widerspruchslos an.
_TIME = re.compile(
    r"^(?P<h>\d{1,3}):(?P<m>\d{2}):(?P<s>\d{2})[,.](?P<ms>\d{1,3})"
    r"\s*-->\s*"
    r"(?P<h2>\d{1,3}):(?P<m2>\d{2}):(?P<s2>\d{2})[,.](?P<ms2>\d{1,3})"
    r"(?:\s+[Xx]1:.*)?$"  # die seltene Positionsangabe ist erlaubt, sonst nichts
)
#: "SPRECHER:" am Blockanfang. Rolle, nicht Name — der Wert wird nur als
#: Label geführt und nie interpretiert.
#: Das ``(?:\s|$)`` ist nötig, damit auch "INTERVIEWER:" ohne Folgetext als
#: Sprecherpräfix erkannt und der Block danach als leer abgelehnt wird.
_SPEAKER = re.compile(r"^\s*([A-ZÄÖÜ][\wÄÖÜäöüß .\-]{0,32}?)\s*:(?:\s|$)")


class SrtParseError(ValueError):
    pass


@dataclass
class _Block:
    index: int
    start_ms: int
    end_ms: int
    lines: list[str]


def _ms(h: str, m: str, s: str, ms: str) -> int:
    mi, se = int(m), int(s)
    if mi > 59 or se > 59:
        # "00:99:99,999" ist kein Zeitcode, sondern ein Tippfehler mit Folgen:
        # er verschiebt jede spätere Dauer- und Coverage-Rechnung.
        raise ValueError(f"ungültiger Zeitcode {h}:{m}:{s},{ms}")
    return ((int(h) * 60 + mi) * 60 + se) * 1000 + int(ms.ljust(3, "0"))


def parse_srt(text: str, *, strict: bool = True) -> list[Segment]:
    text = text.replace("\r\n", "\n").replace("\r", "\n").lstrip("﻿")
    raw_blocks = [b for b in re.split(r"\n\s*\n", text) if b.strip()]
    segments: list[Segment] = []
    problems: list[str] = []

    for n, raw in enumerate(raw_blocks, start=1):
        lines = [ln for ln in raw.split("\n") if ln.strip() != ""]
        if not lines:
            continue
        cursor = 0
        if lines[0].strip().isdigit() and len(lines) > 1:
            cursor = 1
        if cursor >= len(lines):
            problems.append(f"Block {n}: nur eine Indexzeile, kein Zeitcode")
            continue
        m = _TIME.match(lines[cursor].strip())
        if not m:
            problems.append(f"Block {n}: kein gültiger Zeitcode in {lines[cursor]!r}")
            continue
        try:
            start = _ms(m["h"], m["m"], m["s"], m["ms"])
            end = _ms(m["h2"], m["m2"], m["s2"], m["ms2"])
        except ValueError as exc:
            problems.append(f"Block {n}: {exc}")
            continue
        if end < start:
            problems.append(f"Block {n}: Ende liegt vor dem Anfang")
            continue
        body = lines[cursor + 1 :]
        if not body:
            problems.append(f"Block {n}: leerer Textkörper")
            continue

        speaker = None
        sm = _SPEAKER.match(body[0])
        if sm:
            speaker = sm.group(1).strip()
            body = [body[0][sm.end() :]] + body[1:]

        if not " ".join(body).strip():
            # Ein Block, der nach dem Sprecherpräfix nichts mehr enthält, ist
            # kein Turn. Er würde als leeres Segment in die Coverage eingehen.
            problems.append(f"Block {n}: kein Text nach dem Sprecherpräfix")
            continue

        segments.append(
            Segment(
                index=len(segments),
                start_ms=start,
                end_ms=end,
                text=" ".join(ln.strip() for ln in body).strip(),
                speaker=speaker,
            )
        )

    if problems and strict:
        head = "; ".join(problems[:5])
        more = f" (+{len(problems) - 5} weitere)" if len(problems) > 5 else ""
        raise SrtParseError(
            f"{len(problems)} unlesbare Blöcke: {head}{more}. "
            "Eine teilweise gelesene SRT wird nicht übernommen."
        )
    if not segments:
        raise SrtParseError("Keine verwertbaren Untertitelblöcke gefunden.")

    # Monotonie UND Überlappungsfreiheit. Beides ist keine Formalie:
    # überlappende Blöcke erzeugen später Coverage-Zahlen, die nichts mehr
    # messen, weil dieselbe Zeit doppelt zählt.
    for a, b in pairwise(segments):
        if b.start_ms is None or a.start_ms is None or a.end_ms is None:
            continue
        if b.start_ms < a.start_ms:
            raise SrtParseError(
                f"Zeitcodes laufen rückwärts bei Block {b.index}: "
                f"{b.start_ms} ms nach {a.start_ms} ms"
            )
        if b.start_ms < a.end_ms:
            raise SrtParseError(
                f"Blöcke {a.index} und {b.index} überlappen: "
                f"{a.end_ms} ms endet nach {b.start_ms} ms Beginn"
            )
    return segments


def load_srt(path: Path, *, strict: bool = True) -> TranscriptRevision:
    """Liest eine SRT als **Draftfassung**; erfindet keinen fehlenden Pflichtwert.

    ``projection_version`` wird ausdrücklich gesetzt. Ein tatsächlich geparster
    Sprecher wird zeichengenau übernommen; ein nicht vorliegender bleibt
    ``None``, und ``language`` bleibt ``None``. Aus dem Draft entsteht weder
    ein ``revision_sha256`` noch ein `RevisionAnchor`.
    """
    data = Path(path).read_bytes()
    segments = parse_srt(data.decode("utf-8-sig"), strict=strict)
    return TranscriptRevision.from_segments(
        segments,
        projection_version=PROJECTION_VERSION,
        source_kind="srt",
        source_sha256=sha256_bytes(data),
    )
