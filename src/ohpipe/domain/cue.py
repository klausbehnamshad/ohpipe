"""Cue-Dokumente — verlustfrei, nicht rekonstruiert.

Dieses Modul hat genau eine Aufgabe, und sie ist eine Sicherheitsaufgabe:

    Nur der gesprochene Text verlässt das Dokument in Richtung Erkennung.
    Alles andere kommt unverändert zurück.

Das ist keine Parserkonvention (ADR 0024 §1). ``private_date`` ist eine
erkannte PII-Klasse. Geht ein vollständiger Cue in die Erkennung, wird
``00:12:03.000`` als Datum erkannt und ersetzt — und das Transkript verliert
seine Synchronisation zum Audio, ohne dass irgendetwas rot wird. Eine
numerische Cue-ID sieht für jeden Erkenner aus wie eine Telefon- oder
Kontonummer.

**Der Fehler geht auch in die andere Richtung**, und der ist schlimmer: Wird
gesprochener Text fälschlich als Struktur erkannt, entzieht ihn das der
Erkennung vollständig. Ein Klarname in einer Zeile, die zufällig ``-->``
enthält, käme nie bei einem Erkenner an. Deshalb wird eine Zeitzeile über
einen **vollständigen Formatabgleich mit Wertebereichen** erkannt und nicht
über das Vorkommen eines Pfeils.

**Was zugesichert wird, genau.** ``parse``/``render`` arbeiten auf ``str`` und
sichern **Zeichenidentität** zu. Wer Bytegleichheit braucht — und das ist der
Normalfall, sobald gehasht wird —, nimmt ``parse_bytes``/``render_bytes``:
strikt UTF-8, keine Ersetzungszeichen, dieselben Bytes zurück.

**Warum nicht der vorhandene SRT-Parser.** ``adapters/input/srt.py`` ist für
semantischen Ingest gebaut und genau richtig dafür: Er normalisiert
Zeilenenden, entfernt das BOM, verwirft Leerzeilen und verbindet Textzeilen zu
einem Segment. Für einen verlustfreien Roundtrip ist jede einzelne dieser
Leistungen ein Datenverlust. Beide Parser bleiben nebeneinander stehen; dieser
hier weiß nichts über Sprecher, Millisekunden oder Segmente.

**Wie die Verlustfreiheit erreicht wird.** Das Dokument merkt sich den
Originaltext und ausschließlich die *Positionen* der Payloadbereiche. Es baut
sich nie aus normalisierten Einzelteilen wieder zusammen.

Was als **Struktur** gilt und den Payload nie erreicht: BOM, ``WEBVTT``-Kopf
samt Kopfmetadaten, ``NOTE``-, ``STYLE``- und ``REGION``-Blöcke, Cue-Kennung,
Zeitzeile, Cue-Settings und jede Leerzeile.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from enum import Enum

__all__ = [
    "CueDocument",
    "CueFormat",
    "CueParseError",
    "CueStructureChanged",
    "PayloadSpan",
    "is_timing_line",
]

BOM = "﻿"
ARROW = "-->"

#: Zeichen, die ``str.splitlines()`` als Zeilengrenze behandelt — zusätzlich zu
#: ``\n`` und ``\r``. Sie dürfen in keinem Ersatztext stehen: Der nachgelagerte
#: SRT-Ingest und jede Python-Textverarbeitung machen daraus eine neue Zeile,
#: und damit wäre über den Umweg doch Struktur entstanden.
LINE_BREAKING = "\v\f\x1c\x1d\x1e\x85  "

#: SRT: Stunden verbindlich, Trennzeichen ``,`` oder ``.`` (viele Werkzeuge
#: schreiben den Punkt), optionale Positionsangabe.
#:
#: ACHTUNG: Diese Grammatik ist **strenger** als die in
#: ``adapters/input/srt.py``. Fünf Formen nimmt der Ingest an und dieser
#: Parser nicht (einstellige Stunde, ein- und zweistellige Millisekunden,
#: Pfeil ohne bzw. mit mehrfachen Leerzeichen). Folge: Eine Datei, die
#: erfolgreich ingestiert wurde, kann später nicht pseudonymisiert werden —
#: der Record wäre blockiert. Festgenagelt in
#: ``tests/test_cue.py::test_the_divergence_from_the_existing_srt_ingest_is_pinned``.
#: Offene Entscheidung: gemeinsamer Zeitzeilenparser oder strengere Form als
#: kanonischer Vertrag.
_SRT_TIME = re.compile(
    r"^(?P<h1>\d{2,3}):(?P<m1>[0-5]\d):(?P<s1>[0-5]\d)[,.](?P<ms1>\d{3})"
    r" --> "
    r"(?P<h2>\d{2,3}):(?P<m2>[0-5]\d):(?P<s2>[0-5]\d)[,.](?P<ms2>\d{3})"
    r"(?:\s+[Xx]1:.*)?$"
)

#: WebVTT: Stunden optional, Trennzeichen ``.``, danach optionale Cue-Settings.
_VTT_TIME = re.compile(
    r"^(?:(?P<h1>\d{2,}):)?(?P<m1>[0-5]\d):(?P<s1>[0-5]\d)\.(?P<ms1>\d{3})"
    r" --> "
    r"(?:(?P<h2>\d{2,}):)?(?P<m2>[0-5]\d):(?P<s2>[0-5]\d)\.(?P<ms2>\d{3})"
    r"(?P<settings>\s+\S.*)?$"
)

_HEADER = re.compile(r"^WEBVTT(?:[ \t].*)?$")


class CueFormat(str, Enum):
    SRT = "srt"
    VTT = "vtt"


class CueParseError(ValueError):
    """Die Eingabe ist kein wohlgeformtes Cue-Dokument.

    Fail-closed wie beim SRT-Ingest: Ein halb gelesenes Transkript ist die
    Vorstufe zu einer inhaltskorrelierten Lücke.
    """


class CueStructureChanged(ValueError):
    """Eine Ersetzung oder Konstruktion hätte die Struktur verändert.

    Der gefährlichste Fall ist nicht der offensichtliche: Eine Leerzeile im
    Ersatztext erzeugt eine neue Cue-Grenze, und ab dort verschiebt sich jede
    Zuordnung von Text zu Zeitcode.
    """


@dataclass(frozen=True)
class PayloadSpan:
    """Wo im Originaltext der gesprochene Text eines Cues steht.

    ``end`` liegt **vor** dem Zeilenende der letzten Textzeile. Andernfalls
    würde ein Ersatztext ohne abschließenden Zeilenumbruch die Cue-Trennung
    verschlucken.
    """

    cue_index: int
    start: int
    end: int


def _ms(h: str | None, m: str, s: str, ms: str) -> int:
    return int(h or 0) * 3_600_000 + int(m) * 60_000 + int(s) * 1000 + int(ms)


def is_timing_line(line: str, fmt: CueFormat) -> bool:
    """Ist das eine Zeitzeile — vollständig, nicht „enthält einen Pfeil"?

    Die Vorgängerfassung prüfte ``"-->" in line``. Damit galt
    ``kein zeitcode --> trotzdem struktur`` als Zeitzeile, und die Zeile
    darunter wurde zum Payload eines Cues, das es nicht gibt. Schlimmer noch:
    Echter gesprochener Text konnte so als Struktur klassifiziert und damit
    der Erkennung **vollständig entzogen** werden.

    Geprüft werden deshalb Format *und* Wertebereiche — und dass das Ende
    nicht vor dem Beginn liegt.
    """
    m = (_SRT_TIME if fmt is CueFormat.SRT else _VTT_TIME).match(line)
    if m is None:
        return False
    g = m.groupdict()
    beginn = _ms(g.get("h1"), g["m1"], g["s1"], g["ms1"])
    ende = _ms(g.get("h2"), g["m2"], g["s2"], g["ms2"])
    return ende >= beginn


def _lines(text: str) -> list[tuple[int, int, str]]:
    """``(start, end, inhalt)`` je Zeile; ``end`` ohne Zeilenende.

    Bewusst von Hand statt ``splitlines()``: Das hier muss ``\\r\\n`` von
    ``\\n`` unterscheiden können und absolute Offsets liefern, und es darf
    ``\\v``, ``\\f`` oder ``\\u2028`` NICHT als Zeilenende behandeln — sonst
    wäre ein Dokument nach dem Roundtrip an einer Stelle anders, an der
    niemand nachsieht.
    """
    out: list[tuple[int, int, str]] = []
    i, n = 0, len(text)
    while i < n:
        j = text.find("\n", i)
        if j == -1:
            out.append((i, n, text[i:n]))
            break
        end = j - 1 if j > i and text[j - 1] == "\r" else j
        out.append((i, end, text[i:end]))
        i = j + 1
    return out


def _terminators(payload: str) -> tuple[str, ...]:
    """Die Zeilenenden INNERHALB eines Payloads, in Reihenfolge."""
    out: list[str] = []
    i = 0
    while (j := payload.find("\n", i)) != -1:
        out.append("\r\n" if j > 0 and payload[j - 1] == "\r" else "\n")
        i = j + 1
    return tuple(out)


def _lone_cr(text: str) -> bool:
    """Ein ``\\r``, das nicht Teil eines ``\\r\\n`` ist.

    Es passierte die Terminatorprüfung, weil die nur ``\\n`` zählt — und der
    nachgelagerte SRT-Ingest macht daraus später eine neue Zeile. Über diesen
    Umweg wäre doch Struktur entstanden.
    """
    return any(
        c == "\r" and (i + 1 >= len(text) or text[i + 1] != "\n") for i, c in enumerate(text)
    )


def _check_payload(i: int, alt: str, ersatz: object) -> None:
    """Die Strukturbarriere. Gilt für ``with_payloads`` UND den Konstruktor.

    Bewusst NICHT geprüft wird ``-->`` im Ersatztext. Ein Pfeil innerhalb
    eines bestehenden Payloadbereichs erzeugt keine Cue-Grenze — die Grenzen
    liegen an festen Positionen, und die Zeilenstruktur ist unveränderlich.
    Die pauschale Ablehnung machte den zugesagten Identitätsroundtrip für
    legitimen Text unmöglich: ``doc.with_payloads(doc.payloads())`` scheiterte
    an einem Cue, in dem jemand „von A --> B" gesagt hatte.
    """
    if not isinstance(ersatz, str):
        raise CueStructureChanged(f"Cue {i}: Ersatz ist kein Text ({type(ersatz)}).")
    if BOM in ersatz:
        raise CueStructureChanged(f"Cue {i}: Ersatz enthält ein BOM.")
    if _lone_cr(ersatz):
        raise CueStructureChanged(
            f"Cue {i}: Ersatz enthält ein alleinstehendes CR. Der nachgelagerte Ingest "
            "macht daraus eine neue Zeile — und damit eine Struktur, die hier nicht "
            "entstehen darf."
        )
    if schlimm := set(ersatz) & set(LINE_BREAKING):
        raise CueStructureChanged(
            f"Cue {i}: Ersatz enthält zeilentrennende Steuerzeichen "
            f"({', '.join(repr(c) for c in sorted(schlimm))})."
        )
    if _terminators(ersatz) != _terminators(alt):
        raise CueStructureChanged(
            f"Cue {i}: Zeilenstruktur weicht ab — erwartet {_terminators(alt)}, "
            f"bekam {_terminators(ersatz)}. Eine zusätzliche Zeile ist eine neue "
            "Cue-Grenze, eine fehlende verliert gesprochenen Text."
        )
    if any(not zeile.strip() for zeile in ersatz.split("\n")):
        raise CueStructureChanged(
            f"Cue {i}: Ersatz enthält eine leere Zeile — das wäre eine neue Cue-Grenze."
        )


@dataclass(frozen=True)
class CueDocument:
    """Ein SRT-/WebVTT-Dokument, dessen Struktur unantastbar ist.

    **Der Konstruktor ist keine Hintertür.** Er parst ``source`` erneut und
    lehnt jede Spanmenge ab, die nicht die kanonische ist. Ohne das könnte ein
    Aufrufer die Zeitzeile als Payload markieren und ersetzen lassen — mit
    genau dem Ergebnis, gegen das dieses Modul gebaut ist. Das erneute Parsen
    kostet einen linearen Durchlauf; für ein Transkript ist das nichts, und
    eine Strukturgrenze, die man umgehen kann, ist keine.
    """

    source: str
    fmt: CueFormat
    spans: tuple[PayloadSpan, ...]
    _payloads: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "fmt", CueFormat(self.fmt))
        kanonisch = tuple(_parse(self.source, self.fmt))
        if tuple(self.spans) != kanonisch:
            raise CueStructureChanged(
                "Die angegebenen Payloadbereiche sind nicht die des Dokuments. "
                "Kanonische Bereiche entstehen ausschließlich beim Parsen — sonst "
                "ließe sich Struktur als gesprochener Text ausgeben."
            )
        object.__setattr__(self, "spans", kanonisch)
        original = tuple(self.source[s.start : s.end] for s in kanonisch)
        if not self._payloads:
            object.__setattr__(self, "_payloads", original)
            return
        if len(self._payloads) != len(kanonisch):
            raise CueStructureChanged(f"{len(self._payloads)} Payloads für {len(kanonisch)} Cues.")
        for i, (alt, neu) in enumerate(zip(original, self._payloads, strict=True)):
            _check_payload(i, alt, neu)

    # ------------------------------------------------------------- lesen

    @classmethod
    def parse(cls, text: str, fmt: CueFormat) -> CueDocument:
        """Zeichenidentität. Für Bytegleichheit :meth:`parse_bytes` nehmen."""
        fmt = CueFormat(fmt)
        return cls(source=text, fmt=fmt, spans=tuple(_parse(text, fmt)))

    @classmethod
    def parse_bytes(cls, data: bytes, fmt: CueFormat) -> CueDocument:
        """Strikt UTF-8. ``render_bytes()`` liefert dieselben Bytes zurück.

        Strikt heißt: kein ``errors="replace"``. Ein Ersetzungszeichen wäre
        eine stille Änderung am Transkript, und der Hash wäre der eines
        Dokuments, das so nie existiert hat.
        """
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CueParseError(
                f"Die Datei ist nicht UTF-8 ({exc}). Eine Umkodierung mit Ersetzungszeichen "
                "wäre eine stille Änderung am Transkript."
            ) from exc
        return cls.parse(text, fmt)

    def payloads(self) -> tuple[str, ...]:
        """Ausschließlich der gesprochene Text — das einzige, was an einen
        Erkenner gehen darf."""
        return self._payloads

    # ---------------------------------------------------------- ersetzen

    def with_payloads(self, payloads: object) -> CueDocument:
        """Ersetzt Payloads. Struktur bleibt, was sie war.

        Geprüft wird VOR der Übernahme, nicht beim Rendern: Anzahl, keine neue
        Cue-Grenze, kein alleinstehendes CR, keine zeilentrennenden
        Steuerzeichen, gleiche Zeilenstruktur.
        """
        if isinstance(payloads, str) or not hasattr(payloads, "__iter__"):
            raise CueStructureChanged("payloads muss eine Folge von Zeichenketten sein.")
        neu = tuple(payloads)
        if len(neu) != len(self.spans):
            raise CueStructureChanged(
                f"{len(neu)} Ersatztexte für {len(self.spans)} Cues — Anzahl muss passen."
            )
        for i, (alt, ersatz) in enumerate(zip(self._payloads, neu, strict=True)):
            _check_payload(i, alt, ersatz)
        return replace(self, _payloads=neu)

    def render(self) -> str:
        """Der Originaltext mit eingesetzten Payloads.

        Von hinten nach vorn, damit die noch nicht angewandten Offsets gültig
        bleiben. Wurde nichts ersetzt, ist das Ergebnis Zeichen für Zeichen die
        Eingabe.
        """
        out = self.source
        for span, payload in sorted(
            zip(self.spans, self._payloads, strict=True),
            key=lambda paar: paar[0].start,
            reverse=True,
        ):
            out = out[: span.start] + payload + out[span.end :]
        return out

    @property
    def sha256(self) -> str:
        """Der Hash des Dokuments in seiner AKTUELLEN Fassung.

        Nach einer Ersetzung ist er ein anderer — genau deshalb bindet eine
        Spanmenge an ihn: Wer zwischendurch ersetzt hat, bekommt die alten
        Spans nicht mehr gebunden.
        """
        return hashlib.sha256(self.render_bytes()).hexdigest()

    def payload_sha256(self, cue_index: int) -> str:
        """Der Hash EINES Payloads — die lokale Integritätsprüfung eines Spans.

        **Keine Erlaubnis zur inkrementellen Wiederverwendung.** Eine
        Spanmenge bindet zuerst an den vollständigen Dokumenthash, und das mit
        Absicht: Sie ist eine Vollständigkeitsbehauptung über das Dokument.
        Änderte sich Cue 7, dürfte ein alter Erkennungslauf für Cue 3 nicht
        weitergelten — der geänderte Cue kann neue PII enthalten, die nie
        jemand gesucht hat. Der Payloadhash kommt zusätzlich, nicht statt.
        """
        return hashlib.sha256(self._payloads[cue_index].encode("utf-8")).hexdigest()

    def render_bytes(self) -> bytes:
        """UTF-8. Bei unverändertem Dokument aus :meth:`parse_bytes` sind das
        exakt die eingelesenen Bytes."""
        return self.render().encode("utf-8")


# ---------------------------------------------------------------- Parser


def _parse(text: str, fmt: CueFormat) -> list[PayloadSpan]:
    return _parse_vtt(text) if fmt is CueFormat.VTT else _parse_srt(text)


def _payload_block(
    zeilen: list[tuple[int, int, str]], i: int, cue_index: int
) -> tuple[PayloadSpan, int]:
    """Sammelt die Textzeilen ab ``i`` bis zur Leerzeile oder zum Dateiende.

    Hier gibt es keine Strukturerkennung mehr: Was nach der Zeitzeile bis zur
    nächsten Leerzeile steht, IST gesprochener Text — auch wenn es einen Pfeil
    oder eine Zahl enthält. Die Cue-Grenze ist die Leerzeile, nicht der Inhalt.
    """
    start = zeilen[i][0]
    ende = zeilen[i][1]
    n = len(zeilen)
    while i < n and zeilen[i][2].strip():
        ende = zeilen[i][1]
        i += 1
    return PayloadSpan(cue_index=cue_index, start=start, end=ende), i


def _parse_srt(text: str) -> list[PayloadSpan]:
    zeilen = _lines(text)
    spans: list[PayloadSpan] = []
    i, n, cue = 0, len(zeilen), 0
    while i < n:
        if not zeilen[i][2].strip():
            i += 1
            continue
        if not is_timing_line(zeilen[i][2], CueFormat.SRT):
            kennung = zeilen[i][2].lstrip(BOM).strip()
            if not kennung.isdigit():
                raise CueParseError(
                    f"Zeile {i + 1}: {zeilen[i][2]!r} ist weder Cue-Kennung noch gültige "
                    "Zeitzeile (Format HH:MM:SS,mmm --> HH:MM:SS,mmm)."
                )
            i += 1
            if i >= n:
                raise CueParseError("Datei endet nach einer Cue-Kennung.")
        if not is_timing_line(zeilen[i][2], CueFormat.SRT):
            raise CueParseError(
                f"Zeile {i + 1}: gültige Zeitzeile erwartet, bekam {zeilen[i][2]!r}."
            )
        i += 1
        if i >= n or not zeilen[i][2].strip():
            raise CueParseError(f"Cue {cue}: kein gesprochener Text nach der Zeitzeile.")
        span, i = _payload_block(zeilen, i, cue)
        spans.append(span)
        cue += 1
    if not spans:
        raise CueParseError("Kein einziges Cue gefunden.")
    return spans


#: Blöcke, die im WebVTT vollständig Struktur sind und nie in den Payload
#: gelangen. ``STYLE`` und ``REGION`` enthalten CSS beziehungsweise
#: Positionsangaben — ein Erkenner hätte dort nichts zu suchen.
_VTT_STRUCTURE = ("NOTE", "STYLE", "REGION")


def _parse_vtt(text: str) -> list[PayloadSpan]:
    zeilen = _lines(text)
    if not zeilen:
        raise CueParseError("Leere Datei.")
    if not _HEADER.match(zeilen[0][2].lstrip(BOM)):
        raise CueParseError(
            f"Erste Zeile ist kein WEBVTT-Kopf: {zeilen[0][2]!r}. Erlaubt ist 'WEBVTT' "
            "allein oder mit Leerzeichen bzw. Tabulator und beliebigem Zusatztext."
        )
    i, n, cue = 1, len(zeilen), 0
    # Kopfmetadaten bis zur ersten Leerzeile — Struktur, kein Text.
    while i < n and zeilen[i][2].strip():
        i += 1
    spans: list[PayloadSpan] = []
    while i < n:
        inhalt = zeilen[i][2].strip()
        if not inhalt:
            i += 1
            continue
        if any(inhalt == w or inhalt.startswith(w + " ") for w in _VTT_STRUCTURE):
            while i < n and zeilen[i][2].strip():
                i += 1
            continue
        if not is_timing_line(zeilen[i][2], CueFormat.VTT):
            # Cue-Kennung: beliebiger Text, aber die NÄCHSTE Zeile muss eine
            # gültige Zeitzeile sein. Sonst ist es Müll und kein Bezeichner.
            if i + 1 >= n or not is_timing_line(zeilen[i + 1][2], CueFormat.VTT):
                raise CueParseError(
                    f"Zeile {i + 1}: {zeilen[i][2]!r} ist weder Cue-Kennung noch gültige "
                    "Zeitzeile (Format [HH:]MM:SS.mmm --> [HH:]MM:SS.mmm)."
                )
            i += 1
        i += 1  # Zeitzeile samt Settings überspringen
        if i >= n or not zeilen[i][2].strip():
            raise CueParseError(f"Cue {cue}: kein gesprochener Text nach der Zeitzeile.")
        span, i = _payload_block(zeilen, i, cue)
        spans.append(span)
        cue += 1
    if not spans:
        raise CueParseError("Kein einziges Cue gefunden.")
    return spans
