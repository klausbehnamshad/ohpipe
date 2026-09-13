"""Erkennungsspans — Positionen, niemals Inhalte.

Ein Span sagt: *an dieser Stelle dieser Payloadfassung steht eine Entität
dieses Typs.* Er sagt **nicht**, was dort steht. Sobald er die Oberflächenform
mitführte, wäre ``pii.spans`` eine zweite, record-lokale Ersetzungstabelle im
Datenbaum — genau das verbietet ADR 0024. Diese Regel gilt auch für
Fehlermeldungen: Eine Ausnahme, die den abgelehnten Wert ausgibt, hat ihn
damit protokolliert.

Drei Schichten, in dieser Reihenfolge:

1. **Strikte Datentypen.** ``Span`` und ``SpanSet`` lassen sich nicht falsch
   bauen. Was der Konstruktor annimmt, ist der Vertrag.
2. **Bindung.** ``SpanSet.bind(document)`` prüft alles, was ein Span über die
   Welt behauptet, gegen das tatsächliche Dokument — und liefert kanonische,
   ausschließlich codepoint-basierte ``BoundSpan``.
3. **Konflikte.** Vollständig geprüft, bevor irgendetwas angewandt wird.

Was hier bewusst **nicht** entschieden wird: welche Erwähnung zu welcher
Person gehört. Ein Span führt eine ``mention_id`` — „diese Erwähnung an dieser
Stelle" — und nichts darüber hinaus. Die Auflösung
``Mention → Entity → Pseudonym`` ist eine adjudizierte Entscheidung und
gehört nicht in ein Textmodul (ADR 0025).

Ebenso wenig entschieden wird, welcher Erkenner bei einem Konflikt gewinnt.
„Höchste Konfidenz gewinnt" ist fachliche Policy, kein Kernverhalten; im
ersten Stand hält der Konflikt an, statt geraten zu werden.
"""

from __future__ import annotations

import hashlib
import math
import itertools
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .cue import CueDocument

__all__ = [
    "TAXONOMY_VERSION",
    "BoundSpan",
    "BoundSpanSet",
    "EntityType",
    "OffsetUnit",
    "Span",
    "SpanConflict",
    "SpanError",
    "SpanOutOfRange",
    "SpanRevisionMismatch",
    "SpanSet",
    "mention_id",
]

_SHA256 = re.compile(r"^[0-9a-f]{64}$")

#: Felder, die ein persistierter Span tragen darf — Allowlist, nicht Blacklist.
#: Eine Blacklist müsste jeden Namen kennen, unter dem jemand eine
#: Oberflächenform unterbringt; eine Allowlist muss nur wissen, was erlaubt ist.
SPAN_FIELDS = frozenset(
    {
        "input_sha256",
        "unit",
        "cue_index",
        "start",
        "end",
        "entity_type",
        "recogniser",
        "confidence",
    }
)

SPANSET_FIELDS = frozenset({"document_sha256", "spans"})


class SpanError(ValueError):
    """Basisklasse. Keine Ausnahme dieses Moduls gibt je einen Textwert aus."""


class SpanRevisionMismatch(SpanError):
    """Der Span zeigt auf eine andere Fassung als das Dokument.

    Es folgt **keine** heuristische Suche nach „wahrscheinlich derselben
    Stelle". Genau das war im Vorgängersystem der Weg, auf dem Offsets zu
    Fiktion wurden.
    """


class SpanOutOfRange(SpanError):
    """Der Bereich liegt nicht vollständig im Payload."""


class SpanConflict(SpanError):
    """Zwei Spans überlappen und lassen sich nicht deterministisch vereinen."""


#: Die Taxonomie ist **versioniert und global**. Neue Typen brauchen eine
#: Code-/Taxonomieaenderung; das Profil waehlt daraus die geforderte Teilmenge
#: aus, es erweitert sie nicht. Eine erste Fassung dieses Kommentars
#: versprach projektspezifische Typen „aus dem Profil" — das widersprach dem
#: festen Enum darunter. Eine der beiden Aussagen musste weichen, und die
#: sicherere ist die feste Taxonomie: Ein Profil, das eigene Typen einfuehren
#: darf, ist wieder ein Freitextkanal.
TAXONOMY_VERSION = "ohpipe:entity-taxonomy:v1"


class EntityType(str, Enum):
    """Kontrolliertes Vokabular. Freitext wäre ein Schmuggelweg.

    ``entity_type`` nahm beliebige nichtleere Zeichenketten an. Damit war
    ``entity_type="Marie Schmitz"`` ein gültiger, persistierbarer Span — die
    Allowlist verhinderte zusätzliche Felder, aber keinen Klartext in einem
    erlaubten. Ein Vokabular hat diesen Weg nicht.

    Projektspezifische Bedarfe (Heimname, Ordensbezeichnung, seltene
    Berufsbiografie — vgl. `F8` der Angriffsliste) werden durch **Erweiterung
    dieser Taxonomie** gedeckt, nicht durch Profilfreitext. Das Profil wählt
    die geforderte Teilmenge; es erfindet keine Typen.

    Einen Sammeltopf ``MISC`` gibt es bewusst nicht: Ein Erkenner, der etwas
    findet, das keinem Typ entspricht, ist ein Konfigurationsfehler und kein
    „sonstiges".
    """

    PERSON = "PERSON"
    ORGANISATION = "ORGANISATION"
    LOCATION = "LOCATION"
    INSTITUTION = "INSTITUTION"
    DATE = "DATE"
    CONTACT = "CONTACT"
    IDENTIFIER = "IDENTIFIER"


#: Erkennerkennungen. Klein, ohne Leerzeichen, aus einer bekannten Menge.
#: Das Muster allein schlägt „Frau Schmitz" schon fehl.
RECOGNISER_RE = re.compile(r"^[a-z][a-z0-9._-]{1,31}$")

#: **Testgerüst, kein Evidenznachweis.** Diese Menge beweist ausschließlich,
#: dass eine Zeichenkette im Quelltext steht — nicht, dass der Erkenner im
#: konkreten Lauf konfiguriert war und tatsächlich lief. Die belastbare
#: Prüfung ist ein Abgleich gegen die Komponenten des jeweiligen
#: ``detection.receipt``; sie kommt mit dem Erkennungsadapter.
#:
#: ``test`` ist deshalb bis dahin enthalten und muss danach verschwinden — ein
#: Beleg mit ``recogniser="test"` in Produktionsdaten wäre eine Behauptung
#: ohne Lauf dahinter.
KNOWN_RECOGNISERS = frozenset(
    {"presidio", "gliner", "spacy", "flair", "gazetteer", "regex", "human", "test"}
)


def _wieviele(keys) -> str:
    """Die Anzahl, nie der Wert.

    Eine erste Fassung liess Feldnamen durch, die einem harmlosen Muster
    entsprachen. Das genuegt nicht: ``Marie_Schmitz`` und ``MarieSchmitz``
    passen darauf, und ``recogniser="marie.schmitz"`` stand ohnehin im Klartext
    in der Meldung. Ein Muster macht einen Wert nicht harmlos.

    Deshalb die einfache Regel: **Bekannte Konstanten und erlaubte Werte
    duerfen genannt werden, abgelehnte Eingaben nicht.** Wer wissen will,
    welches Feld gemeint war, sieht in seine eigene Datei — sie liegt ihm vor.
    Das Log liegt anderen vor.
    """
    n = len(list(keys))
    return f"{n} unerlaubtes Feld" if n == 1 else f"{n} unerlaubte Felder"


class OffsetUnit(str, Enum):
    """Die Einheit steht am Span und wird nie aus dem Text erraten.

    ``Lëtzebuerg`` ist als UTF-8 länger als in Codepoints. Wer Byteoffsets als
    Codepoints liest, schneidet mitten in ein Zeichen — und ersetzt dann
    entweder zu wenig oder zerstört die Kodierung.
    """

    CODEPOINT = "codepoint"
    UTF8_BYTE = "utf8_byte"


def _as_index(wert: object, feld: str) -> int:
    """Ein echter, nichtnegativer ``int``.

    ``bool`` ist in Python ein ``int``. ``cue_index=True`` wäre sonst Cue 1,
    und niemand hätte das gewollt.
    """
    if isinstance(wert, bool) or not isinstance(wert, int):
        raise SpanError(f"{feld} muss eine ganze Zahl sein, ist aber {type(wert).__name__}.")
    if wert < 0:
        raise SpanError(f"{feld} darf nicht negativ sein ({wert}).")
    return wert


@dataclass(frozen=True)
class Span:
    """Ein ungebundener Erkennungsbefund. Position und Typ, sonst nichts."""

    input_sha256: str
    unit: OffsetUnit
    cue_index: int
    start: int
    end: int
    entity_type: str
    recogniser: str
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if not isinstance(self.input_sha256, str) or not _SHA256.match(self.input_sha256):
            raise SpanError(
                "input_sha256 muss 64 kleine Hexzeichen sein — der Span bindet an eine "
                "bestimmte Payloadfassung, nicht an „das Transkript“."
            )
        try:
            object.__setattr__(self, "unit", OffsetUnit(self.unit))
        except ValueError as exc:
            erlaubt = ", ".join(u.value for u in OffsetUnit)
            raise SpanError(f"unit muss eine bekannte Offseteinheit sein ({erlaubt}).") from exc
        object.__setattr__(self, "cue_index", _as_index(self.cue_index, "cue_index"))
        object.__setattr__(self, "start", _as_index(self.start, "start"))
        object.__setattr__(self, "end", _as_index(self.end, "end"))
        if self.start >= self.end:
            raise SpanOutOfRange(
                f"Leerer oder rückwärts laufender Bereich: start={self.start}, end={self.end}."
            )
        try:
            object.__setattr__(self, "entity_type", EntityType(self.entity_type))
        except ValueError as exc:
            erlaubt = ", ".join(e.value for e in EntityType)
            raise SpanError(
                f"entity_type muss aus Taxonomie {TAXONOMY_VERSION} stammen ({erlaubt}). "
                "Freitext wäre ein Weg, Klartext in einem erlaubten Feld zu persistieren."
            ) from exc
        if not isinstance(self.recogniser, str) or not RECOGNISER_RE.match(self.recogniser):
            raise SpanError(
                "recogniser muss eine Kennung sein (klein, ohne Leerzeichen, 2-32 Zeichen), "
                "kein Freitext."
            )
        if self.recogniser not in KNOWN_RECOGNISERS:
            raise SpanError(
                "Unbekannte Erkennerkennung. Bekannt: " + ", ".join(sorted(KNOWN_RECOGNISERS))
            )
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise SpanError("confidence muss eine Zahl sein.")
        if not math.isfinite(self.confidence) or not 0.0 <= self.confidence <= 1.0:
            raise SpanError(f"confidence muss endlich und in [0, 1] liegen ({self.confidence}).")
        object.__setattr__(self, "confidence", float(self.confidence))

    @classmethod
    def from_json(cls, payload: object) -> Span:
        if not isinstance(payload, dict):
            raise SpanError(f"Ein Span ist ein Objekt, kein {type(payload).__name__}.")
        unbekannt = set(payload) - SPAN_FIELDS
        if unbekannt:
            # Absichtlich nur die NAMEN. Ein `surface`-Feld enthält den
            # Klarnamen; ihn in die Fehlermeldung zu schreiben hieße, ihn in
            # jedes Log zu schreiben, das diese Meldung aufnimmt.
            raise SpanError(
                f"Span enthält {_wieviele(unbekannt)}. Erlaubt sind ausschließlich: "
                + ", ".join(sorted(SPAN_FIELDS))
                + ". Ein Span trägt Positionen, keine Inhalte (ADR 0024). Der abgelehnte "
                "Feldname wird nicht ausgegeben — er kann selbst ein Klarname sein."
            )
        # `confidence` ist im PERSISTIERTEN Span Pflicht. Der Konstruktor darf
        # sie vorbelegen, die Datei nicht: Eine fehlende Konfidenz still zu 1.0
        # zu machen hiesse, eine unsichere Erkennung als sicher zu lesen.
        fehlt = SPAN_FIELDS - set(payload)
        if fehlt:
            raise SpanError("Pflichtfelder fehlen: " + ", ".join(sorted(fehlt)) + ".")
        return cls(**{k: payload[k] for k in payload})

    def to_json(self) -> dict[str, Any]:
        return {
            "input_sha256": self.input_sha256,
            "unit": self.unit.value,
            "cue_index": self.cue_index,
            "start": self.start,
            "end": self.end,
            "entity_type": self.entity_type.value,
            "recogniser": self.recogniser,
            "confidence": self.confidence,
        }


#: Schutz gegen VERSEHENTLICHE Fehlbenutzung — mehr ist es nicht, und das
#: gehoert hier hin statt in eine Behauptung.
#:
#: In Python laesst sich damit keine Sicherheitsgrenze bauen: Der Wert ist
#: importierbar, und ``dataclasses.replace(echter_span, cue_index=999)``
#: uebernimmt ihn ohnehin. Beides wurde nachgestellt.
#:
#: Die Grenze liegt deshalb nicht am Objekt, sondern am API: Eine oeffentliche
#: Funktion nimmt **kein** ``BoundSpanSet`` entgegen. ``apply_spans(document,
#: span_set, ...)`` akzeptiert ausschliesslich ein ``SpanSet`` und ruft
#: ``span_set.bind(document)`` selbst auf. Wer nicht hineinreichen kann, muss
#: auch nicht daran gehindert werden.
_GEBUNDEN = object()


@dataclass(frozen=True)
class BoundSpan:
    """Ein gegen ein konkretes Dokument geprüfter Span.

    Erzeugt wird er in :meth:`SpanSet.bind`. Die Prüfungen, auf die sich jeder
    spätere Schritt verlässt — Cue existiert, Bereich liegt im Payload, Einheit
    kanonisiert, Konflikte ausgeschlossen — brauchen das Dokument.

    Die Konstruktionsschranke unten ist **Schutz gegen Versehen, keine
    Sicherheitsgrenze**: Sie ist über den importierbaren Wert und über
    ``dataclasses.replace`` umgehbar. Die Sicherheit liegt darin, dass kein
    öffentliches API ein ``BoundSpanSet`` entgegennimmt.

    Ausschließlich Codepoints. Nach der Bindung gibt es keine gemischten
    Einheiten mehr — Vergleiche über verschiedene Einheiten hinweg wären
    genau die stille Fehlerquelle, die die Einheit am Span verhindern soll.

    ``recognisers`` ist eine Menge, weil identische Befunde mehrerer Erkenner
    zu **einem** Span verschmelzen. Eine Konfidenz führt der gebundene Span
    bewusst nicht: Sie zu mitteln oder die höchste zu nehmen wäre bereits
    fachliche Policy.
    """

    mention_id: str
    cue_index: int
    start: int
    end: int
    entity_type: EntityType
    recognisers: tuple[str, ...]
    _bound: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._bound is not _GEBUNDEN:
            raise SpanError(
                "Ein BoundSpan entsteht ausschließlich in SpanSet.bind(document). "
                "Er behauptet, gegen ein Dokument geprüft zu sein — diese Behauptung "
                "kann niemand von außen einlösen."
            )

    @property
    def sort_key(self) -> tuple[int, int, int, str]:
        return (self.cue_index, self.start, self.end, self.entity_type)


@dataclass(frozen=True)
class BoundSpanSet:
    """Das Ergebnis von :meth:`SpanSet.bind` — kanonisch sortiert, konfliktfrei."""

    document_sha256: str
    spans: tuple[BoundSpan, ...]
    _bound: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._bound is not _GEBUNDEN:
            raise SpanError("Ein BoundSpanSet entsteht ausschließlich in SpanSet.bind(document).")

    def __iter__(self):
        return iter(self.spans)

    def __len__(self) -> int:
        return len(self.spans)

    def for_cue(self, cue_index: int) -> tuple[BoundSpan, ...]:
        return tuple(s for s in self.spans if s.cue_index == cue_index)


#: Domain Separation. Ohne sie waere derselbe Hash ueber dieselben Felder in
#: einem anderen Kontext derselbe Wert — und eine spaetere Aenderung am
#: Verfahren waere von aussen nicht unterscheidbar.
MENTION_ID_DOMAIN = "ohpipe:mention:v1"


def mention_id(
    document_sha256: str, cue_index: int, start: int, end: int, entity_type: object
) -> str:
    """Deterministisch aus der Textstelle — und aus nichts sonst.

    Sie sagt „diese Erwähnung an dieser Stelle" und ist keine Identität. Wer
    zwei Erwähnungen derselben Person zusammenführt, tut das über die
    Entity-Auflösung (ADR 0025), nicht über diesen Wert.

    Die Offsets sind die kanonischen Codepointwerte. Derselbe Textort ergibt
    damit dieselbe ID, gleichgültig in welcher Einheit er gemeldet wurde.
    """
    typ = entity_type.value if isinstance(entity_type, EntityType) else str(entity_type)
    roh = f"{MENTION_ID_DOMAIN}|{document_sha256}|{cue_index}|{start}|{end}|{typ}"
    return "MEN-" + hashlib.sha256(roh.encode("utf-8")).hexdigest()[:24]


@dataclass(frozen=True)
class SpanSet:
    """Die persistierbare Spanmenge eines Dokuments."""

    document_sha256: str
    spans: tuple[Span, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.document_sha256, str) or not _SHA256.match(self.document_sha256):
            raise SpanError("document_sha256 muss 64 kleine Hexzeichen sein.")
        if isinstance(self.spans, (str, bytes)) or not hasattr(self.spans, "__iter__"):
            raise SpanError("spans muss eine Folge von Span-Objekten sein.")
        gepackt = tuple(self.spans)
        for s in gepackt:
            if not isinstance(s, Span):
                raise SpanError(f"spans enthält ein {type(s).__name__}, keinen Span.")
        object.__setattr__(self, "spans", gepackt)

    def __iter__(self):
        return iter(self.spans)

    def __len__(self) -> int:
        return len(self.spans)

    @classmethod
    def from_json(cls, payload: object) -> SpanSet:
        """Fail-closed, mit Allowlist auf beiden Ebenen."""
        if not isinstance(payload, dict):
            raise SpanError(f"Eine Spanmenge ist ein Objekt, kein {type(payload).__name__}.")
        unbekannt = set(payload) - SPANSET_FIELDS
        if unbekannt:
            raise SpanError(
                f"Spanmenge enthält {_wieviele(unbekannt)}. Erlaubt: "
                + ", ".join(sorted(SPANSET_FIELDS))
            )
        fehlt = SPANSET_FIELDS - set(payload)
        if fehlt:
            raise SpanError("Pflichtfelder fehlen: " + ", ".join(sorted(fehlt)))
        roh = payload["spans"]
        if not isinstance(roh, list):
            raise SpanError("spans muss eine Liste sein.")
        return cls(
            document_sha256=payload["document_sha256"],
            spans=tuple(Span.from_json(s) for s in roh),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "document_sha256": self.document_sha256,
            "spans": [s.to_json() for s in self.spans],
        }

    # ------------------------------------------------------------ Bindung

    def bind(self, document: CueDocument) -> BoundSpanSet:
        """Prüft jede Behauptung eines Spans gegen das echte Dokument.

        Die Bindung an den **vollständigen Dokumenthash** ist streng gemeint:
        Eine Spanmenge ist eine Vollständigkeitsbehauptung über das Dokument.
        Änderte sich irgendein Cue, wird sie ungültig — auch für die
        unveränderten. Sonst ließe sich ein alter Erkennungslauf
        weiterverwenden, obwohl der geänderte Cue neue PII enthalten kann, die
        nie jemand gesucht hat. Der Payloadhash ist die zusätzliche lokale
        Prüfung, keine Erlaubnis zur inkrementellen Wiederverwendung.

        Die Reihenfolge ist nicht beliebig. Erst Fassung, dann Existenz, dann
        Einheit, dann Bereich, dann Konflikte — und **alles**, bevor
        irgendetwas angewandt wird. Ein halb gebundener Lauf, der schon
        Pseudonyme verbraucht hat, hinterließe Lücken in einem korpusweiten
        Register, die später niemand mehr auflösen kann.
        """
        if document.sha256 != self.document_sha256:
            raise SpanRevisionMismatch(
                f"Die Spanmenge gehört zu Dokument {self.document_sha256[:12]}…, "
                f"gebunden wurde gegen {document.sha256[:12]}…. Es wird nicht gesucht, "
                "wo die Stelle „wahrscheinlich“ jetzt liegt."
            )
        payloads = document.payloads()
        gebunden: list[BoundSpan] = []
        for s in self.spans:
            if s.cue_index >= len(payloads):
                raise SpanOutOfRange(
                    f"Span nennt Cue {s.cue_index}; das Dokument hat {len(payloads)}."
                )
            payload = payloads[s.cue_index]
            if document.payload_sha256(s.cue_index) != s.input_sha256:
                raise SpanRevisionMismatch(
                    f"Cue {s.cue_index}: Der Span bindet an Payloadfassung "
                    f"{s.input_sha256[:12]}…, vorliegend ist eine andere. Gleiche Zahlen "
                    "zeigen auf verschiedene Zeichen, sobald die Normalisierung abweicht."
                )
            start, end = _to_codepoints(s, payload)
            if end > len(payload):
                raise SpanOutOfRange(
                    f"Cue {s.cue_index}: Bereich endet bei {end}, der Payload hat "
                    f"{len(payload)} Zeichen."
                )
            gebunden.append(
                BoundSpan(
                    mention_id=mention_id(
                        self.document_sha256, s.cue_index, start, end, s.entity_type
                    ),
                    cue_index=s.cue_index,
                    start=start,
                    end=end,
                    entity_type=s.entity_type,
                    recognisers=(s.recogniser,),
                    _bound=_GEBUNDEN,
                )
            )
        vereint = _merge_identical(gebunden)
        _refuse_overlaps(vereint)
        return BoundSpanSet(
            document_sha256=self.document_sha256, spans=tuple(vereint), _bound=_GEBUNDEN
        )


def _to_codepoints(span: Span, payload: str) -> tuple[int, int]:
    """Byteoffsets einmalig kanonisieren — und nur auf Zeichengrenzen.

    Der Dekodierversuch IST die Grenzprüfung: ``b"L\\xc3"`` lässt sich nicht
    dekodieren, weil ``ë`` mitten durchgeschnitten wäre.
    """
    if span.unit is OffsetUnit.CODEPOINT:
        return span.start, span.end
    roh = payload.encode("utf-8")
    if span.end > len(roh):
        raise SpanOutOfRange(
            f"Cue {span.cue_index}: Byteoffset {span.end} liegt hinter dem Payload "
            f"({len(roh)} Bytes)."
        )
    try:
        return len(roh[: span.start].decode("utf-8")), len(roh[: span.end].decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise SpanOutOfRange(
            f"Cue {span.cue_index}: Byteoffset liegt nicht auf einer Zeichengrenze — "
            "er schneidet mitten in ein Zeichen."
        ) from exc


def _merge_identical(spans: list[BoundSpan]) -> list[BoundSpan]:
    """Gleiche Grenzen und gleicher Typ sind EIN Befund, nicht zwei.

    Zwei Erkenner, die dieselbe Stelle gleich beurteilen, sind eine
    Bestätigung — kein Konflikt und keine doppelte Entität im Bericht.
    """
    nach_stelle: dict[tuple[int, int, int, str], list[BoundSpan]] = {}
    for s in spans:
        nach_stelle.setdefault(s.sort_key, []).append(s)
    out = []
    for key in sorted(nach_stelle):
        gruppe = nach_stelle[key]
        erkenner = tuple(sorted({r for g in gruppe for r in g.recognisers}))
        out.append(
            BoundSpan(
                mention_id=gruppe[0].mention_id,
                cue_index=key[0],
                start=key[1],
                end=key[2],
                entity_type=key[3],
                recognisers=erkenner,
                _bound=_GEBUNDEN,
            )
        )
    return out


def _refuse_overlaps(spans: list[BoundSpan]) -> None:
    """Jede Überlappung, die kein exaktes Duplikat war, hält an.

    Kein „höchste Konfidenz gewinnt", kein „der längere gewinnt", und vor
    allem nicht die Reihenfolge der Adapterliste: Die Spans sind hier bereits
    kanonisch sortiert, das Ergebnis hängt also nicht davon ab, in welcher
    Reihenfolge die Erkenner gelaufen sind.

    Benachbart ist erlaubt: ``end == start`` überlappt nicht.
    """
    for a, b in itertools.pairwise(spans):
        if a.cue_index == b.cue_index and b.start < a.end:
            raise SpanConflict(
                f"Cue {a.cue_index}: Die Bereiche [{a.start},{a.end}) als {a.entity_type} "
                f"und [{b.start},{b.end}) als {b.entity_type} überlappen. Welcher gilt, "
                "ist eine fachliche Entscheidung und wird nicht geraten."
            )
