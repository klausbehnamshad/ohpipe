"""Der seiteneffektfreie Revisionskern: eine Fassung, genau eine Bytefolge.

`docs/adr/0028B-S-revisionsserialisierung-und-P-projektionsvertrag.md` setzt
Teil P und Teil S. Dieses Modul ist ihre Umsetzung und sonst nichts: es liest
keine Datei, schreibt kein Journal, kennt keinen Store und erzeugt kein
Bestaetigungsartefakt.

**Die Invariante, in einem Satz.** Zu jeder gueltigen identitaetsbildenden
Revision existiert genau eine kanonische UTF-8-Bytefolge ohne Folgebyte; aus
ihr sind alle identitaetsbildenden Felder wiederherstellbar, ihr sha256 ist
die Revisionsidentitaet, und jeder Regelbruch faellt in der festgelegten
Prioritaet fail-closed, ohne Eingaben zu reparieren.

**Warum geprueft und nicht repariert wird.** Ein Trimmen, ein
Nachnormalisieren oder ein stiller Default macht aus zwei verschiedenen
Eingaben dieselbe Identitaet. Genau das darf eine Adresse nicht: sie muss
zurueckweisen, was sie nicht eindeutig binden kann.

**Die sieben Stufen.** Die erste verletzte Stufe bestimmt den Ausgang;
spaetere Stufen werden nicht mehr ausgefuehrt und deshalb auch nicht
behauptet. Ohne diese Ordnung traegt derselbe Fehler zwei Namen, und ein
Aufrufer kann aus der Klasse nicht mehr lesen, wie weit die Pruefung kam.

1. UTF-8-Gueltigkeit
2. JSON-Parse
3. Schema, Typen, null-Grenze, Normalisierung, Reihenfolge
4. projection_version: Syntax, Katalog, Produktdefinition
5. Konsistenztor Volltext gegen Segmentprojektion
6. bytegleiche kanonische Reserialisierung
7. Vergleich des vorgelegten revision_sha256 mit dem aus CANON berechneten
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # zyklusfrei: nur fuer die Typprueferin
    from .transcript import Segment, TranscriptRevision

__all__ = [
    "KNOWN_PROJECTION_VERSIONS",
    "PROJECTION_VERSION",
    "InvalidProjectionVersion",
    "InvalidRevisionNormalization",
    "InvalidRevisionSchema",
    "InvalidRevisionType",
    "InvalidSegmentOrder",
    "ProjectionDefinitionUnavailable",
    "ProjectionMismatch",
    "RevisionHashMismatch",
    "RevisionReconstructionMismatch",
    "RevisionValidationError",
    "UnknownProjectionVersion",
    "canonical_revision_bytes",
    "project_segments",
    "reconstruct_revision",
    "revision_sha256",
    "validate_revision",
    "verify_revision",
]

_LF = chr(10)
_CR = chr(13)

#: Die eine angenommene Projektionskennung. Teil P, Abschnitt P1.
PROJECTION_VERSION = "seg-join-lf.v1"

#: Syntax aus P1. `fullmatch`, nicht `match`: ein Dollarzeichen traefe auch
#: vor einem abschliessenden Zeilenvorschub.
_PV_RE = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*\.v[1-9][0-9]*")
_PV_MIN, _PV_MAX = 3, 64

#: Der geschlossene Katalog. Er wird NICHT aus Datei, Umgebung, Profil, Store
#: oder Journal geladen und hat keinen Erweiterungshook: ein Katalog, den ein
#: Aufrufer erweitern kann, ist kein geschlossenes Vokabular mehr.
KNOWN_PROJECTION_VERSIONS: frozenset[str] = frozenset({PROJECTION_VERSION})

#: Die sechs Top-Level-Schluessel in kanonischer Ordnung (S2, S4).
_FELDER: tuple[str, ...] = (
    "domain",
    "fulltext",
    "profile_id",
    "projection_version",
    "segments",
    "v",
)
#: Die sechs Segmentschluessel in kanonischer Ordnung.
_SEGMENTFELDER: tuple[str, ...] = (
    "end_ms",
    "index",
    "language",
    "speaker",
    "start_ms",
    "text",
)

#: Kennung und Version der Serialisierungsregel, gefuehrt als Felder IM Objekt
#: nach dem E3-Formelmuster (S8). Es gibt keine zweite Kennung daneben.
_DOMAIN = "transcript_revision"
_V = 1

_LANG_RE = re.compile(r"[a-z]{3}")


class RevisionValidationError(ValueError):
    """Gemeinsame Basis der zehn Klassen. Fail-closed, nie reparierend."""


class InvalidRevisionSchema(RevisionValidationError):
    """Fehlendes oder unbekanntes Feld, leere Segmentliste, falsche Kennung."""


class InvalidRevisionType(RevisionValidationError):
    """Falscher Typ, null, bool, unzulaessige Zahlform, Wertgrenze verletzt."""


class InvalidRevisionNormalization(RevisionValidationError):
    """Nicht-NFC oder U+000D im Text."""


class InvalidSegmentOrder(RevisionValidationError):
    """Negative, doppelte, lueckenhafte oder ungeordnete Indizes."""


class InvalidProjectionVersion(RevisionValidationError):
    """Die Kennung verletzt Syntax oder Laengengrenze."""


class UnknownProjectionVersion(RevisionValidationError):
    """Syntaktisch gueltig, aber nicht im geschlossenen Katalog."""


class ProjectionDefinitionUnavailable(RevisionValidationError):
    """Im Katalog, aber ohne Produktdefinition — ein Konsistenzbruch."""


class ProjectionMismatch(RevisionValidationError):
    """Der vorgelegte Volltext ist nicht die Projektion der Segmente."""


class RevisionReconstructionMismatch(RevisionValidationError):
    """Gueltig parsebar, aber nicht die kanonische Byteform. Einzige Klasse fuer N6."""


class RevisionHashMismatch(RevisionValidationError):
    """Stufen 1 bis 6 bestanden, der vorgelegte Digest weicht ab. Einzige Klasse fuer N7."""


def _projektion_seg_join_lf(texte: Sequence[str]) -> str:
    return _LF.join(texte)


#: Die im Produkt vorhandenen Projektionsdefinitionen. Der Waechter in
#: `_projektion_fuer` faellt, wenn Katalog und Definitionen auseinanderlaufen.
_PROJEKTIONEN: Mapping[str, Any] = MappingProxyType({PROJECTION_VERSION: _projektion_seg_join_lf})


def _geprueft_projection_version(wert: Any) -> str:
    """Die vier Ausgaenge der Kennung in ihrer verbindlichen Reihenfolge.

    1. falscher Laufzeittyp        -> InvalidRevisionType, Stufe 3
    2. Syntax- oder Laengenbruch   -> InvalidProjectionVersion, Stufe 4
    3. gueltig, aber unbekannt     -> UnknownProjectionVersion, Stufe 4
    4. im Katalog ohne Definition  -> ProjectionDefinitionUnavailable, Stufe 4
       (in `_projektion_fuer`)

    Nur eine **Zeichenkette** kann die P1-Syntax oder die Laengengrenze
    verletzen. `null`, `bool`, `int` und `float` sind Typ- beziehungsweise
    null-Grenzbrueche und gehoeren nach S13 an Stufe 3 — nicht an Stufe 4.
    Wuerden sie als `InvalidProjectionVersion` gemeldet, traege die
    siebenstufige Prioritaet an dieser Stelle nicht, und ein Aufrufer, der auf
    die Typklasse filtert, saehe den Fall nicht.
    """
    if isinstance(wert, bool) or not isinstance(wert, str):
        raise InvalidRevisionType(
            f"Stufe 3: projection_version muss eine Zeichenkette sein, ist aber "
            f"{wert!r} vom Typ {type(wert).__name__}. Ein falscher Laufzeittyp ist "
            "ein Typbruch an Stufe 3 und keine Syntaxverletzung an Stufe 4. Der Wert "
            "wird nicht repariert, nicht konvertiert und nicht ersetzt."
        )
    if not (_PV_MIN <= len(wert) <= _PV_MAX) or not _PV_RE.fullmatch(wert):
        raise InvalidProjectionVersion(
            f"projection_version ist {wert!r} und verletzt die Syntax aus Teil P: "
            f"ASCII-Kleinbuchstaben, Ziffern und Bindestriche, dann .v<n>, "
            f"Laenge {_PV_MIN} bis {_PV_MAX}."
        )
    if wert not in KNOWN_PROJECTION_VERSIONS:
        raise UnknownProjectionVersion(
            f"projection_version ist {wert!r} und steht nicht im geschlossenen "
            f"Katalog {sorted(KNOWN_PROJECTION_VERSIONS)}. Der Katalog wird nicht "
            "aus Datei, Umgebung oder Journal erweitert."
        )
    return wert


def _projektion_fuer(wert: str):
    try:
        return _PROJEKTIONEN[wert]
    except KeyError as exc:
        raise ProjectionDefinitionUnavailable(
            f"projection_version {wert!r} steht im Katalog, aber im Produkt liegt "
            "keine Projektionsdefinition dafuer vor. Katalog und Definitionen sind "
            "auseinandergelaufen."
        ) from exc


def project_segments(segments: Sequence[Segment], projection_version: str) -> str:
    """Die reine Projektion nach Teil P. Liest ausschliesslich `text`."""
    _geprueft_projection_version(projection_version)
    verbinde = _projektion_fuer(projection_version)
    geordnet = sorted(segments, key=lambda s: (s.index is None, s.index))
    return verbinde([s.text for s in geordnet])


def _ganzzahl(wert: Any, feld: str, wo: str, *, nichtnegativ: bool = True) -> int:
    """Typpruefung fuer eine Ganzzahl. `bool` ist keine zulaessige Ganzzahl.

    Mit ``nichtnegativ=False`` bleibt das Vorzeichen ungeprueft: fuer ``index``
    ist ein negativer Wert kein Typbruch, sondern ein Reihenfolgefehler und
    faellt darum in `_segmentwerte` als `InvalidSegmentOrder` (S13).
    """
    if isinstance(wert, bool) or not isinstance(wert, int):
        raise InvalidRevisionType(
            f"{wo}: {feld} muss eine Ganzzahl sein, ist aber "
            f"{wert!r} vom Typ {type(wert).__name__}."
        )
    if nichtnegativ and wert < 0:
        raise InvalidRevisionType(f"{wo}: {feld} ist {wert} und damit negativ.")
    return wert


def _zeichenkette(wert: Any, feld: str, wo: str, *, nichtleer: bool) -> str:
    if isinstance(wert, bool) or not isinstance(wert, str):
        raise InvalidRevisionType(
            f"{wo}: {feld} muss eine Zeichenkette sein, ist aber {wert!r} "
            f"vom Typ {type(wert).__name__}."
        )
    if nichtleer and not wert:
        raise InvalidRevisionType(f"{wo}: {feld} ist die leere Zeichenkette.")
    return wert


def _ohne_surrogat(wert: str, feld: str, wo: str) -> str:
    """Ein isolierter Surrogatcodepunkt ist kein UTF-8-Skalarwert.

    Er wuerde erst bei der Byteerzeugung als roher `UnicodeEncodeError`
    auffallen und damit den Fehlervertrag verlassen: ein Aufrufer, der auf
    `RevisionValidationError` faengt, saehe diesen Eingang nicht. Deshalb
    faellt er hier, an Stufe 3, mit Feld, Grund und Stufe.
    """
    for stelle, zeichen in enumerate(wert):
        wert_cp = ord(zeichen)
        if 0xD800 <= wert_cp <= 0xDFFF:
            raise InvalidRevisionNormalization(
                f"{wo}: {feld} traegt an Zeichenstelle {stelle} den isolierten "
                f"Surrogatcodepunkt U+{wert_cp:04X}. Surrogate sind keine "
                "UTF-8-Skalarwerte; fuer diese Zeichenkette ist CANON nicht "
                "bildbar. Stufe 3, nicht repariert."
            )
    return wert


def _geprueft_nfc(wert: str, feld: str, wo: str) -> str:
    """NFC fuer JEDE Zeichenkette im Objekt (P4, S5) — nicht nur fuer Text.

    `profile_id` und `speaker` gehen zeichengenau in CANON ein. Blieben sie
    ungeprueft, erzeugten zwei kanonisch aequivalente Eingaben zwei
    verschiedene, beide akzeptierte Identitaeten — genau das schliesst die
    NFC-Zusage aus.
    """
    _ohne_surrogat(wert, feld, wo)
    if not unicodedata.is_normalized("NFC", wert):
        raise InvalidRevisionNormalization(
            f"{wo}: {feld} ist nicht NFC-normalisiert. Der Kern normalisiert nicht nach, er prueft."
        )
    return wert


def _geprueft_text(wert: str, feld: str, wo: str) -> str:
    if _CR in wert:
        raise InvalidRevisionNormalization(
            f"{wo}: {feld} enthaelt U+000D. Zeilenenden werden nicht umgeschrieben; "
            "die Eingabe wird zurueckgewiesen."
        )
    return _geprueft_nfc(wert, feld, wo)


def _segmentwerte(segments: Sequence[Segment]) -> list[dict[str, Any]]:
    if not isinstance(segments, Sequence) or isinstance(segments, str | bytes):
        raise InvalidRevisionSchema(
            f"segments muss eine Liste von Segmenten sein, ist aber {type(segments).__name__}."
        )
    if len(segments) == 0:
        raise InvalidRevisionSchema(
            "segments ist leer. Eine Revision ohne Segment traegt keine "
            "identitaetsbildenden Segmentdaten."
        )
    werte: list[dict[str, Any]] = []
    for stelle, s in enumerate(segments):
        wo = f"Segment index {getattr(s, 'index', stelle)!r} (Listenstelle {stelle})"
        idx = _ganzzahl(getattr(s, "index", None), "index", wo, nichtnegativ=False)
        if idx < 0:
            raise InvalidSegmentOrder(
                f"{wo}: index ist {idx} und damit negativ. Die Segmentindizes bilden "
                "die lueckenlose, nullbasierte, streng aufsteigende Folge; ein "
                "negativer Index verletzt diese Reihenfolge und ist kein Typbruch."
            )
        start = _ganzzahl(getattr(s, "start_ms", None), "start_ms", wo)
        ende = _ganzzahl(getattr(s, "end_ms", None), "end_ms", wo)
        if ende < start:
            raise InvalidRevisionType(f"{wo}: end_ms {ende} liegt vor start_ms {start}.")
        sprecher = _zeichenkette(getattr(s, "speaker", None), "speaker", wo, nichtleer=True)
        sprache = _zeichenkette(getattr(s, "language", None), "language", wo, nichtleer=True)
        if not _LANG_RE.fullmatch(sprache):
            raise InvalidRevisionType(
                f"{wo}: language ist {sprache!r} und damit kein ISO-639-3-Code aus "
                "genau drei ASCII-Kleinbuchstaben."
            )
        text = _zeichenkette(getattr(s, "text", None), "text", wo, nichtleer=False)
        _geprueft_nfc(sprecher, "speaker", wo)
        _geprueft_text(text, "text", wo)
        werte.append(
            {
                "end_ms": ende,
                "index": idx,
                "language": sprache,
                "speaker": sprecher,
                "start_ms": start,
                "text": text,
            }
        )
    indizes = [w["index"] for w in werte]
    if indizes != list(range(len(werte))):
        raise InvalidSegmentOrder(
            f"Die Segmentindizes sind {indizes}. Erwartet ist die lueckenlose, "
            f"nullbasierte, streng aufsteigende Folge {list(range(len(werte)))}."
        )
    return werte


def _objekt(revision: TranscriptRevision) -> dict[str, Any]:
    """Stufen 3 bis 5 in ihrer Reihenfolge. Repariert nichts."""
    profil = _zeichenkette(
        getattr(revision, "profile_id", None), "profile_id", "Revision", nichtleer=True
    )
    volltext = _zeichenkette(
        getattr(revision, "text", None), "fulltext", "Revision", nichtleer=False
    )
    segmente = _segmentwerte(getattr(revision, "segments", ()))
    _geprueft_text(volltext, "fulltext", "Revision")
    _geprueft_nfc(profil, "profile_id", "Revision")
    kennung = _geprueft_projection_version(getattr(revision, "projection_version", None))
    verbinde = _projektion_fuer(kennung)
    erwartet = verbinde([w["text"] for w in segmente])
    if volltext != erwartet:
        raise ProjectionMismatch(
            "fulltext ist nicht die Projektion der Segmente. Der vorgelegte Volltext "
            "wird NICHT durch die Projektion ersetzt und die Segmente werden nicht "
            f"angepasst. Vorgelegt {volltext!r}, projiziert {erwartet!r}."
        )
    return {
        "domain": _DOMAIN,
        "fulltext": volltext,
        "profile_id": profil,
        "projection_version": kennung,
        "segments": segmente,
        "v": _V,
    }


def validate_revision(revision: TranscriptRevision) -> None:
    """Prueft die objektseitigen Stufen 3 bis 5. Gibt nichts zurueck und repariert nichts."""
    _objekt(revision)


def _kanonisch(objekt: Mapping[str, Any]) -> bytes:
    return json.dumps(objekt, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


def canonical_revision_bytes(revision: TranscriptRevision) -> bytes:
    """Validiert und liefert genau CANON: beginnt 7b, endet 7d, kein Folgebyte."""
    return _kanonisch(_objekt(revision))


def revision_sha256(revision: TranscriptRevision) -> str:
    """sha256 ueber genau `canonical_revision_bytes`. Kein Praefix, kein Suffix."""
    return hashlib.sha256(canonical_revision_bytes(revision)).hexdigest()


def _revision_aus(objekt: Mapping[str, Any]) -> TranscriptRevision:
    from .transcript import Segment, TranscriptRevision  # zyklusfrei: nur hier gebraucht

    return TranscriptRevision(
        text=objekt["fulltext"],
        projection_version=objekt["projection_version"],
        profile_id=objekt["profile_id"],
        segments=tuple(
            Segment(
                index=s["index"],
                start_ms=s["start_ms"],
                end_ms=s["end_ms"],
                text=s["text"],
                speaker=s["speaker"],
                language=s["language"],
            )
            for s in objekt["segments"]
        ),
    )


def _geparst(canon: bytes) -> Mapping[str, Any]:
    if not isinstance(canon, bytes | bytearray):
        raise RevisionValidationError(
            f"Stufe 1: CANON muss eine Bytefolge sein, ist aber {type(canon).__name__}."
        )
    try:
        text = bytes(canon).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RevisionValidationError(f"Stufe 1: CANON ist kein gueltiges UTF-8: {exc}") from exc
    try:
        objekt = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RevisionValidationError(f"Stufe 2: CANON ist kein parsebares JSON: {exc}") from exc
    if not isinstance(objekt, dict):
        raise InvalidRevisionSchema(
            f"Stufe 3: CANON traegt kein JSON-Objekt, sondern {type(objekt).__name__}."
        )
    return objekt


def _geprueftes_schema(objekt: Mapping[str, Any]) -> None:
    fehlend = [f for f in _FELDER if f not in objekt]
    if fehlend:
        raise InvalidRevisionSchema(f"Es fehlen die Top-Level-Felder {fehlend}.")
    fremd = sorted(set(objekt) - set(_FELDER))
    if fremd:
        raise InvalidRevisionSchema(
            f"nicht erlaubte Felder: {fremd}. Erlaubt sind {list(_FELDER)}. "
            "Ein unbekanntes Feld wird nicht stillschweigend verworfen."
        )
    if type(objekt["v"]) is not int:
        raise InvalidRevisionType(
            f"Stufe 3: v muss eine echte Ganzzahl sein, ist aber {objekt['v']!r} "
            f"vom Typ {type(objekt['v']).__name__}. In Python gilt True == 1 und "
            "1.0 == 1; ein blosser Gleichheitsvergleich liesse beide Formen "
            "passieren, und der Typbruch fiele erst an Stufe 6 unter dem "
            "falschen Namen."
        )
    if type(objekt["domain"]) is not str:
        raise InvalidRevisionType(
            f"Stufe 3: domain muss eine Zeichenkette sein, ist aber "
            f"{objekt['domain']!r} vom Typ {type(objekt['domain']).__name__}."
        )
    if objekt["domain"] != _DOMAIN or objekt["v"] != _V:
        raise InvalidRevisionSchema(
            f"domain/v sind {objekt['domain']!r}/{objekt['v']!r}, erwartet "
            f"{_DOMAIN!r}/{_V!r}. Dann gilt eine andere Serialisierungsregel."
        )
    segmente = objekt["segments"]
    if not isinstance(segmente, list):
        raise InvalidRevisionSchema(
            f"segments muss eine Liste sein, ist aber {type(segmente).__name__}."
        )
    for stelle, s in enumerate(segmente):
        if not isinstance(s, dict):
            raise InvalidRevisionSchema(
                f"Segment an Listenstelle {stelle} ist kein Objekt, sondern {type(s).__name__}."
            )
        fehlend_s = [f for f in _SEGMENTFELDER if f not in s]
        if fehlend_s:
            raise InvalidRevisionSchema(
                f"Segment an Listenstelle {stelle}: es fehlen die Felder {fehlend_s}."
            )
        fremd_s = sorted(set(s) - set(_SEGMENTFELDER))
        if fremd_s:
            raise InvalidRevisionSchema(
                f"Segment an Listenstelle {stelle}: nicht erlaubte Felder {fremd_s}."
            )


def reconstruct_revision(canon: bytes) -> TranscriptRevision:
    """Fuehrt die Stufen 1 bis 6 aus und gibt die identitaetsbildenden Felder zurueck.

    Nicht identitaetsbildende Herkunftsfelder werden NICHT aus CANON erfunden:
    die Round-trip-Zusage gilt den identitaetsbildenden Feldern und der
    Bytefolge, nicht der Provenienz.
    """
    objekt = _geparst(canon)
    _geprueftes_schema(objekt)
    revision = _revision_aus(objekt)
    wieder = canonical_revision_bytes(revision)
    if wieder != bytes(canon):
        raise RevisionReconstructionMismatch(
            "Stufe 6: die vorgelegten Bytes sind nicht die kanonische "
            f"Reserialisierung. Vorgelegt {len(canon)} Byte, kanonisch "
            f"{len(wieder)} Byte. Der Inhalt ist gueltig parsebar; allein die "
            "Byteform ist nicht kanonisch."
        )
    return revision


def verify_revision(canon: bytes, submitted_revision_sha256: str) -> TranscriptRevision:
    """Fuehrt die Stufen 1 bis 7 aus. Stufe 7 wird nur nach bestandener Stufe 6 erreicht."""
    revision = reconstruct_revision(canon)
    berechnet = hashlib.sha256(bytes(canon)).hexdigest()
    if submitted_revision_sha256 != berechnet:
        raise RevisionHashMismatch(
            "Stufe 7: der vorgelegte revision_sha256 trifft den aus CANON "
            f"berechneten nicht. Vorgelegt {submitted_revision_sha256!r}, "
            f"berechnet {berechnet!r}. Die Bytes selbst sind kanonisch."
        )
    return revision
