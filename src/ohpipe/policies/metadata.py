"""Das Metadata Model als kanonische deskriptive Schicht.

Quelle: IMM-Core v1.0 (DOI 10.5281/zenodo.20507329), vendort unter
``ohpipe/schemas/metadata/``. Im Projektgebrauch heißt es **Metadata Model**; der
Publikationsname steht nur noch in der Zitation.

Zwei Dinge übernimmt dieses Modul aus dem Modell, weil sie erzwingbar sind:

1. **Pflichtfelder und Wertebereiche** kommen aus der DCTAP, nicht aus einer
   Handkopie. Eine vendorte Kopie, die still driftet, war im Vorgängersystem ein
   realer Defekt.
2. **Die Widerrufs-Invariante:** ``withdrawn`` bleibt in jedem Profil gültig,
   und ein zurückgezogener Record hat ``accessRights: "closed"``. Sie verbindet
   sich unmittelbar mit dem ``WITHDRAW``-Verdikt einer :class:`Decision`.

Was das Modul **nicht** tut: Es behauptet keine Konformität. Ob ein Export
tatsächlich modellkonform ist, entscheidet die Validierung gegen die vendorte
DCTAP — nicht diese Datei.
"""

from __future__ import annotations

import csv
import re
import tomllib
from dataclasses import dataclass
from datetime import date
from importlib.resources import files
from pathlib import Path
from typing import Any

__all__ = [
    "CONSENT_REFERENCE_KEY",
    "RECORD_INPUT_KEYS",
    "REQUIRED_FIELDS",
    "WITHDRAWN",
    "FieldSpec",
    "MetadataError",
    "RecordMetadataError",
    "RecordMetadataInput",
    "check_record",
    "load_record_metadata",
    "load_tap",
]

TAP_PATH = files("ohpipe").joinpath("schemas", "metadata", "core.tap.csv")

#: Der Term, der laut Vokabular in JEDEM Profil gültig bleiben muss.
WITHDRAWN = "withdrawn"
CLOSED = "closed"


class MetadataError(ValueError):
    pass


@dataclass(frozen=True)
class FieldSpec:
    property_id: str
    block: str
    datatype: str
    mandatory: bool
    repeatable: bool
    description: str
    enum: tuple[str, ...] = ()

    @property
    def is_descriptive(self) -> bool:
        """Block A/B beschreiben das Interview, C strukturiert es."""
        return self.block in ("A", "B")


def load_tap(path: Path | None = None) -> dict[str, FieldSpec]:
    """Liest die DCTAP — die maßgebliche Fassung, nicht den JSON-Spiegel."""
    p = path or TAP_PATH
    try:
        rows = list(csv.DictReader(p.read_text(encoding="utf-8").splitlines()))
    except OSError as exc:
        raise MetadataError(f"Metadata-Model-DCTAP nicht lesbar: {exc}") from exc
    out: dict[str, FieldSpec] = {}
    for r in rows:
        pid = (r.get("propertyID") or "").strip()
        if not pid:
            continue
        enum = tuple(v for v in (r.get("enum") or "").split("|") if v)
        out[pid] = FieldSpec(
            property_id=pid,
            block=(r.get("block") or "").strip(),
            datatype=(r.get("valueDatatype") or "").strip(),
            mandatory=(r.get("mandatory") or "").strip().upper() == "TRUE",
            repeatable=(r.get("repeatable") or "").strip().upper() == "TRUE",
            description=(r.get("description") or "").strip(),
            enum=enum,
        )
    if not out:
        raise MetadataError("Metadata-Model-DCTAP ist leer")
    return out


REQUIRED_FIELDS = tuple(sorted(k for k, v in load_tap().items() if v.mandatory))


#: Der Schluessel, der die Herkunft der Rechtezusage traegt. Er steht
#: ABSICHTLICH nicht in der DCTAP: Das Metadata Model beschreibt das Interview,
#: nicht den Verwaltungsakt, auf dem seine Freigabe beruht. Deshalb geht er auch
#: nicht in ``fields`` — sonst meldete ihn ``check_record`` als Feld, das das
#: Modell nicht kennt, und es haette recht damit.
CONSENT_REFERENCE_KEY = "consent_reference"

#: Was in der Eingabedatei stehen MUSS: die sieben Pflichtfelder des Modells
#: und die Herkunft der Rechtezusage. Keine Vorgabewerte, keine fremden
#: Schluessel — dasselbe Muster wie ``adapters/models/ollama.py::CONFIG_KEYS``.
RECORD_INPUT_KEYS = (*REQUIRED_FIELDS, CONSENT_REFERENCE_KEY)

#: Dieselbe Strenge wie eine Entscheidungsreferenz (``domain/decision.py``):
#: ein Token ohne Whitespace, 3 bis 64 Zeichen. Ein mehrwortiger Freitext waere
#: keine Referenz, sondern eine Notiz, und eine Notiz laesst sich nicht
#: nachschlagen.
_REFERENCE_RE = re.compile(r"^[\w.:@/+-]{3,64}$")

#: Die drei Buchstaben von ISO 639-3, so wie die DCTAP sie verlangt.
_LANGUAGE_RE = re.compile(r"^[a-z]{3}$")

_NICHTS = "Kein Lauf, nichts geschrieben."


class RecordMetadataError(MetadataError):
    """Die Eingabedatei eines Records fehlt oder ist formfalsch.

    Getrennt von den Befunden aus :func:`check_record`, weil die Antwort eine
    andere ist: Ein Befund benennt eine offene Anforderung und laesst den Lauf
    weiterlaufen (der Ausgang entscheidet darueber, ``export.py``); eine
    formfalsche Datei ist eine Behauptung, deren Inhalt unklar ist, und die
    haelt sofort an.
    """


@dataclass(frozen=True)
class RecordMetadataInput:
    """Was der Operator je Interview eingetragen hat, in zwei Haelften.

    ``fields`` sind die Felder des Modells und gehen so in den Katalogentwurf.
    ``consent_reference`` gehoert nicht dazu: Sie sagt, WORAUF die Zusage
    beruht, und das ist eine Angabe ueber die Freigabe, keine ueber das
    Interview.
    """

    fields: dict[str, Any]
    consent_reference: str
    raw: bytes
    path: Path


def _fehler(pfad: Path, schluessel: str | None, grund: str) -> RecordMetadataError:
    ort = f"{pfad}" if schluessel is None else f"{pfad}, Schlüssel {schluessel!r}"
    return RecordMetadataError(f"{ort}: {grund} {_NICHTS}")


def load_record_metadata(path: Path, *, record_id: str) -> RecordMetadataInput:
    """Liest die Eingabedatei eines Records streng und gibt ihre Rohbytes mit.

    Streng heisst: alle acht Schluessel, keine fremden, alle Werte nicht leerer
    Text. Der Grund fuer die Haerte steht im Unterschied zu ``check_record``:
    Dort ist ein fehlender Wert eine offene Anforderung, hier ist ein
    unbekannter Schluessel ein Tippfehler, der still nichts taete.

    ``record_id`` wird gegen den Aufruf gehalten. Der Dateiname ist keine
    Pruefung: Eine kopierte, umbenannte oder in den falschen Ordner gelegte
    Eingabedatei ist genau der Fehler, der unbemerkt in einen Katalogeintrag
    laeuft, und dort ist er nicht mehr sichtbar.

    ``consent_reference`` traegt die Herkunft der Rechtezusage.
    ``consent_status`` wird nicht beim Eintragen ENTSCHIEDEN, sondern vom
    Controller ausserhalb dieses Systems; was hier passiert, ist eine
    Uebertragung. Der Beleg soll deshalb sagen, WORAUF die Zusage beruht, und
    nicht nur, wer sie getippt hat. Die Formstrenge ist die einer
    Entscheidungsreferenz, weil der Wert dieselbe Aufgabe hat: nachschlagbar
    sein.

    Die ROHBYTES reisen mit. Was der Operator geschrieben hat, ist die Aussage;
    eine kanonisierte Zweitfassung waere ein Objekt, dessen Verhaeltnis zur
    ersten niemand belegt.
    """
    if not path.exists():
        raise _fehler(path, None, "Metadateneingabe fehlt.")
    try:
        roh = path.read_bytes()
        block = tomllib.loads(roh.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise _fehler(path, None, f"nicht lesbar ({exc}).") from exc

    inhalt = block.get("record")
    if not isinstance(inhalt, dict):
        raise _fehler(path, "record", "Abschnitt [record] fehlt oder ist kein Abschnitt.")

    fremd = sorted(set(inhalt) - set(RECORD_INPUT_KEYS))
    if fremd:
        raise _fehler(
            path,
            ", ".join(fremd),
            "unbekannter Schlüssel. Ein unbekannter Schlüssel ist keine Erweiterung, "
            "sondern ein Tippfehler, der still nichts tut.",
        )
    fehlend = sorted(set(RECORD_INPUT_KEYS) - set(inhalt))
    if fehlend:
        raise _fehler(
            path,
            ", ".join(fehlend),
            "fehlt. Für keine dieser Angaben gibt es einen sicheren Vorgabewert.",
        )

    for schluessel in RECORD_INPUT_KEYS:
        wert = inhalt[schluessel]
        if not isinstance(wert, str) or not wert.strip():
            raise _fehler(
                path, schluessel, f"muss nicht leerer Text sein, ist {type(wert).__name__}."
            )

    if inhalt["record_id"] != record_id:
        raise _fehler(
            path,
            "record_id",
            f"nennt {inhalt['record_id']!r}, der Aufruf gilt {record_id!r}. Der Dateiname "
            "ist keine Prüfung; eine falsch zugeordnete Eingabe wäre im Katalogeintrag "
            "nicht mehr sichtbar.",
        )
    if not _REFERENCE_RE.match(inhalt[CONSENT_REFERENCE_KEY]):
        raise _fehler(
            path,
            CONSENT_REFERENCE_KEY,
            f"{inhalt[CONSENT_REFERENCE_KEY]!r} ist kein Token (3-64 Zeichen, kein "
            "Whitespace). Verlangt ist dieselbe Form wie bei einer "
            "Entscheidungsreferenz: nachschlagbar, nicht erzählt.",
        )
    if not _LANGUAGE_RE.match(inhalt["language"]):
        raise _fehler(
            path,
            "language",
            f"{inhalt['language']!r} ist kein ISO-639-3-Code (drei Kleinbuchstaben).",
        )
    try:
        date.fromisoformat(inhalt["interview_date"])
    except ValueError as exc:
        raise _fehler(
            path,
            "interview_date",
            f"{inhalt['interview_date']!r} ist kein Datum nach ISO 8601 (JJJJ-MM-TT).",
        ) from exc

    return RecordMetadataInput(
        fields={k: inhalt[k] for k in REQUIRED_FIELDS},
        consent_reference=inhalt[CONSENT_REFERENCE_KEY],
        raw=roh,
        path=path,
    )


def _datentyp_befunde(name: str, spec: FieldSpec, wert: Any) -> list[str]:
    """Der ``valueDatatype`` der DCTAP, geprueft statt mitgefuehrt.

    Bis hierher stand der Typ in der Tabelle und wurde nirgends benutzt:
    ``interview_date = "gestern"`` lief ohne einen einzigen Befund durch, und
    ein Katalogeintrag mit einem Datum, das keines ist, kam an keiner Stelle
    mehr zum Halt. Ein Wertebereich, der nur dasteht, ist kein Wertebereich.

    ``repeatable`` wird mitgelesen: Ein wiederholbares Feld traegt eine Liste,
    und jeder Eintrag wird einzeln geprueft. Ohne das faellt ein gueltiges
    ``keywords = ["a", "b"]`` an einer Typregel, die es gar nicht meint.
    """
    werte = wert if (spec.repeatable and isinstance(wert, list)) else [wert]
    if spec.repeatable and not isinstance(wert, list):
        return [f"{name} ist wiederholbar und verlangt eine Liste, ist aber "
                f"{type(wert).__name__}"]

    befunde: list[str] = []
    for einzeln in werte:
        if spec.datatype == "date":
            if not isinstance(einzeln, str):
                befunde.append(f"{name}={einzeln!r} ist kein Datum (erwartet Text nach ISO 8601)")
                continue
            try:
                date.fromisoformat(einzeln)
            except ValueError:
                befunde.append(
                    f"{name}={einzeln!r} ist kein Datum nach ISO 8601 (erwartet JJJJ-MM-TT)"
                )
        elif spec.datatype == "string":
            # bool ist in Python ein int und waere hier ohne die Zusatzfrage
            # ein gueltiger Wert, sobald jemand ihn in Text giesst.
            if not isinstance(einzeln, str):
                befunde.append(
                    f"{name}={einzeln!r} ist kein Text, sondern {type(einzeln).__name__}"
                )
        elif spec.datatype == "object" and not isinstance(einzeln, dict):
            befunde.append(f"{name} verlangt ein Objekt, ist aber {type(einzeln).__name__}")
    return befunde


def check_record(
    record: dict[str, Any],
    *,
    consent_vocabulary: tuple[str, ...] = (),
) -> list[str]:
    """Prüft einen Metadatensatz gegen das Modell. Liefert Befunde, wirft nicht.

    ``consent_vocabulary`` kommt aus dem Projektprofil. Das Modell schreibt am
    Core bewusst kein Consent-Enum vor, weil Consent-Regime sich zwischen
    Disziplinen unterscheiden — die Einschränkung ist Profilsache. ``withdrawn``
    bleibt aber immer erlaubt, auch wenn ein Profil es nicht aufführt.
    """
    tap = load_tap()
    problems: list[str] = []

    for name in REQUIRED_FIELDS:
        value = record.get(name)
        if value is None or (isinstance(value, str) and not value.strip()):
            problems.append(f"Pflichtfeld {name!r} fehlt")

    # Ein Feldname, den das Modell nicht kennt, ist ein BEFUND und kein
    # Beifang. Vorher fiel er stillschweigend heraus: Der Operator sah seinen
    # Wert dastehen, das Pflichtfeld galt weiter als fehlend, und die einzige
    # Auskunft war die zweite Haelfte davon. Ein Tippfehler im Feldnamen ist
    # genau die Sorte Fehler, die man nur sieht, wenn jemand sie nennt.
    for name in sorted(record):
        if name not in tap:
            problems.append(f"{name!r} ist kein Feld des Metadata Models")

    for name, spec in tap.items():
        if name not in record or record[name] is None:
            continue
        problems.extend(_datentyp_befunde(name, spec, record[name]))
        if spec.enum and str(record[name]) not in spec.enum:
            problems.append(
                f"{name}={record[name]!r} steht nicht im Wertebereich ({' | '.join(spec.enum)})"
            )

    consent = record.get("consent_status")
    if consent is not None and consent_vocabulary:
        allowed = set(consent_vocabulary) | {WITHDRAWN}
        if consent not in allowed:
            problems.append(
                f"consent_status={consent!r} steht nicht im Profilvokabular "
                f"({' | '.join(sorted(allowed))})"
            )

    # Die Invariante aus dem Vokabular — erzwingbar, also erzwungen.
    if consent == WITHDRAWN and record.get("accessRights") != CLOSED:
        problems.append(
            "consent_status='withdrawn' verlangt accessRights='closed' "
            f"(gefunden: {record.get('accessRights')!r})"
        )

    return problems
