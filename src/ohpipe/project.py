"""Projektprofil und Arbeitsbereich.

Zwei Trennungen, beide aus DINOH übernommen:

1. **Code / Governance / Daten** liegen in drei getrennten Bäumen, und es gibt
   GENAU EINEN Zeiger: ``OHPIPE_DATA_ROOT``. Kein Per-Datei-Override — jeder
   einzelne wäre ein Weg, einen echten Record mit einer fremden Blockliste
   zusammenzubringen. Diese Klasse Loch war schon einmal offen.

2. **Kern / Profil.** Der Kern kennt keine Projekt-IDs. Das Präfix, die
   Sprachen, das Consent-Modell und das Exportziel kommen aus dem Profil.
   ``CHILDLUX-%04d`` im Kern zu verdrahten war der Grund, warum das
   Vorgängersystem nicht projektneutral werden konnte.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import tempfile
import tomllib
from contextlib import suppress
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .domain.pii import EntityType
from .domain.step import build_graph, graph_contract_fingerprint
from .domain.token import TOKEN_RE, TOKEN_RULE
from .store import ContentStore

__all__ = [
    "DataRootError",
    "GraphBinding",
    "GraphBindingError",
    "GraphBindingState",
    "Profile",
    "ProfileError",
    "Workspace",
    "WorkspaceUnsafe",
]

ENV_ROOT = "OHPIPE_DATA_ROOT"

#: 0700 auf alles, was zur Datenwurzel gehoert. Siehe Workspace.ensure().
DIR_MODE = 0o700
_ID_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,15}$")

#: Laufzeitsysteme, die es tatsaechlich gibt. Allowlist, damit ein Tippfehler
#: in `legacy_runtime` nicht zu einem Eigentuemer fuehrt, den niemand
#: ablösen kann.
THIS_RUNTIME = "ohpipe"
BEKANNTE_RUNTIMES = frozenset({THIS_RUNTIME, "dinoh"})

#: Allowlist. Ein unbekannter Schluessel ist ein Fehler und kein Kommentar.
PROFILE_FIELDS = frozenset(
    {
        "id",
        "record_prefix",
        "record_digits",
        "languages",
        "processing_routes",
        "coding_mode",
        "coverage_threshold",
        "export_targets",
        "consent_vocabulary",
        "key_required",
        "pseudonymisation_required",
        "pii_detection",
        "pseudonymisation_policy_version",
        "pseudonymisation_rules",
        "production",
        "legacy_runtime",
        "description",
        "model_vocabulary",
        "codebook",
    }
)


class ProfileError(ValueError):
    pass


class ModelNotAllowed(ProfileError):
    """Das benannte Modell steht nicht in der geschlossenen Liste des Profils.

    Eigene Klasse, weil die Antwort eine andere ist als bei einem Profilfehler:
    Ein fehlendes Profil korrigiert man (CONFIG), ein Modell ausserhalb der
    Liste ist ein Halt (STOP). Die Liste ist keine Empfehlung — sie ist die
    Menge der Gewichte, ueber die fuer diesen Bestand entschieden wurde.
    """


class DataRootError(ProfileError):
    """Mit der Datenwurzel stimmt etwas nicht — kein Profilfehler.

    Eigene Klasse, weil die Klassifikation vorher per Substringsuche in einer
    DEUTSCHEN Fehlermeldung geschah (``ENV_ROOT in str(exc)``). Sobald jemand
    den Text umformuliert, kippt der reason_code lautlos — und der Operator
    bekommt ein NEXT, das seinen Fall nicht anfasst.
    """


class WorkspaceUnsafe(ProfileError):
    """Die Struktur der Datenwurzel ist nicht die, für die eingestanden wird.

    Eigene Klasse, weil die Antwort eine andere ist: Ein fehlendes Profil
    korrigiert man, einen untergeschobenen Symlink untersucht man.
    """


class GraphBindingError(WorkspaceUnsafe):
    """Die gespeicherte Graphbindung ist nicht streng und sicher lesbar."""


class GraphBindingState(str, Enum):
    """Zustand der Bindung, bevor ein Journal ausgewertet oder verändert wird."""

    CURRENT = "CURRENT"
    UNBOUND = "UNBOUND"
    MISMATCH = "MISMATCH"


@dataclass(frozen=True)
class GraphBinding:
    """Der kleine, journalexterne Vertrag eines Arbeitsbereichs."""

    profile: str
    graph_sha256: str
    schema: int = 1


@dataclass(frozen=True)
class Profile:
    id: str
    record_prefix: str
    record_digits: int = 4
    languages: tuple[str, ...] = ()
    #: Erlaubte Verarbeitungswege. Allowlist, nicht Blacklist.
    processing_routes: tuple[str, ...] = ("local",)
    coding_mode: str = "descriptive_l1"
    #: Mindest-Coverage, unter der ein Lauf nicht als PASS gilt.
    coverage_threshold: float = 0.90
    export_targets: tuple[str, ...] = ("webvtt",)
    #: Erlaubte consent_status-Werte dieses Projekts. Das Metadata Model
    #: schreibt am Core bewusst kein Enum vor — die Einschränkung ist
    #: Profilsache. `withdrawn` bleibt immer zusätzlich erlaubt.
    #: (Vorher hieß das Feld `consent_model` und war eine Projekteigenschaft.
    #: Das war falsch modelliert: Consent variiert je Interview, nicht je
    #: Projekt. Der Record trägt `consent_status`, das Profil den Wertebereich.)
    consent_vocabulary: tuple[str, ...] = ()
    #: Verlangt dieses Profil eine authentifizierte Evidenzkette?
    #: Steht IM PROFIL, also außerhalb der Datenwurzel — damit kann eine
    #: vergessene Umgebungsvariable die Prüfung nicht still abschalten
    #: (ADR 0017).
    key_required: bool = False
    #: Verlangt dieses Profil den Pseudonymisierungsschritt? (ADR 0024)
    #: Kein sicherheitsrelevanter False-Default für Produktionsprofile: Fehlt
    #: die Angabe dort, ist das Profil ungültig statt stillschweigend „nein".
    pseudonymisation_required: bool = False
    #: Verarbeitet dieses Profil reale Daten? Steuert, welche Angaben
    #: ausdrücklich getroffen werden MÜSSEN, statt vorbelegt zu sein.
    production: bool = False
    #: Name des Vorgängersystems, dem unbekannte Records dieses Profils
    #: gehören — oder "" für ein Profil ohne Vorgänger.
    #:
    #: Das kam erst mit dem ERSTEN Schreibpfad ans Licht: ``CutoverLedger``
    #: nahm global ``dinoh`` als Standardeigentümer an. Für ``childlux`` ist
    #: das genau richtig — unbekannte Records gehören dem Altsystem, aus
    #: Unwissen folgt kein Schreibrecht (ADR 0009). Für ``sandbox`` gibt es
    #: aber gar kein Altsystem, und ``ingest`` verweigerte die Aufnahme eines
    #: synthetischen Records mit dem Hinweis, er gehöre DINOH.
    #:
    #: Die Wache war nicht falsch. Falsch war, dass ihre wichtigste Annahme
    #: keine Profileigenschaft war — und das fiel neun Monate nicht auf, weil
    #: sie nie aufgerufen wurde.
    legacy_runtime: str = ""
    description: str = ""
    #: Die geschlossene Modellliste dieses Profils, in Reihenfolge, mit EXAKTEN
    #: Tags. Der erste Eintrag ist die Vorgabe. Gebaut nach dem Vorbild von
    #: ``consent_vocabulary``: das Profil traegt den Wertebereich, geprueft wird
    #: beim Schreiben. Ein Unterschied zum Consent ist bewusst — dort gibt es
    #: mit ``withdrawn`` einen immer zusaetzlich gueltigen Wert, hier gibt es
    #: keinen: Eine leere Liste heisst KEIN Modell, nicht KEINE Pruefung.
    #: ``check_model`` haelt deshalb auch bei leerer Liste an, und ein
    #: Produktionsprofil muss den Schluessel ausdruecklich fuehren (siehe
    #: ``load``); die leere Liste ist dort die Angabe „kein Modell entschieden".
    model_vocabulary: tuple[str, ...] = ()
    codebook: str = ""
    pii_detection: str = ""
    pseudonymisation_policy_version: str = ""
    pseudonymisation_rules: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # P4a: kein erratener Erkennermodus bei verpflichtendem Pfad.
        if self.pseudonymisation_required and self.pii_detection not in ("manual", "model"):
            raise ProfileError("pii_detection muss ausdrücklich manual oder model sein")
        if self.pii_detection and self.pii_detection not in ("manual", "model"):
            raise ProfileError("unbekannter pii_detection-Modus")
        if not self.pseudonymisation_required and self.pii_detection:
            raise ProfileError("pii_detection widerspricht dem direkten Pfad")
        if self.pii_detection != "manual":
            if self.pseudonymisation_policy_version or self.pseudonymisation_rules:
                raise ProfileError("Ersatzregeln verlangen pii_detection=manual")
            return
        if not self.pseudonymisation_policy_version.strip():
            raise ProfileError("pseudonymisation_policy_version fehlt")
        rules = dict(self.pseudonymisation_rules)
        if len(rules) != len(self.pseudonymisation_rules) or set(rules) != {
            t.value for t in EntityType
        }:
            raise ProfileError("pseudonymisation_rules müssen genau alle EntityType-Werte abdecken")
        for entries in rules.values():
            rule = dict(entries)
            action = rule.get("action")
            keys = {
                "keep": {"action"},
                "remove": {"action"},
                "coarsen": {"action", "value"},
                "pseudonym": {"action", "scope", "entity_key"},
            }
            if action not in keys or set(rule) != keys[action] or len(entries) != len(rule):
                raise ProfileError("ungültige Aktion oder unvollständige Ersatzregel")
            if any(not isinstance(v, str) or not v.strip() for v in rule.values()):
                raise ProfileError("Regelparameter müssen nichtleere Zeichenketten sein")
            if action == "pseudonym" and rule["entity_key"] != "opaque-entity-id":
                raise ProfileError("Pseudonyme verlangen opake Entity-ID")

    @property
    def pseudonymisation_policy_sha256(self) -> str | None:
        """Kanonischer Inhaltsdigest, kein Lauf-/Registerbeleg."""
        if self.pii_detection != "manual":
            return None
        value = {
            "domain": "ohpipe/pseudonymisation-policy",
            "v": 1,
            "version": self.pseudonymisation_policy_version,
            "rules": {typ: dict(entries) for typ, entries in self.pseudonymisation_rules},
        }
        return hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()

    @property
    def default_model(self) -> str:
        """Der erste Eintrag der Liste, sonst die leere Zeichenkette."""
        return self.model_vocabulary[0] if self.model_vocabulary else ""

    def check_model(self, tag: str) -> str:
        """Haelt an, wenn ``tag`` nicht in der Liste steht. Sonst gibt er ihn zurueck.

        Kein Warnpfad: Ein Modell ausserhalb der Liste ist keine Abweichung, die
        man vermerkt und dann doch faehrt.

        Und eine LEERE Liste haelt ebenfalls an. Sie ist kein fehlendes Urteil,
        sondern eines: Fuer dieses Profil ist ueber kein Gewicht entschieden
        worden, also ist keines freigegeben. Die Gegenlesart -- keine Liste,
        keine Pruefung -- macht die Freigabe genau dort wirkungslos, wo noch
        niemand sie gefuellt hat, und das ist die einzige Stelle, an der sie
        gebraucht wird.
        """
        if not self.model_vocabulary:
            raise ModelNotAllowed(
                f"Profil {self.id!r} führt kein Modellvokabular; kein Modell ist "
                "freigegeben. Kein Lauf."
            )
        if tag not in self.model_vocabulary:
            raise ModelNotAllowed(
                f"Modell {tag!r} ist im Profil {self.id!r} nicht freigegeben "
                f"(model_vocabulary: {', '.join(self.model_vocabulary)}). Kein Lauf. "
                "Ein Eintrag ist ein exakter Tag; eine Familie ist kein Eintrag."
            )
        return tag

    def record_id(self, n: int) -> str:
        return f"{self.record_prefix}-{n:0{self.record_digits}d}"

    def is_record_id(self, value: str) -> bool:
        return bool(
            re.fullmatch(rf"{re.escape(self.record_prefix)}-\d{{{self.record_digits}}}", value)
        )

    def normalize_record_id(self, value: str) -> str:
        """Nimmt ``7`` oder ``CHILDLUX-0007`` und liefert die kanonische Form."""
        value = value.strip()
        if value.isdigit():
            return self.record_id(int(value))
        if self.is_record_id(value):
            return value
        raise ProfileError(
            f"Unbekannte Record-Kennung: {value!r} (erlaubt: 7 oder {self.record_id(7)})"
        )

    @classmethod
    def load(cls, path: Path) -> Profile:
        """Allowlist und Typstrenge — dieselbe Disziplin wie ``Span.from_json``.

        Die Vorgängerfassung verwarf unbekannte Schlüssel kommentarlos. Das
        traf den sicherheitsrelevantesten Schalter des Systems: Ein vertipptes
        ``key_requred = true`` degradierte ein Produktionsprofil wortlos zu
        einem unauthentifizierten Arbeitsprotokoll. ADR 0017 begründet
        ausführlich, warum diese Angabe ins Profil gehört und nicht in eine
        Umgebungsvariable, „die man vergessen kann" — ein Tippfehler ist
        dasselbe Vergessen, nur schlechter sichtbar.

        Ebenso ungeprüft blieben ``record_digits = 0`` und ein
        ``coverage_threshold`` außerhalb von [0, 1].
        """
        raw = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        unbekannt_oben = set(raw) - {"profile"}
        if unbekannt_oben:
            raise ProfileError(
                f"{path}: unbekannte Abschnitte: {', '.join(sorted(unbekannt_oben))}"
            )
        p = raw.get("profile", {})
        if not isinstance(p, dict):
            raise ProfileError(f"{path}: [profile] ist kein Abschnitt.")

        unbekannt = set(p) - PROFILE_FIELDS
        if unbekannt:
            raise ProfileError(
                f"{path}: unbekannte Felder: {', '.join(sorted(unbekannt))}. "
                "Ein vertipptes Feld ist eine stillschweigend nicht gesetzte Zusicherung "
                "— gerade bei key_required und pseudonymisation_required."
            )

        def text(k: str, pflicht: bool = False) -> str:
            v = p.get(k, "")
            if not isinstance(v, str):
                raise ProfileError(f"{path}: {k} muss eine Zeichenkette sein.")
            if pflicht and not v.strip():
                raise ProfileError(f"{path}: {k} fehlt oder ist leer.")
            return v

        def liste(k: str) -> tuple[str, ...]:
            v = p.get(k, [])
            if not isinstance(v, list) or any(not isinstance(x, str) for x in v):
                raise ProfileError(f"{path}: {k} muss eine Liste von Zeichenketten sein.")
            return tuple(v)

        def wahrheit(k: str) -> bool:
            """Strikt. ``"false"`` ist als Zeichenkette wahr — genau der Fall,
            der eine Sicherheitszusage lautlos umkehrt."""
            v = p.get(k, False)
            if not isinstance(v, bool):
                raise ProfileError(
                    f"{path}: {k} muss ein echter Boolescher Wert sein (true/false), "
                    f"nicht {type(v).__name__}."
                )
            return v

        for pflichtfeld in ("id", "record_prefix"):
            text(pflichtfeld, pflicht=True)
        if not _ID_RE.match(p["record_prefix"]):
            raise ProfileError(
                f"{path}: record_prefix {p['record_prefix']!r} muss GROSS, 2-16 Zeichen sein"
            )

        digits = p.get("record_digits", 4)
        if isinstance(digits, bool) or not isinstance(digits, int) or not 1 <= digits <= 12:
            raise ProfileError(f"{path}: record_digits muss eine ganze Zahl in [1, 12] sein.")

        schwelle = p.get("coverage_threshold", 0.90)
        if isinstance(schwelle, bool) or not isinstance(schwelle, (int, float)):
            raise ProfileError(f"{path}: coverage_threshold muss eine Zahl sein.")
        if not 0.0 <= float(schwelle) <= 1.0:
            raise ProfileError(
                f"{path}: coverage_threshold muss in [0, 1] liegen (ist {schwelle})."
            )

        # `legacy_runtime` ist der DRITTE Sicherheitsschalter und bekam
        # zunaechst keine der Behandlungen der ersten beiden. Ein
        # Produktionsprofil konnte sich damit selbst zum Alt-Runtime erklaeren:
        # `legacy_runtime = "ohpipe"` heisst, unbekannte Records gehoeren uns —
        # exakt das Fail-open, gegen das ADR 0009 und 0014 stehen.
        legacy = text("legacy_runtime")
        if legacy and legacy not in BEKANNTE_RUNTIMES:
            raise ProfileError(
                f"{path}: legacy_runtime {legacy!r} ist kein bekanntes Laufzeitsystem. "
                f"Bekannt sind: {', '.join(sorted(BEKANNTE_RUNTIMES))}. Ein Tippfehler "
                "hier hiesse, dass unbekannte Records einem System gehoeren, das es "
                "nicht gibt — und niemand duerfte je schreiben."
            )
        if legacy == THIS_RUNTIME:
            raise ProfileError(
                f"{path}: legacy_runtime darf nicht {THIS_RUNTIME!r} sein. Das Profil "
                "erklaerte sich damit selbst zum Vorgaengersystem; unbekannte Records "
                "gehoerten dann ohpipe, und die Schreibwache waere wirkungslos "
                "(ADR 0009). Fuer ein Projekt ohne Vorgaenger bleibt das Feld leer."
            )

        # Modellvokabular: dieselbe Tokenstrenge wie jeder andere technische
        # Bezeichner (ADR 0011: geschlossene Vokabulare, unbekannter Wert haelt
        # an). Reihenfolge ist bedeutungstragend — der erste Eintrag ist die
        # Vorgabe —, deshalb faellt eine Dublette: sie waere keine groessere
        # Menge, sondern eine zweite Vorgabe an anderer Stelle.
        vokabular = liste("model_vocabulary")
        for tag in vokabular:
            if not TOKEN_RE.fullmatch(tag):
                raise ProfileError(
                    f"{path}: model_vocabulary-Eintrag {tag!r} ist kein kanonischer "
                    f"Token ({TOKEN_RULE})."
                )
            if tag.count(":") != 1:
                raise ProfileError(
                    f"{path}: model_vocabulary-Eintrag {tag!r} ist kein exakter Tag. "
                    "Verlangt ist genau ein Doppelpunkt: ohne ihn ergaenzt die Registry "
                    "stumm ':latest', und derselbe Wortlaut waere morgen ein anderes "
                    "Gewicht — eine Familie ist kein Element."
                )
        if len(set(vokabular)) != len(vokabular):
            raise ProfileError(f"{path}: model_vocabulary enthaelt einen Eintrag doppelt.")

        produktion = wahrheit("production")
        codebook = text("codebook")
        if codebook:
            if codebook in {".", ".."} or any(c in codebook for c in ("/", "\\", "..", "\0")):
                raise ProfileError(f"{path}: codebook muss ein Dateiname ohne Pfad und '..' sein.")
            directory = Path(path).resolve().parent
            candidate = directory / codebook
            if not candidate.is_file() or candidate.resolve().parent != directory:
                raise ProfileError(
                    f"{candidate}: Codebuch fehlt oder liegt außerhalb des Profilverzeichnisses."
                )
        if produktion:
            # Fuer ein Produktionsprofil gibt es keinen sicheren Default. Fehlt
            # die Angabe, ist das Profil ungueltig - nicht stillschweigend nein.
            # ``model_vocabulary`` steht hier aus demselben Grund wie die drei
            # anderen, aber die Pruefung ist eine andere: verlangt ist das
            # VORHANDENSEIN, nicht ein Inhalt. Die leere Liste ist erlaubt und
            # bedeutet „kein Modell entschieden" — ``check_model`` haelt dann
            # an. Ein FEHLENDER Schluessel bedeutet dagegen gar nichts, und
            # genau das darf ein Produktionsprofil nicht sagen.
            fehlend = [
                k
                for k in (
                    "key_required",
                    "pseudonymisation_required",
                    "legacy_runtime",
                    "model_vocabulary",
                )
                if k not in p
            ]
            if fehlend:
                raise ProfileError(
                    f"{path}: Produktionsprofil ohne ausdrückliche Angabe von "
                    f"{', '.join(fehlend)}. Für diese Angaben gibt es keinen sicheren "
                    "Vorgabewert (ADR 0017, ADR 0024)."
                )

        rules = p.get("pseudonymisation_rules", {})
        if not isinstance(rules, dict) or any(
            not isinstance(rule, dict) or any(not isinstance(v, str) for v in rule.values())
            for rule in rules.values()
        ):
            raise ProfileError("pseudonymisation_rules verlangt Tabellen mit Textparametern")
        return cls(
            pii_detection=text("pii_detection"),
            pseudonymisation_policy_version=text("pseudonymisation_policy_version"),
            pseudonymisation_rules=tuple(
                (typ, tuple(sorted(rule.items()))) for typ, rule in sorted(rules.items())
            ),
            id=p["id"],
            record_prefix=p["record_prefix"],
            record_digits=digits,
            languages=liste("languages"),
            processing_routes=liste("processing_routes") or ("local",),
            coding_mode=text("coding_mode") or "descriptive_l1",
            coverage_threshold=float(schwelle),
            export_targets=liste("export_targets") or ("webvtt",),
            consent_vocabulary=liste("consent_vocabulary"),
            key_required=wahrheit("key_required"),
            pseudonymisation_required=wahrheit("pseudonymisation_required"),
            legacy_runtime=text("legacy_runtime"),
            production=produktion,
            description=text("description"),
            model_vocabulary=vokabular,
            codebook=codebook,
            raw=raw,
        )


@dataclass(frozen=True)
class Workspace:
    """Der EINE Zeiger und alles, was sich daraus ableitet."""

    root: Path
    profile: Profile

    @property
    def records(self) -> Path:
        return self.root / "records"

    @property
    def governance(self) -> Path:
        return self.root / "_governance"

    @property
    def journal_path(self) -> Path:
        return self.governance / "journal.jsonl"

    @property
    def cutover_path(self) -> Path:
        return self.governance / "cutover.json"

    @property
    def graph_binding_path(self) -> Path:
        """Die Bindung liegt neben, nie in der append-only Evidenzkette."""
        return self.governance / "graph-contract.json"

    def running_graph_sha256(self) -> str:
        """Der laufende Vertrag für genau das aufgelöste Projektprofil."""
        return graph_contract_fingerprint(build_graph(self.profile))

    def graph_binding(self) -> GraphBinding | None:
        """Liest die Bindung strikt und ohne einem Symlink zu folgen."""
        path = self.graph_binding_path
        try:
            st = path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise GraphBindingError(f"Graphbindung nicht prüfbar: {exc}") from exc
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise GraphBindingError(f"Graphbindung {path} ist keine reguläre Datei ohne Symlink.")
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                opened = os.fstat(fd)
                if not stat.S_ISREG(opened.st_mode):
                    raise GraphBindingError(f"Graphbindung {path} ist keine reguläre Datei.")
                mode = stat.S_IMODE(opened.st_mode)
                if mode != 0o600:
                    raise GraphBindingError(
                        f"Graphbindung {path} hat Modus {mode:o}, erwartet 600."
                    )
                blob = os.read(fd, 65537)
                if len(blob) > 65536:
                    raise GraphBindingError(f"Graphbindung {path} ist größer als 64 KiB.")
                raw = json.loads(blob.decode("utf-8"))
            finally:
                os.close(fd)
        except GraphBindingError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GraphBindingError(f"Graphbindung {path} ist nicht lesbar: {exc}") from exc

        erwartet = {"schema", "profile", "graph_sha256"}
        if not isinstance(raw, dict) or set(raw) != erwartet:
            raise GraphBindingError(
                f"Graphbindung {path} braucht exakt die Felder {sorted(erwartet)}."
            )
        if raw["schema"] != 1 or isinstance(raw["schema"], bool):
            raise GraphBindingError(f"Graphbindung {path}: schema muss die ganze Zahl 1 sein.")
        if not isinstance(raw["profile"], str) or not raw["profile"]:
            raise GraphBindingError(f"Graphbindung {path}: profile muss nichtleer sein.")
        sha = raw["graph_sha256"]
        if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{64}", sha) is None:
            raise GraphBindingError(
                f"Graphbindung {path}: graph_sha256 muss ein kleiner SHA-256 sein."
            )
        return GraphBinding(profile=raw["profile"], graph_sha256=sha)

    def inspect_graph_binding(self) -> tuple[GraphBindingState, GraphBinding | None, str]:
        """Liest einmal und vergleicht gespeicherten und laufenden Vertrag."""
        binding = self.graph_binding()
        running = self.running_graph_sha256()
        if binding is None:
            return GraphBindingState.UNBOUND, None, running
        if binding.profile != self.profile.id or binding.graph_sha256 != running:
            return GraphBindingState.MISMATCH, binding, running
        return GraphBindingState.CURRENT, binding, running

    def graph_binding_state(self) -> GraphBindingState:
        """Der benannte E8-Zustand für Aufrufer, die nur die Stufe brauchen."""
        return self.inspect_graph_binding()[0]

    def _binding_bytes(self) -> bytes:
        body = {
            "graph_sha256": self.running_graph_sha256(),
            "profile": self.profile.id,
            "schema": 1,
        }
        return (json.dumps(body, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
            "utf-8"
        )

    def _fsync_governance(self) -> None:
        """Macht auch den Verzeichniseintrag dauerhaft, soweit das FS es kann."""
        fd = os.open(self.governance, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                os.fsync(fd)
            except OSError as exc:
                if exc.errno not in {errno.EINVAL, errno.ENOTSUP}:
                    raise
        finally:
            os.close(fd)

    def bind_graph_initially(self) -> str:
        """Bindet nur einen neuen, noch journalfreien Arbeitsbereich."""
        if self.journal_path.exists():
            raise GraphBindingError(
                "Ein bestehendes Journal ohne Graphbindung ist Altbestand; "
                "dafür ist ein ausdrücklicher graph-upgrade nötig."
            )
        path = self.graph_binding_path
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            binding = self.graph_binding()
            if binding is None:
                raise GraphBindingError(f"Graphbindung {path} verschwand beim Lesen.") from None
            if (
                binding.profile != self.profile.id
                or binding.graph_sha256 != self.running_graph_sha256()
            ):
                raise GraphBindingError(
                    f"Graphbindung {path} entstand parallel mit einem anderen Vertrag."
                ) from None
            return ""
        except OSError as exc:
            raise GraphBindingError(f"Graphbindung {path} nicht anlegbar: {exc}") from exc
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(self._binding_bytes())
                fh.flush()
                os.fsync(fh.fileno())
            self._fsync_governance()
        except Exception:
            with suppress(OSError):
                path.unlink()
            raise
        return str(path)

    def upgrade_graph_binding(self) -> bool:
        """Schreibt die aktuelle Bindung atomar nach einem ausdrücklichen CLI-Akt."""
        # Eine beschädigte oder untergeschobene Bindung wird niemals durch ein
        # Upgrade verwischt. Erst sichern und untersuchen, dann handeln.
        existing = self.graph_binding()
        if (
            existing is not None
            and existing.profile == self.profile.id
            and existing.graph_sha256 == self.running_graph_sha256()
        ):
            return False

        fd, raw_tmp = tempfile.mkstemp(prefix=".graph-contract.", dir=self.governance)
        tmp = Path(raw_tmp)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(self._binding_bytes())
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.graph_binding_path)
            self._fsync_governance()
        except Exception:
            with suppress(OSError):
                os.close(fd)
            with suppress(OSError):
                tmp.unlink()
            raise
        return True

    @property
    def releases(self) -> Path:
        return self.root / "releases"

    @property
    def objects(self) -> Path:
        """Das Objektverzeichnis. **Nicht** die Wurzel für ``ContentStore``.

        ``ContentStore`` leitet sein Verzeichnis selbst als ``root/"objects"``
        ab. Wer diesen Pfad hineinreicht, bekommt ``objects/objects/`` — genau
        das ist passiert: ``ingest`` schrieb dorthin, ``doctor`` und ``status``
        lasen eine Ebene höher, und ``doctor`` zählte im Objektverzeichnis den
        Eintrag ``objects`` auf und stoppte mit „ist keine Objektadresse".

        Der Fehler war ein Wort. Möglich war er, weil es drei
        Konstruktionsstellen für denselben Speicher gab. Deshalb gibt es jetzt
        genau eine: :meth:`store`.
        """
        return self.root / "objects"

    def store(self) -> ContentStore:
        """Die EINZIGE Stelle, an der ein ``ContentStore`` entsteht.

        Drei Konstruktionsstellen für denselben Speicher sind derselbe Gedanke
        wie zwei Schreiber für ein Artefakt (ADR 0005) — und sie waren hier
        bereits auseinandergelaufen, ohne dass die gesamte Suite es sah: Jede Stelle
        war für sich konsistent, weil sie schrieb und las, was sie selbst
        konstruiert hatte.
        """
        return ContentStore(self.root)

    @property
    def index_path(self) -> Path:
        # Abgeleitet, jederzeit löschbar (ADR 008).
        return self.root / ".index" / "ohpipe.sqlite"

    def record_dir(self, record_id: str) -> Path:
        return self.records / record_id

    @classmethod
    def resolve(cls, profile_path: Path, root: Path | str | None = None) -> Workspace:
        raw = root or os.environ.get(ENV_ROOT)
        if not raw:
            raise DataRootError(
                f"Kein Datenwurzelverzeichnis. Setze {ENV_ROOT} oder übergib --root. "
                "Reale Daten liegen niemals im Repository."
            )
        root = Path(raw).expanduser().resolve()
        # Die Datenwurzel darf NICHT im Repository liegen. `.gitignore` ist ein
        # Netz, keine Trennung: eine reale .srt unter einem nicht erfassten
        # Muster wäre sonst eine Zeile `git add -A` von GitLab entfernt.
        repo = Path(__file__).resolve().parents[2]
        if root == repo or repo in root.parents:
            raise DataRootError(
                f"Datenwurzel {root} liegt im Repository ({repo}). "
                "Reale Daten und Governance-Zustand gehören außerhalb (ADR 0006)."
            )
        return cls(root=root, profile=Profile.load(profile_path))

    @property
    def managed_dirs(self) -> tuple[Path, ...]:
        """Die vier Verzeichnisse, die zur Datenwurzel gehören. Keines davon
        darf ein Symlink sein — sonst verwaltet ``ohpipe`` fremdes Gebiet."""
        return (self.records, self.governance, self.releases, self.objects)

    def unsafe_entries(self) -> list[str]:
        """Read-only: Was an der Struktur der Datenwurzel nicht stimmt.

        Getrennt von :meth:`ensure`, weil ``doctor`` nichts verändern darf
        (ADR 0004) und die Diagnose trotzdem dieselbe sein muss.
        """
        out: list[str] = []
        for p in self.managed_dirs:
            try:
                st = p.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:  # pragma: no cover - Rechte auf der Wurzel
                out.append(f"{p.name}/ nicht prüfbar: {exc}")
                continue
            if stat.S_ISLNK(st.st_mode):
                out.append(
                    f"{p.name}/ ist ein Symlink. Verzeichnisse der Datenwurzel sind echte "
                    "Verzeichnisse — ein Link führt aus dem Bereich hinaus, für den dieses "
                    "Werkzeug einsteht (ADR 0006)."
                )
            elif not stat.S_ISDIR(st.st_mode):
                out.append(f"{p.name}/ ist kein Verzeichnis ({stat.filemode(st.st_mode)}).")
        return out

    def ensure(self) -> list[str]:
        """Legt an, zieht eng — und meldet **jede** Änderung.

        Zwei Fehler dieser Funktion sind teuer bezahlt worden. ``exists()``,
        ``stat()`` und ``chmod()`` folgen Symlinks: Ein untergeschobener
        ``objects/``-Link ließ ``init`` den Modus eines Verzeichnisses
        AUSSERHALB der Datenwurzel ändern. Und die Änderung tauchte in der
        Rückgabe nicht auf, ``CHANGED`` meldete „keine".

        ``CHANGED: keine`` ist eine Zusage, kein Hinweis (ADR 0004). Deshalb
        jetzt: ``lstat`` vor jeder Veränderung, ``fchmod`` auf einem
        Deskriptor mit ``O_NOFOLLOW`` statt ``chmod`` auf einem Pfad, und
        jede Modusänderung steht in der Liste.
        """
        unsafe = self.unsafe_entries()
        if unsafe:
            raise WorkspaceUnsafe("; ".join(unsafe))

        changed: list[str] = []
        if not self.root.exists():
            self.root.mkdir(parents=True, mode=DIR_MODE)
            changed.append(str(self.root))
        for p in self.managed_dirs:
            if not p.exists():
                # 0700 hat keine Gruppen- oder Andere-Bits; die umask kann
                # daran nichts beschneiden. Ein nachträgliches chmod wäre eine
                # zweite, unnötige Veränderung.
                p.mkdir(mode=DIR_MODE)
                changed.append(str(p))
                continue
            fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                current = stat.S_IMODE(os.fstat(fd).st_mode)
                if current != DIR_MODE:
                    os.fchmod(fd, DIR_MODE)
                    changed.append(f"{p} (Modus {current:o} → {DIR_MODE:o})")
            finally:
                os.close(fd)
        return changed
