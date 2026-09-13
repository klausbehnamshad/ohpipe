"""Record-Ownership und Cutover.

Die Antwort auf die offene Frage aus dem Review: Ein `RETIRED`-Textfile genügt
nicht — aber nicht, weil es zu schwach wäre, sondern weil es die falsche
Körnung hat. Es legt einen ORDNER still. Was einen Eigentümer braucht, ist ein
RECORD.

Der Beleg steht in DINOHs eigener Notiz vom 14.07.2026: Der alte GO-LIVE-Ordner
trug bereits einen RETIRED-Marker und lief trotzdem weiter — "mit seinem
eigenen Manifest und seinem eigenen BUILDER_STATE". Die Gefahr war nie, dass
zwei Systeme existieren. Sie war, dass zwei Systeme DIESELBEN Records
schreiben konnten.

Daraus drei getrennte Dinge, von denen nur das letzte eine Sperre ist:

1. **Ownership** — ab Tag 1, kostet nichts. Genau ein schreibender Runtime pro
   Record. Jeder Runtime verweigert Records, die ihm nicht gehören. Das
   blockiert den laufenden Betrieb NICHT: DINOH besitzt weiterhin alles, was
   es heute besitzt.
2. **Fahrtrichtung** — Records wandern ohpipe-wärts. Ein Rückweg ist möglich,
   aber ein protokollierter Akt, keine Gewohnheit.
3. **Stilllegung** — die eigentliche Sperre, und erst am Ende: Besitzt ohpipe
   alle aktiven Records, verweigert DINOHs Schreibpfad vollständig.

Damit ist der Cutover keine Nacht-und-Nebel-Aktion, die man terminieren muss,
sondern die FOLGE davon, dass die Records gewandert sind.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = ["CutoverLedger", "Owner", "OwnershipError", "Transfer"]

#: Der Name dieses Runtimes. Ein anderer Runtime, der dieselbe Datenwurzel
#: liest, trägt einen anderen Namen — und schreibt deshalb nichts von uns.
THIS_RUNTIME = "ohpipe"
LEGACY_RUNTIME = "dinoh"


class OwnershipError(RuntimeError):
    """Ein Runtime hat versucht, einen fremden Record zu schreiben."""


@dataclass(frozen=True)
class Owner:
    runtime: str
    since: str
    reference: str = ""

    def to_json(self) -> dict[str, Any]:
        return {"runtime": self.runtime, "since": self.since, "reference": self.reference}


@dataclass(frozen=True)
class Transfer:
    record_id: str
    from_runtime: str
    to_runtime: str
    at: str
    reference: str
    #: Hashes der Artefakte im Moment der Übergabe. Macht die Übergabe
    #: nachprüfbar, ohne Inhalte zu versionieren.
    artifact_hashes: dict[str, str] = field(default_factory=dict)
    note: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "from": self.from_runtime,
            "to": self.to_runtime,
            "at": self.at,
            "reference": self.reference,
            "artifact_hashes": dict(self.artifact_hashes),
            "note": self.note,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class CutoverLedger:
    """Wer besitzt welchen Record — und wie kam es dazu.

    Liegt als ``cutover.json`` im Governance-Baum (nie in Git). Das
    Übergabeprotokoll ist namensfrei und kann als Beleg exportiert werden;
    genau das fehlte der bisherigen Stilllegung, die zwar operativ wirksam,
    aber nicht revisionsfest dokumentiert war.
    """

    #: NICHT gespeichert, sondern aus ``transfers`` abgeleitet. Eine frühere
    #: Fassung persistierte das Mapping — und ein handeditierter Eintrag
    #: verschaffte Schreibrecht, ohne dass eine Übergabe stattgefunden hätte.
    #: Ownership ist jetzt eine Funktion der protokollierten Übergaben, genau
    #: wie READY eine Funktion der Evidenz ist (ADR 0003).
    transfers: list[Transfer] = field(default_factory=list)
    #: Default für Records, die der Ledger nicht kennt. Fail-closed heißt hier
    #: NICHT "niemand darf": ein unbekannter Record gehört dem Legacy-Runtime,
    #: weil das der Zustand vor dem Cutover ist.
    default_runtime: str = LEGACY_RUNTIME
    version: int = 1
    #: Befunde aus ``from_journal(strict=False)``.
    problems: list[str] = field(default_factory=list)

    # -- Abgeleiteter Zustand ---------------------------------------------

    @property
    def owners(self) -> dict[str, Owner]:
        """Ergebnis des Abspielens aller Übergaben. Kein Speicherfeld."""
        out: dict[str, Owner] = {}
        for tr in self.transfers:
            out[tr.record_id] = Owner(runtime=tr.to_runtime, since=tr.at, reference=tr.reference)
        return out

    # -- Abfragen ---------------------------------------------------------

    def owner_of(self, record_id: str) -> str:
        o = self.owners.get(record_id)
        return o.runtime if o else self.default_runtime

    def may_write(self, record_id: str, runtime: str = THIS_RUNTIME) -> bool:
        return self.owner_of(record_id) == runtime

    def require_write(self, record_id: str, runtime: str = THIS_RUNTIME) -> None:
        """Fail-closed Schreibwache. Genau ein Aufrufpunkt vor jedem Schreibzugriff."""
        current = self.owner_of(record_id)
        if current != runtime:
            raise OwnershipError(
                f"{record_id} gehört '{current}', nicht '{runtime}'. "
                f"Kein Dual-Write. Übergabe: ohpipe adopt {record_id} --ref <Entscheidung>"
            )

    def retired(self, runtime: str = LEGACY_RUNTIME, active: set[str] | None = None) -> bool:
        """Ist ``runtime`` stillgelegt — besitzt er also keinen aktiven Record mehr?

        Die Stilllegung ist eine ABGELEITETE Eigenschaft, kein Schalter. Genau
        wie READY (ADR 003).

        ``active`` ist PFLICHT: Ohne die Menge der tatsächlich aktiven Records
        lässt sich Stilllegung nicht behaupten. Eine frühere Fassung nahm bei
        leerem Ledger die leere Menge an und meldete "stillgelegt" — also genau
        dann, wenn man am wenigsten weiß. Unbekannte Records gehören nach
        eigener Regel dem Altsystem; aus Unwissen folgt daher das Gegenteil.
        """
        if not active:
            return False
        if runtime == self.default_runtime and any(r not in self.owners for r in active):
            return False  # unbekannte Records gehören dem Default-Runtime
        return not any(self.owner_of(r) == runtime for r in active)

    # -- Übergabe ---------------------------------------------------------

    def adopt(
        self,
        record_id: str,
        *,
        reference: str,
        artifact_hashes: dict[str, str] | None = None,
        to_runtime: str = THIS_RUNTIME,
        note: str = "",
    ) -> Transfer:
        """Übernimmt einen Record. Protokolliert, nie stillschweigend."""
        if not reference:
            raise ValueError("Eine Übernahme ohne Entscheidungsreferenz gibt es nicht.")
        frm = self.owner_of(record_id)
        if frm == to_runtime:
            raise OwnershipError(f"{record_id} gehört bereits '{to_runtime}'.")
        t = Transfer(
            record_id=record_id,
            from_runtime=frm,
            to_runtime=to_runtime,
            at=_now(),
            reference=reference,
            artifact_hashes=dict(artifact_hashes or {}),
            note=note,
        )
        self.transfers.append(t)
        return t

    # -- Persistenz -------------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "default_runtime": self.default_runtime,
            # Nur Lesehilfe. Beim Laden wird dieser Block IGNORIERT und aus
            # den Übergaben neu berechnet — sonst wäre er ein Schreibrecht,
            # das man sich mit einem Texteditor ausstellen kann.
            "owners_derived_do_not_edit": {k: v.to_json() for k, v in sorted(self.owners.items())},
            "transfers": [t.to_json() for t in self.transfers],
        }

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(self.to_json(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        tmp.replace(path)  # atomar innerhalb eines Dateisystems

    @classmethod
    def load(cls, path: Path, *, default_runtime: str = LEGACY_RUNTIME) -> CutoverLedger:
        """``default_runtime`` kommt vom PROFIL, nie aus dieser Datei.

        Der Unterschied ist der ganze Punkt: Das Profil liegt im Paket,
        ausserhalb der Datenwurzel — wer die Datenwurzel schreiben darf, kann
        es nicht ändern. Eine Zeile in ``cutover.json`` dagegen wäre ein
        Schreibrecht, das man sich mit einem Texteditor ausstellt.
        """
        if not path.exists():
            return cls(default_runtime=default_runtime)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
            raise OwnershipError(f"{path} ist nicht lesbar oder kein gültiges JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise OwnershipError(f"{path}: erwartet ein Objekt, gefunden {type(raw).__name__}")
        if not isinstance(raw.get("transfers", []), list):
            raise OwnershipError(f"{path}: 'transfers' ist keine Liste")
        for i, tr in enumerate(raw.get("transfers", [])):
            if not isinstance(tr, dict):
                raise OwnershipError(f"{path}: Übergabe {i} ist kein Objekt")
        # Fail-closed: der Default-Runtime ist NICHT konfigurierbar. Sonst wäre
        # eine Zeile in einer JSON-Datei genug, um sich selbst zum Eigentümer
        # aller unbekannten Records zu erklären.
        declared = raw.get("default_runtime", default_runtime)
        if declared != default_runtime:
            raise OwnershipError(
                f"{path}: default_runtime ist {declared!r}, das Profil sagt "
                f"{default_runtime!r}. Ownership wird durch protokollierte Übergabe "
                "erworben, nicht durch eine Konfigurationszeile."
            )
        if "owners" in raw:
            raise OwnershipError(
                f"{path}: enthält einen 'owners'-Block. Ownership wird aus den "
                "protokollierten Übergaben berechnet, nicht eingetragen. "
                "Vermutlich von Hand bearbeitet — bitte prüfen."
            )
        transfers = [
            Transfer(
                record_id=t.get("record_id", ""),
                from_runtime=t["from"],
                to_runtime=t["to"],
                at=t["at"],
                reference=t.get("reference", ""),
                artifact_hashes=t.get("artifact_hashes", {}),
                note=t.get("note", ""),
            )
            for t in raw.get("transfers", [])
        ]
        # `default_runtime`, nicht LEGACY_RUNTIME. Die hartkodierte Fassung
        # verwarf den Profilwert, sobald die Datei existierte:
        #
        #   Datei fehlt, Aufruf sagt 'ohpipe'  -> default='ohpipe', may_write=True
        #   Datei da,    Aufruf sagt 'ohpipe'  -> default='dinoh',  may_write=False
        #
        # Dieselbe Frage — wem gehört ein unbekannter Record — bekam zwei
        # Antworten je nach Aufrufweg. Das ist die zweite Wahrheit eine Ebene
        # unter der, die `legacy_runtime` im Profil beseitigt hat.
        return cls(
            transfers=transfers, default_runtime=default_runtime, version=raw.get("version", 1)
        )

    def _valid_adoption(self, payload: dict, at: str) -> str | None:
        """Auch das Journal ist kein Freibrief.

        Der Befund: ein Ereignis, das nur ``record_id`` trug, machte ohpipe zum
        Eigentümer. Die Datei war repariert, die maßgebliche Darstellung selbst
        aber zu freizügig — dieselbe Klasse, eine Ebene tiefer.
        """
        from ..domain.decision import REFERENCE_RE, parse_aware_iso

        if not payload.get("record_id"):
            return "record.adopted ohne record_id"
        if not REFERENCE_RE.match(payload.get("reference", "") or ""):
            return (
                f"record.adopted ohne gültige Entscheidungsreferenz ({payload.get('reference')!r})"
            )
        # Aus dem Ledger, nicht global: Ein Profil ohne Vorgänger kennt
        # `dinoh` gar nicht, und ein späteres Profil mit anderem Vorgänger
        # wäre mit einer festen Zweiermenge nicht abbildbar.
        known = {self.default_runtime, THIS_RUNTIME}
        if payload.get("from") not in known or payload.get("to") not in known:
            return (
                "record.adopted mit unbekanntem Runtime "
                f"({payload.get('from')!r} -> {payload.get('to')!r})"
            )
        if payload["from"] == payload["to"]:
            return "record.adopted ohne Eigentümerwechsel"
        if parse_aware_iso(at) is None:
            return "record.adopted ohne zeitzonenbehafteten Zeitpunkt"
        return None

    @classmethod
    def from_journal(
        cls, journal, *, strict: bool = True, authority=None, default_runtime: str = LEGACY_RUNTIME
    ) -> CutoverLedger:
        """Die maßgebliche Fassung: aus der hash-verketteten Evidenz gebaut.

        ``cutover.json`` ist demgegenüber ein abgeleiteter Index — wie SQLite
        (ADR 0008). Weicht die Datei ab, gewinnt das Journal, und die Abweichung
        ist ein Befund.
        """
        from .authority import OWNERSHIP_REASON, Authority

        authority = authority or Authority.UNAUTHENTICATED
        from ..domain.decision import Decision, InvalidDecision, Verdict

        led = cls(default_runtime=default_runtime)
        problems: list[str] = []
        decisions: dict[str, Decision] = {}
        if not authority.may_confer_ownership:
            # Aus einer nicht authentifizierten Kette wird keine Ownership.
            # Ein angehängtes record.adopted waere sonst ein Schreibrecht, das
            # man sich selbst ausstellt (ADR 0017).
            if any(e.kind == "record.adopted" for e in journal):
                led.problems = [OWNERSHIP_REASON]
            return led
        for e in journal:
            # Entscheidungen mitlesen: eine Uebergabe muss sich auf eine
            # TATSAECHLICHE Entscheidung berufen koennen. HMAC beweist nur, dass
            # ein Schluesselinhaber geschrieben hat - nicht, dass die behauptete
            # menschliche Entscheidung existiert.
            if e.kind == "decision.recorded":
                pl = e.payload or {}
                try:
                    d = Decision(
                        record_id=pl.get("record_id") or getattr(e, "record_id", "") or "",
                        artifact=pl.get("artifact", ""),
                        subject_sha256=pl.get("subject_sha256", ""),
                        verdict=Verdict(pl.get("verdict", "")),
                        reference=pl.get("reference", ""),
                        actor=pl.get("actor", ""),
                        at=pl.get("at") or getattr(e, "at", ""),
                    )
                except (InvalidDecision, ValueError):
                    continue
                decisions[d.id] = d
                continue
            if e.kind != "record.adopted":
                continue
            p = e.payload or {}
            bad = led._valid_adoption(p, getattr(e, "at", ""))
            if bad:
                problems.append(bad)
                continue
            rid = p["record_id"]
            envelope = getattr(e, "record_id", None)
            if envelope and envelope != rid:
                problems.append(
                    f"record.adopted: Nutzlast nennt {rid!r}, die Ereignishülle {envelope!r}"
                )
                continue
            decision_id = p.get("decision_id", "")
            d = decisions.get(decision_id)
            if d is None:
                problems.append(
                    f"{rid}: Übergabe beruft sich auf die Entscheidung {decision_id!r}, "
                    "die im Journal (bis hierher) nicht vorkommt. Eine Referenz ist keine "
                    "Entscheidung."
                )
                continue
            if d.verdict is not Verdict.ACCEPT or d.record_id != rid:
                problems.append(
                    f"{rid}: die berufene Entscheidung hat Verdikt {d.verdict.value} "
                    f"und gehört zu {d.record_id!r}"
                )
                continue
            # Der Übergang muss stimmen: von wem behauptet wird, ist prüfbar.
            if led.owner_of(rid) != p["from"]:
                problems.append(
                    f"{rid}: Übergabe behauptet Herkunft {p['from']!r}, "
                    f"Eigentümer war {led.owner_of(rid)!r}"
                )
                continue
            led.transfers.append(
                Transfer(
                    record_id=rid,
                    from_runtime=p["from"],
                    to_runtime=p["to"],
                    at=e.at,
                    reference=d.reference,
                    artifact_hashes=p.get("artifact_hashes") or {},
                    note=p.get("note", ""),
                )
            )
        led.problems = problems
        if strict and problems:
            raise OwnershipError(
                "Ungültige Übergabeereignisse im Journal: " + "; ".join(problems[:3])
            )
        return led

    # -- Journalbindung ---------------------------------------------------

    def verify_against(self, journal, *, authority=None) -> list[str]:
        """Vergleicht den GESAMTEN abgeleiteten Zustand gegen das Journal.

        Eine frühere Fassung verglich nur die Übergabeliste — und übersah
        deshalb ein handeingetragenes ``owners``-Mapping vollständig. Verglichen
        wird jetzt die Eigentümerkarte selbst.
        """
        truth = CutoverLedger.from_journal(journal, strict=False, authority=authority)
        mine, theirs = self.owners, truth.owners
        problems: list[str] = []
        for rid in sorted(set(mine) | set(theirs)):
            a = mine.get(rid)
            b = theirs.get(rid)
            if a and not b:
                # Die Datei behauptet mehr als die Evidenz. Das ist die
                # gefährliche Richtung.
                problems.append(
                    f"{rid}: Ledger nennt Eigentümer '{a.runtime}', das Journal kennt "
                    "keine Übergabe"
                )
            elif a and b and (a.runtime != b.runtime or a.reference != b.reference):
                problems.append(
                    f"{rid}: Ledger sagt '{a.runtime}' ({a.reference}), Journal "
                    f"'{b.runtime}' ({b.reference})"
                )
        return problems

    def stale_against(self, journal, *, authority=None) -> list[str]:
        """Das Journal weiß MEHR als die Datei — der Index ist veraltet.

        Das ist die harmlose Richtung und ausdrücklich kein STOP: Ein
        abgeleiteter Index darf hinterherhinken, er wird neu gebaut (ADR 0008).
        Nur die andere Richtung — die Datei behauptet mehr als die Evidenz — ist
        ein Sicherheitsbefund.
        """
        truth = CutoverLedger.from_journal(journal, strict=False, authority=authority)
        return [
            f"{rid}: Journal belegt Übergabe an '{o.runtime}', die Datei kennt sie nicht"
            for rid, o in sorted(truth.owners.items())
            if rid not in self.owners
        ]
