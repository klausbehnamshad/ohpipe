"""Belege für Ableitungen — deterministische wie generative.

Ein Receipt beantwortet: *Woraus ist dieses Artefakt entstanden, womit, und
wie ist der Lauf geendet?* Er ersetzt die Regeneration bei Modellschritten
(ADR 003): `check` läuft nie erneut gegen das Modell, sondern vergleicht die
deklarierten Eingaben gegen den gespeicherten Beleg.

Der teuerste Fehler des Vorgängerprojekts steckt in ``finish_reason``.
`num_predict=1280` schnitt Antworten ab; das Chunk-Ende fiel weg. In fünf von
fünf Interviews lagen 55–88 % der unkodierten Masse im letzten Viertel des
Chunks — die Lücke korrelierte also mit dem Merkmal, das gemessen wurde. Kein
Skript hat je Alarm geschlagen, weil ein abgeschnittener Lauf wie ein
erfolgreicher aussah.

Hier kann er das nicht mehr: ``ModelReceipt.truncated`` ist ein Fehlerzustand,
kein Hinweis. Siehe :meth:`ModelReceipt.validate`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .hashing import sha256_json


def _parse_iso(value: str) -> datetime | None:
    """Nur zeitzonenbehaftete ISO-8601-Zeitpunkte.

    Naive und aware Zeitpunkte zu mischen endete in einem ``TypeError`` beim
    Vergleich — also einem Absturz genau dort, wo eine Reihenfolge geprueft
    werden sollte. Ein Zeitpunkt ohne Zone ist ausserdem mehrdeutig; in einem
    Beleg hat er nichts verloren.
    """
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo is not None else None


__all__ = [
    "FINISH_CLEAN",
    "FINISH_LENGTH",
    "FINISH_OK",
    "FINISH_UNKNOWN",
    "ModelParams",
    "ModelReceipt",
    "Receipt",
    "TruncatedOutput",
    "UnauthorisedRun",
]


class TruncatedOutput(RuntimeError):
    """Ein Modelllauf endete an der Token-Grenze. Kein Teilergebnis wird verwendet."""


class UnauthorisedRun(RuntimeError):
    """Ein Modelllauf ohne gültige, vorher erteilte Autorisierung."""


# Bewusst Konstanten statt Enum: fremde Adapter reichen beliebige Rohwerte
# durch, und ein unbekannter Wert darf NICHT auf einen Default fallen.
FINISH_OK = "stop"
FINISH_LENGTH = "length"
FINISH_UNKNOWN = "unknown"

#: Alles, was NICHT auf dieser Allowlist steht, gilt als nicht sauber beendet.
#: Default = fehlgeschlagen. Dieselbe Regel wie bei kontrollierten Vokabularen
#: (ADR 011): ein unbekannter Wert schließt nichts.
FINISH_CLEAN = frozenset({FINISH_OK, "end_turn", "eos", "stop_sequence"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class ModelParams:
    """Der eingefrorene Parametersatz eines Laufs.

    Gehört laut ADR 012 einem KORPUS, nicht einem Interview: Wird einer dieser
    Werte geändert, sind interviewübergreifende Aussagen über den alten Korpus
    nicht mehr gedeckt.
    """

    model: str
    model_digest: str | None = None
    temperature: float = 0.0
    seed: int | None = None
    num_ctx: int | None = None
    num_predict: int | None = None
    max_chars: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return sha256_json(
            {
                "model": self.model,
                "model_digest": self.model_digest,
                "temperature": self.temperature,
                "seed": self.seed,
                "num_ctx": self.num_ctx,
                "num_predict": self.num_predict,
                "max_chars": self.max_chars,
                "extra": self.extra,
            }
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "model_digest": self.model_digest,
            "temperature": self.temperature,
            "seed": self.seed,
            "num_ctx": self.num_ctx,
            "num_predict": self.num_predict,
            "max_chars": self.max_chars,
            "extra": dict(self.extra),
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True)
class Receipt:
    """Beleg für eine deterministische Ableitung."""

    step: str
    inputs: dict[str, str]  # logischer Name -> sha256
    output_sha256: str
    code_version: str
    created_at: str = field(default_factory=_now)
    kind: str = "deterministic"

    @property
    def input_fingerprint(self) -> str:
        return sha256_json({"step": self.step, "inputs": self.inputs, "code": self.code_version})

    def matches(self, inputs: dict[str, str], code_version: str) -> bool:
        """Sind die deklarierten Eingaben unverändert?

        Das — und NICHT eine Regeneration — ist die Definition von
        ``derivation_state == current`` für Modellschritte (ADR 003).
        """
        return self.inputs == inputs and self.code_version == code_version

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "step": self.step,
            "inputs": dict(self.inputs),
            "output_sha256": self.output_sha256,
            "code_version": self.code_version,
            "created_at": self.created_at,
            "input_fingerprint": self.input_fingerprint,
        }


@dataclass(frozen=True)
class ModelReceipt(Receipt):
    """Beleg für einen generativen Lauf."""

    params: ModelParams | None = None
    prompt_sha256: str = ""
    finish_reason: str = FINISH_UNKNOWN
    output_tokens: int | None = None
    chunk_index: int | None = None
    chunk_count: int | None = None
    #: ``Decision.id`` der menschlichen Entscheidung, die diesen Lauf autorisiert.
    authorisation: str = ""
    #: Die Bytes, die dieser Mensch gesehen hat. Ohne sie ist die Referenz ein
    #: Name ohne Gegenstand.
    authorisation_subject_sha256: str = ""
    #: Zeitpunkte in derselben ISO-Form wie ``created_at`` (UTC, Sekunden) —
    #: nur so ist der lexikografische Vergleich unten zulässig.
    authorised_at: str = ""
    started_at: str = ""
    kind: str = "model"

    @property
    def truncated(self) -> bool:
        """True, wenn der Lauf nicht sauber beendet wurde.

        Bewusst konservativ: ein unbekannter ``finish_reason`` zählt als
        abgeschnitten. Ein Adapter, der die Abbruchursache nicht meldet, darf
        nicht wie einer aussehen, der sauber beendet hat.
        """
        return self.finish_reason not in FINISH_CLEAN

    def check_authorisation(self) -> None:
        """Ein Beleg wird nicht rückwirkend erteilt.

        Herkunft: ``test_corsia.sh:95`` — „vor dem GATE begonnener Pass 1 wird
        nicht rückwirkend belegt". Ohne diese Regel könnte ein Lauf, der vor
        der menschlichen Freigabe gestartet wurde, hinterher legitimiert
        werden — die Freigabe wäre dann eine Formalie statt einer Bedingung.
        """
        from .decision import REFERENCE_RE, SHA256_RE  # zyklusfrei: nur hier gebraucht

        if not self.authorisation or "@" not in self.authorisation:
            raise UnauthorisedRun(
                f"Modelllauf '{self.step}' ohne gültige Autorisierungsreferenz "
                f"(erwartet Decision.id der Form 'REF@sha12', bekam {self.authorisation!r})."
            )
        ref, _, short_sha = self.authorisation.partition("@")
        if not REFERENCE_RE.match(ref) or len(short_sha) != 12:
            raise UnauthorisedRun(
                f"Modelllauf '{self.step}': {self.authorisation!r} ist keine Decision.id."
            )
        if not SHA256_RE.match(self.authorisation_subject_sha256):
            raise UnauthorisedRun(
                f"Modelllauf '{self.step}': die autorisierten Bytes sind nicht benannt. "
                "Eine Referenz ohne Gegenstand ist kein Beleg."
            )
        if not self.authorisation_subject_sha256.startswith(short_sha):
            raise UnauthorisedRun(
                f"Modelllauf '{self.step}': Referenz und Bezugsbytes passen nicht zusammen."
            )
        auth_at = _parse_iso(self.authorised_at)
        start_at = _parse_iso(self.started_at)
        if auth_at is None or start_at is None:
            raise UnauthorisedRun(
                f"Modelllauf '{self.step}': Autorisierungs- und Startzeitpunkt müssen "
                f"gültige ISO-8601-Zeitpunkte sein (bekam {self.authorised_at!r} / "
                f"{self.started_at!r}). Ein lexikografischer Vergleich beliebiger "
                "Zeichenketten prüft gar nichts."
            )
        if start_at < auth_at:
            raise UnauthorisedRun(
                f"Modelllauf '{self.step}' begann {self.started_at}, autorisiert wurde er erst "
                f"{self.authorised_at}. Ein Beleg wird nicht rückwirkend erteilt."
            )

    def validate(self, decision: object = None) -> None:
        """Fail-closed. Wird von jedem Modelladapter vor dem Speichern gerufen.

        ``decision`` ist PFLICHT. Das Format der Referenz allein beweist nichts:
        ``PI-1@aaaaaaaaaaaa`` ist wohlgeformt und frei erfunden. Erst der
        Abgleich gegen die tatsächliche Entscheidung macht aus einer Zeichenkette
        einen Beleg.
        """
        self.check_authorisation()
        if decision is None:
            raise UnauthorisedRun(
                f"Modelllauf '{self.step}': validate() braucht die Entscheidung, auf die sich "
                "die Autorisierung beruft. Ein wohlgeformter Referenzstring ist kein Nachweis."
            )
        if not self.bound_to(decision):
            raise UnauthorisedRun(
                f"Modelllauf '{self.step}': die angegebene Autorisierung passt nicht zu dieser "
                "Entscheidung (Referenz, Bezugsbytes, Verdikt oder Reihenfolge)."
            )
        if self.truncated:
            where = (
                f" (Chunk {self.chunk_index + 1}/{self.chunk_count})"
                if self.chunk_index is not None and self.chunk_count
                else ""
            )
            raise TruncatedOutput(
                f"Modelllauf '{self.step}' endete mit finish_reason={self.finish_reason!r}{where}. "
                "Ein abgeschnittener Lauf wird nicht als Teilergebnis übernommen — "
                "die Lücke säße systematisch am Ende der dichtesten Passagen. "
                "num_predict erhöhen oder max_chars senken; beides ist eine "
                "Korpusentscheidung (ADR 012)."
            )

    def to_json(self) -> dict[str, Any]:
        out = super().to_json()
        out.update(
            {
                "params": self.params.to_json() if self.params else None,
                "prompt_sha256": self.prompt_sha256,
                "authorisation": self.authorisation,
                "authorisation_subject_sha256": self.authorisation_subject_sha256,
                "authorised_at": self.authorised_at,
                "started_at": self.started_at,
                "finish_reason": self.finish_reason,
                "output_tokens": self.output_tokens,
                "chunk_index": self.chunk_index,
                "chunk_count": self.chunk_count,
                "truncated": self.truncated,
            }
        )
        return out

    def matches(  # type: ignore[override]
        self,
        inputs: dict[str, str],
        code_version: str,
        *,
        params: ModelParams | None = None,
        prompt_sha256: str | None = None,
        output_sha256: str | None = None,
    ) -> bool:
        """Sind ALLE deklarierten Eingaben unverändert?

        Zu den Eingaben eines generativen Schritts gehören Modell, Parameter
        und Prompt — sonst gilt ein Lauf als aktuell, dessen ``num_predict``
        inzwischen verdoppelt wurde. Genau das wäre die Korpus-Vergleichbarkeit,
        die ADR 0012 schützt.

        ``params``/``prompt_sha256`` sind Pflicht: werden sie nicht übergeben,
        ist der Vergleich unvollständig und liefert False (fail-closed).
        """
        if not super().matches(inputs, code_version) or self.truncated:
            return False
        try:
            self.check_authorisation()
        except UnauthorisedRun:
            return False
        if params is None or prompt_sha256 is None or output_sha256 is None:
            return False
        if self.params is None or self.params.fingerprint != params.fingerprint:
            return False
        if self.prompt_sha256 != prompt_sha256:
            return False
        # Der Beleg gilt fuer BESTIMMTE Ausgabebytes. Liegen heute andere auf
        # der Platte, belegt er sie nicht — auch wenn alle Eingaben stimmen.
        return self.output_sha256 == output_sha256

    def bound_to(self, decision: object) -> bool:
        """Bindet dieser Beleg an genau diese Entscheidung?"""
        from .decision import Decision

        if not isinstance(decision, Decision) or not decision.is_accepting:
            return False
        if self.authorisation != decision.id:
            return False
        if self.authorisation_subject_sha256 != decision.subject_sha256:
            return False
        # Massgeblich ist der Zeitpunkt DER ENTSCHEIDUNG, nicht das vom Beleg
        # selbst behauptete authorised_at. Sonst schreibt der Lauf sich seine
        # eigene Vorgeschichte.
        d_at = _parse_iso(decision.at)
        started = _parse_iso(self.started_at)
        if d_at is None or started is None:
            return False
        return d_at <= started
