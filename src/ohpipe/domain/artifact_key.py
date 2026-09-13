"""Die Artefaktidentität ist vierteilig — und ihr `instance_id` ist heute nur als `None` schreibbar.

`docs/adr/0027-artefaktidentitaet-und-evidenzbindung.md § Entscheidung · A ·
Identität` setzt die Identität auf `ArtifactKey(scope, scope_id, kind,
instance_id)` und hält fest, dass der volle Schlüssel von Anfang an gilt.
`docs/ENTSCHEIDUNGEN_2026-08-05.md § E3 · Receiptvertrag` belegt die Felder:
`scope` geschlossen auf `workspace | record`, `scope_id` als `workspace_id`
oder `record_id`, `kind` als kontrollierte Artefaktart und `instance_id` als
`null` für den Singleton.

**Warum ein nichtleerer `instance_id` hier nicht geschrieben wird.**
Dieselbe ADR macht ein kontrolliertes Format zur einzigen zulässigen Form und
weist alles andere beim Schreiben zurück; die Formatdetails — Präfix, Länge,
Trennzeichen, Serialisierung, Ableitungsformel — sind an ADR 0028B delegiert,
und ADR 0028B liegt nicht vor. Eine positive Formatprüfung ist ohne Maßstab
nicht konstruierbar. Dieses Modul erfindet deshalb keinen Maßstab, sondern
weist jeden nichtleeren `instance_id` fail-closed zurück und nennt als Ursache
genau das: es ist kein Maßstab hinterlegt. Die Meldung behauptet **nicht**,
gegen ein vorhandenes Format geprüft zu haben.

Das gilt auch für den unitgebundenen `instance_id = unit_id`: er ist ein
nichtleerer `instance_id` und damit formatpflichtig. Die Vertagung des eigenen
`unit`-Scope ist eine Scope-Frage und keine Ausnahme von der Formatpflicht.

Sobald ADR 0028B einen Maßstab setzt, tritt er an die Stelle der
Zurückweisung; bis dahin ist die gesperrte Seite hier vollständig und die
offene Seite genau der Singleton.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, ClassVar

__all__ = ["ArtifactKey", "InvalidArtifactKey", "NO_FORMAT_STANDARD_REASON", "Scope"]


class Scope(str, Enum):
    """Geschlossenes Vokabular (ADR 0011). Ein dritter Wert ist ein Fehler, kein `unbekannt`."""

    WORKSPACE = "workspace"
    RECORD = "record"


class InvalidArtifactKey(ValueError):
    """Ein Schlüssel, der nicht geschrieben wird.

    Fail-closed: die Zurückweisung nennt ihre konkrete Ursache und behauptet
    nichts über eine Prüfung, die nicht stattgefunden hat.
    """


#: Die Ursache, die ein nichtleerer `instance_id` heute erhält. Kein Format,
#: kein Platzhalter, keine Regex — die Abwesenheit eines Maßstabs selbst ist
#: der Grund, und der Satz sagt genau das.
NO_FORMAT_STANDARD_REASON = (
    "kein normativer Formatmaßstab für einen nichtleeren instance_id hinterlegt"
)

_KEIN_MASSSTAB = (
    f"instance_id ist nichtleer, aber es ist {NO_FORMAT_STANDARD_REASON}: "
    "ADR 0027 § Entscheidung · A · Identität macht ein kontrolliertes Format zur "
    "einzigen zulässigen Form und delegiert die Formatdetails an ADR 0028B; "
    "ADR 0028B liegt nicht vor. Der Schlüssel wird deshalb nicht geschrieben. "
    "Er wurde nicht gegen ein vorhandenes Format geprüft."
)

_LEERE_ZEICHENKETTE = (
    "instance_id ist die leere Zeichenkette. Der eininstanzige Fall wird nach "
    "docs/ENTSCHEIDUNGEN_2026-08-05.md § E3 · Receiptvertrag als null dargestellt; "
    "die leere Zeichenkette ist keine Singletondarstellung und wird nicht als "
    "null behandelt."
)


def _nichtleerer_text(wert: Any, feld: str) -> str:
    if not isinstance(wert, str) or not wert:
        raise InvalidArtifactKey(
            f"{feld} muss eine nichtleere Zeichenkette sein, ist aber {wert!r}. "
            "Der volle Schlüssel gilt von Anfang an (ADR 0027 § Entscheidung · A · Identität)."
        )
    return wert


@dataclass(frozen=True)
class ArtifactKey:
    """Der volle vierteilige Schlüssel. Unvollständig gibt es ihn nicht."""

    scope: Scope
    scope_id: str
    kind: str
    instance_id: str | None

    #: Die vier Felder in ihrer Vertragsreihenfolge. Kein Datenfeld, sondern
    #: die Liste, gegen die Abwesenheit und fremde Felder gemessen werden.
    FIELDS: ClassVar[tuple[str, ...]] = ("scope", "scope_id", "kind", "instance_id")

    def __post_init__(self) -> None:
        if not isinstance(self.scope, Scope):
            raise InvalidArtifactKey(
                f"scope ist {self.scope!r} und damit kein Wert des geschlossenen "
                f"Vokabulars {_scope_werte()}. Ein dritter Wert ist ein Fehler, "
                "kein unbekannt (ADR 0011)."
            )
        _nichtleerer_text(self.scope_id, "scope_id")
        _nichtleerer_text(self.kind, "kind")

        if self.instance_id is None:
            return
        if not isinstance(self.instance_id, str):
            raise InvalidArtifactKey(
                f"instance_id ist {self.instance_id!r}. Zulässig sind null für den "
                "eininstanzigen Fall oder eine Zeichenkette."
            )
        if self.instance_id == "":
            raise InvalidArtifactKey(_LEERE_ZEICHENKETTE)
        raise InvalidArtifactKey(_KEIN_MASSSTAB)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ArtifactKey:
        """Baut den Schlüssel aus einer Abbildung und trennt Abwesenheit von `null`.

        Ein weggelassenes Feld ist ein anderer Fall als ein Feld mit dem Wert
        `null`: der erste ist nicht der volle Schlüssel, der zweite ist der
        entschiedene eininstanzige Fall. Beide Fälle werden hier getrennt
        benannt, weil ein Aufrufer die Abwesenheit sonst nicht von der
        Singletondarstellung unterscheiden kann.
        """
        fehlend = [feld for feld in cls.FIELDS if feld not in data]
        if fehlend:
            raise InvalidArtifactKey(
                f"ArtifactKey unvollständig: die Felder {fehlend} fehlen. Der volle "
                "Schlüssel gilt von Anfang an (ADR 0027 § Entscheidung · A · "
                "Identität); ein Schlüssel ohne diese Felder ist nicht der volle "
                "Schlüssel. Ein abwesendes Feld ist nicht dasselbe wie instance_id null."
            )
        fremd = sorted(set(data) - set(cls.FIELDS))
        if fremd:
            raise InvalidArtifactKey(
                f"nicht erlaubte Felder: {fremd}. Erlaubt sind {list(cls.FIELDS)}. "
                "Ein unbekanntes Feld wird nicht stillschweigend verworfen."
            )
        return cls(
            scope=_scope_aus(data["scope"]),
            scope_id=data["scope_id"],
            kind=data["kind"],
            instance_id=data["instance_id"],
        )


def _scope_werte() -> list[str]:
    return [s.value for s in Scope]


def _scope_aus(wert: Any) -> Scope:
    if isinstance(wert, Scope):
        return wert
    try:
        return Scope(wert)
    except ValueError as exc:
        raise InvalidArtifactKey(
            f"scope ist {wert!r} und damit kein Wert des geschlossenen Vokabulars "
            f"{_scope_werte()}. Ein dritter Wert ist ein Fehler, kein unbekannt "
            "(ADR 0011); ein eigener unit-Scope bleibt vertagt."
        ) from exc
