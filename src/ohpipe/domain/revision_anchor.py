"""Ein Anker bindet an ein Tripel — Fassung, Projektion und Herkunft, oder er bindet nicht.

`docs/adr/0028A-transkriptvertrag-was-transcript-confirm-bestaetigt.md § Der
Vertrag` setzt den Anker auf `(artifact_key, revision_sha256,
projection_version)`. Die Begründung ist eine Aussage über Identität: derselbe
Vertrag schliesst die Herkunft aus dem Identitätshash aus und legt sie an den
`ArtifactKey`. Ein Anker, der den `ArtifactKey` nicht mitführt, führt die
Herkunft dorthin, wo sie niemand mehr erreicht — zwei Fassungen mit
identischen Segmenten, eine ungeprüfte Rohausgabe und dieselbe Ausgabe nach
menschlicher Durchsicht, sind dieselbe Revision, und genau dann, wenn die
Durchsicht nichts geändert hat, verschwindet ihre Spur aus einem zweiteiligen
Zitat. `§ Folgen` derselben ADR nennt einen Anker ohne Projektionsangabe oder
ohne `ArtifactKey` deshalb unvollständig.

Derselbe Abschnitt hält fest, dass Anker bei einer neuen Fassung **nicht
mitwandern**. Diese Form macht das strukturell wahr: sie ist unveränderlich,
und ein anderer Revisionshash oder eine andere Projektionskennung ergibt einen
anderen Wert, nicht denselben mit anderem Inhalt.

**Was diese Form prüft — und was sie ausdrücklich nicht prüft.**

*   `artifact_key` wird nicht zum zweiten Mal buchstabiert.
    `src/ohpipe/domain/artifact_key.py::ArtifactKey.from_mapping` bleibt die
    einzige Prüfung der vierteiligen Schlüsselform; dieses Modul kopiert ihre
    Regeln nicht und lässt ihre Fehler nicht als gültigen Anker durch. Die
    äussere Meldung nennt den Ankerkontext, die innere bleibt über
    ``__cause__`` erreichbar.

*   `revision_sha256` wird gegen
    `src/ohpipe/domain/decision.py::SHA256_RE` geprüft, und zwar mit
    ``fullmatch``. ``match`` wäre hier falsch: das Dollarzeichen des Musters
    trifft auch vor einem abschliessenden Zeilenvorschub, und ein Hash mit
    angehängtem Byte ist kein Hash. Der Wert wird **nicht berechnet** und
    **nicht** gegen eine `TranscriptRevision` gehalten; geprüft ist allein
    seine Form.

*   `projection_version` wird auf Typ und Nichtleere geprüft — sonst nichts.
    Es gibt am Sockel keinen Katalog bekannter Projektionsversionen, und das
    Bestätigungstor, das eine unbekannte Kennung nach ADR 0028A blockieren
    soll, ist nicht gebaut. Diese Form behauptet deshalb nicht, die Kennung
    sei bekannt: sie bindet die ausdrücklich übergebene Kennung an den Anker
    und trägt sie zeichengenau. Kein Trimmen, kein Kleinschreiben, kein
    Default und keine Ableitung aus `joiner` oder Profil — eine solche Regel
    hätte hier keinen Maßstab und wäre eine erfundene Norm.

**Abgrenzung.** Der Textstellenanker in
`src/ohpipe/domain/anchor.py::Anchor` bindet eine Stelle *im* Transkript mit
Offsets, Zitat und Kontext. Diese Form hier ist der übergeordnete Bezug auf
Fassung und Projektion. Die beiden sind verschiedene Gegenstände und bleiben
getrennte Module.

Die Formatdetails der kanonischen, verlustfreien Serialisierung einer
`TranscriptRevision` sind nach ADR 0028A an ADR 0028B delegiert und werden
hier nicht gesetzt. `to_mapping` und `from_mapping` sind **strukturelle
Abbildungen** — ein Weg hinaus und ein Weg zurück —, keine kanonische
Serialisierung und keine Hashformel.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, ClassVar

from .artifact_key import ArtifactKey, InvalidArtifactKey
from .decision import SHA256_RE

__all__ = ["InvalidRevisionAnchor", "RevisionAnchor"]


class InvalidRevisionAnchor(ValueError):
    """Ein Anker, der nicht gebaut wird.

    Fail-closed: die Zurückweisung nennt das betroffene Feld und den konkreten
    Grund und behauptet nichts über eine Prüfung, die nicht stattgefunden hat.
    """


def _schluessel_aus(wert: Any) -> ArtifactKey:
    """Nimmt einen fertigen Schlüssel oder baut ihn über den bestehenden Vertrag."""
    if isinstance(wert, ArtifactKey):
        return wert
    if isinstance(wert, Mapping):
        try:
            return ArtifactKey.from_mapping(wert)
        except InvalidArtifactKey as exc:
            raise InvalidRevisionAnchor(
                f"artifact_key ist keine gültige Artefaktidentität: {exc} "
                "Der Anker wird deshalb nicht gebaut; die Schlüsselprüfung bleibt "
                "bei ArtifactKey und wird hier nicht wiederholt."
            ) from exc
    raise InvalidRevisionAnchor(
        f"artifact_key ist {wert!r} und damit weder ein ArtifactKey noch eine "
        "Abbildung, aus der einer gebaut werden kann. Ein Anker ohne "
        "Artefaktidentität ist nach ADR 0028A unvollständig."
    )


def _geprueft_revision_sha256(wert: Any) -> None:
    if not isinstance(wert, str):
        raise InvalidRevisionAnchor(
            f"revision_sha256 muss eine Zeichenkette sein, ist aber {wert!r} "
            f"vom Typ {type(wert).__name__}."
        )
    if not SHA256_RE.fullmatch(wert):
        raise InvalidRevisionAnchor(
            f"revision_sha256 ist {wert!r} und damit kein kleingeschriebener "
            "sha256 aus genau 64 Hexziffern — auch ein angehängter Zeilenvorschub "
            "oder ein weiteres Byte macht den Wert unzulässig. Der Wert wurde "
            "nicht berechnet und nicht gegen eine Revision gehalten; geprüft ist "
            "allein seine Form."
        )


def _geprueft_projection_version(wert: Any) -> None:
    if not isinstance(wert, str):
        raise InvalidRevisionAnchor(
            f"projection_version muss eine Zeichenkette sein, ist aber {wert!r} "
            f"vom Typ {type(wert).__name__}."
        )
    if not wert:
        raise InvalidRevisionAnchor(
            "projection_version ist die leere Zeichenkette. Die Projektion ist "
            "nach ADR 0028A identitätsbildend und aus der Fassung ablesbar; eine "
            "leere Kennung benennt keine Projektion. Geprüft sind Typ und "
            "Nichtleere — die Kennung wurde nicht gegen einen Katalog bekannter "
            "Projektionsversionen geprüft, denn ein solcher Katalog ist nicht "
            "hinterlegt."
        )


def _schluessel_abbildung(schluessel: ArtifactKey) -> dict[str, Any]:
    """Die vier Felder aus `src/ohpipe/domain/artifact_key.py::ArtifactKey.FIELDS`.

    `scope` erscheint als sein Stringwert, damit die Abbildung JSON-fähig ist;
    `instance_id` bleibt mit dem Wert `None` ausdrücklich vorhanden, weil ein
    abwesendes Feld nach dem Schlüsselvertrag etwas anderes ist als der
    eininstanzige Fall.
    """
    werte: dict[str, Any] = {feld: getattr(schluessel, feld) for feld in ArtifactKey.FIELDS}
    werte["scope"] = schluessel.scope.value
    return werte


@dataclass(frozen=True)
class RevisionAnchor:
    """Das dreiteilige Tripel. Unvollständig gibt es es nicht."""

    artifact_key: ArtifactKey
    revision_sha256: str
    projection_version: str

    #: Die drei Felder in ihrer Vertragsreihenfolge. Kein Datenfeld, sondern
    #: die Liste, gegen die Abwesenheit und fremde Felder gemessen werden.
    FIELDS: ClassVar[tuple[str, ...]] = (
        "artifact_key",
        "revision_sha256",
        "projection_version",
    )

    def __post_init__(self) -> None:
        if not isinstance(self.artifact_key, ArtifactKey):
            raise InvalidRevisionAnchor(
                f"artifact_key ist {self.artifact_key!r} und damit kein ArtifactKey. "
                "Der Konstruktor nimmt einen bereits gebauten Schlüssel; der Weg von "
                "einer Abbildung heraus ist from_mapping."
            )
        _geprueft_revision_sha256(self.revision_sha256)
        _geprueft_projection_version(self.projection_version)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> RevisionAnchor:
        """Baut den Anker aus einer Abbildung, ohne ein Feld zu ergänzen oder zu verwerfen.

        `artifact_key` darf ein fertiger Schlüssel oder eine vollständige
        Abbildung sein; im zweiten Fall geht er ausschliesslich über
        `src/ohpipe/domain/artifact_key.py::ArtifactKey.from_mapping`.
        """
        fehlend = [feld for feld in cls.FIELDS if feld not in data]
        if fehlend:
            raise InvalidRevisionAnchor(
                f"RevisionAnchor unvollständig: die Felder {fehlend} fehlen. Der Anker "
                "bindet nach ADR 0028A an das volle Tripel (artifact_key, "
                "revision_sha256, projection_version); ein Anker ohne Projektionsangabe "
                "oder ohne ArtifactKey ist nach diesem Vertrag unvollständig."
            )
        fremd = sorted(set(data) - set(cls.FIELDS))
        if fremd:
            raise InvalidRevisionAnchor(
                f"nicht erlaubte Felder: {fremd}. Erlaubt sind {list(cls.FIELDS)}. "
                "Ein unbekanntes Feld wird nicht stillschweigend verworfen."
            )
        return cls(
            artifact_key=_schluessel_aus(data["artifact_key"]),
            revision_sha256=data["revision_sha256"],
            projection_version=data["projection_version"],
        )

    def to_mapping(self) -> dict[str, Any]:
        """Die strukturelle Abbildung: drei Schlüssel, der erste vierteilig verschachtelt.

        Jeder Aufruf baut frische Abbildungen; zwei Aufrufe teilen keine
        mutierbare innere Abbildung, damit eine Änderung an der Ausgabe den
        Anker nicht erreicht.
        """
        return {
            "artifact_key": _schluessel_abbildung(self.artifact_key),
            "revision_sha256": self.revision_sha256,
            "projection_version": self.projection_version,
        }
