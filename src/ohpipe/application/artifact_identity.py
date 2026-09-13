"""Das recordgebundene Tor für ``kind`` und ``scope_id`` — vor B2.

`docs/ENTSCHEIDUNGEN_2026-08-05.md § E3 · Receiptvertrag` setzt zwei Grenzen,
die B1 noch nicht vollstreckt: ``ArtifactKey.scope_id`` ist ``workspace_id``
oder ``record_id``, und ``ArtifactKey.kind`` ist eine **kontrollierte**
Artefaktart. `src/ohpipe/domain/artifact_key.py::ArtifactKey` prüft beide nur
auf nichtleer — richtig so, denn es ist ein **kontextfreier Wert**. Wogegen
etwas kontrolliert ist, weiss erst die Anwendungsschicht, in der Profil, Graph
und aktueller Record-Kontext gemeinsam vorliegen. Deshalb steht das Tor hier
und nicht in der Domäne.

**Der Katalog ist der aktive Graph, nicht eine Liste.** Geprüft wird gegen
`src/ohpipe/domain/step.py::build_graph`, aufgerufen mit genau dem übergebenen
validierten Profil. Es gibt keine kopierte Positivliste und keinen Rückfall auf
``DEFAULT_GRAPH``: eine Kopie wäre eine zweite Wahrheit über dieselbe Sache und
liefe beim nächsten Graphschritt still auseinander, und ein Rückfall auf den
Sandboxgraphen gäbe unter jedem Profil dieselbe Antwort.

**Der Aufrufer wählt den Katalog nicht.** Das Tor nimmt weder einen Graphen
noch ein String-Set entgegen. Nähme es einen, liesse sich ein Profil mit dem
Graphen eines anderen paaren — und genau diese Paarung soll es ausschliessen.

**Was hier NICHT entschieden wird.** `KIND_NOT_IN_ACTIVE_GRAPH` sagt nicht,
eine Artefaktart sei global ungültig. ``unit_set`` und ``codebook`` nennt
`docs/adr/0027-artefaktidentitaet-und-evidenzbindung.md § Entscheidung · A ·
Identität` als Artefakte, aber kein aktueller Graph erzeugt sie.
``StepGraph.artifacts`` ist deshalb kein globales Artenregister, sondern die
Schreibzulässigkeit **dieses** Pfades.

**Warum es kein workspace-Tor gibt.** ``workspace.identity.assigned`` — nach
`docs/ENTSCHEIDUNGEN_2026-08-05.md § E3 · Bytevertrag der Identitäten` die
Quelle der ``workspace_id`` — existiert am Sockel nicht im Produktcode. Ein
Pfad, ein Profilname, eine Datenwurzel oder ein frisch erzeugter Zufallswert
wäre keine ``workspace_id``, sondern eine Erfindung. Der Scope fällt deshalb
mit eigener, benannter Ursache; die Lücke wird nicht in einen Default
geschoben.

**Warum der Grund ein Attribut ist und kein Textbaustein.** Ein
``reason_code``, den ein Aufrufer per Substringsuche aus einer deutschen
Meldung zieht, kippt lautlos, sobald jemand den Satz umformuliert. Dieselbe
Klasse Fehler hat `src/ohpipe/project.py::DataRootError` zu einem eigenen Typ
gemacht.

**Was dieses Tor NICHT beurteilt.** Die Totalität zwischen erzeugten
Artefaktarten und ``ArtifactContract`` ist die fail-closed Grenze von
`src/ohpipe/domain/step.py::build_graph`: ein Drift hält dort mit
``GraphError``, bevor dieses Tor überhaupt einen Schlüssel ansieht. Ein
solcher Graphfehler ist kein Grund über einen ``ArtifactKey`` und bekommt
deshalb keinen ``GateReason``. Ebenso bleibt eine unerwartete
Programmierfehler-Ausnahme aus ``contract_for`` in Typ, Text und Ursache
dieselbe Ausnahme: ein maschinenlesbarer Grund, der im Fehlerfall das Falsche
behauptet, ist schlimmer als keiner.

Das Tor schreibt nichts, normalisiert nichts still und ersetzt keinen Wert: bei
Erfolg kommt derselbe Schlüssel zurück, den es bekommen hat.
"""

from __future__ import annotations

from enum import Enum

from ohpipe.domain.artifact_key import ArtifactKey, InvalidArtifactKey, Scope
from ohpipe.domain.step import build_graph

__all__ = ["ArtifactKeyNotWritable", "GateReason", "check_record_scoped_key"]


class GateReason(str, Enum):
    """Die fünf stabilen, maschinenlesbaren Gründe dieses Tors.

    Fünf Ursachen, fünf Codes, fünf Meldungen. Zwei Ursachen, die sich einen
    Code teilen, machen aus zwei Befunden einen — und der Aufrufer kann nicht
    mehr entscheiden, was zu tun ist. Genau das war der Fall, solange eine
    formungültige ``scope_id`` denselben Code und dieselbe Meldung bekam wie
    eine formgültige, kontextfremde: die Meldung behauptete dann eine
    Formgültigkeit, die im gemessenen Fall falsch war.

    **Diese fünf sind Kontext- und Schreibzulässigkeitsgründe des Gates.**
    Systemische Fehler gehören nicht hierher und werden nicht hineinübersetzt:
    ein ``GraphError`` aus `src/ohpipe/domain/step.py::build_graph` — etwa die
    verletzte Vertragstotalität — bleibt ein ``GraphError``, und eine
    unerwartete Programmierfehler-Ausnahme bleibt sie selbst.
    """

    #: Der übergebene Record-Kontext ist keine kanonische Kennung dieses Profils.
    INVALID_CURRENT_RECORD_ID = "INVALID_CURRENT_RECORD_ID"
    #: ``key.scope_id`` erfüllt die kanonische Form dieses Profils nicht.
    INVALID_SCOPE_ID = "INVALID_SCOPE_ID"
    #: Beide Kennungen sind formgültig, meinen aber verschiedene Records.
    SCOPE_ID_CONTEXT_MISMATCH = "SCOPE_ID_CONTEXT_MISMATCH"
    #: Der aktive Graph dieses Profils erzeugt diese Artefaktart nicht.
    KIND_NOT_IN_ACTIVE_GRAPH = "KIND_NOT_IN_ACTIVE_GRAPH"
    #: Für ``workspace`` gibt es am Sockel keine Identitätsquelle.
    WORKSPACE_IDENTITY_UNAVAILABLE = "WORKSPACE_IDENTITY_UNAVAILABLE"


class ArtifactKeyNotWritable(InvalidArtifactKey):
    """Ein Schlüssel, der in diesem Kontext nicht geschrieben wird.

    Erbt von `src/ohpipe/domain/artifact_key.py::InvalidArtifactKey`: die
    Anwendungsschicht erfindet keine zweite Fehlerfamilie, und ein Aufrufer,
    der den B1-Fehler fängt, fängt auch diesen. Der Grund steht als Attribut
    ``reason_code``.
    """

    def __init__(self, reason_code: GateReason, meldung: str) -> None:
        super().__init__(meldung)
        self.reason_code = reason_code


def check_record_scoped_key(
    key: ArtifactKey, profile: object, current_record_id: str
) -> ArtifactKey:
    """Ist ``key`` im aktuellen recordgebundenen Kontext schreibbar?

    Die fünf Bedingungen in genau dieser Reihenfolge:

    1. ``current_record_id`` ist eine kanonische Kennung von ``profile``;
    2. ``key.scope`` ist genau ``Scope.RECORD``;
    3. ``key.scope_id`` ist **selbst** eine kanonische Kennung desselben Profils;
    4. beide formgültigen Kennungen sind **zeichengleich**;
    5. ``key.kind`` steht im aktiven Graphen dieses Profils.

    Die Reihenfolge ist die Aussage. Der Kontext wird zuerst geprüft: sonst
    wäre eine Gleichheitsprüfung mit sich selbst zufriedenzustellen, weil
    derselbe ungültige Wert auf beiden Seiten stehen kann. ``Scope.WORKSPACE``
    fällt vor Schritt 3, damit seine ``scope_id`` gar nicht erst als
    ``record_id`` gelesen wird. Und Form kommt vor Gleichheit, damit die
    Meldung zur Kontextungleichheit sagen darf, dass beide Seiten formgültig
    sind — sie sind es dann gemessen.

    **Was hier nicht abgefangen wird.** Die Totalität zwischen erzeugten
    Artefaktarten und Verträgen ist die fail-closed Grenze von
    `src/ohpipe/domain/step.py::build_graph`; ein Drift hält dort mit
    ``GraphError``, und dieses Tor übersetzt ihn nicht in einen
    ArtifactKey-Grund. Nach bestandener Mitgliedschaft ist die Totalität
    erwiesen, und ``contract_for`` wird ohne pauschalen Fang gezogen: eine
    unerwartete Ausnahme bleibt in Typ, Text und Ursache dieselbe.

    Gibt bei Erfolg denselben Schlüssel zurück; hält sonst mit
    :class:`ArtifactKeyNotWritable` **vor jeder Ablage**.
    """
    if not profile.is_record_id(current_record_id):
        raise ArtifactKeyNotWritable(
            GateReason.INVALID_CURRENT_RECORD_ID,
            f"Der aktuelle Record-Kontext {current_record_id!r} ist keine kanonische "
            f"Kennung des Profils {getattr(profile, 'id', '?')!r} (erwartete Form: "
            f"{profile.record_id(7)!r}). Ohne gültigen Kontext gibt es nichts, "
            "wogegen scope_id geprüft werden könnte.",
        )

    if key.scope is not Scope.RECORD:
        raise ArtifactKeyNotWritable(
            GateReason.WORKSPACE_IDENTITY_UNAVAILABLE,
            f"scope ist {key.scope.value!r}; dieses Tor ist recordgebunden und hat "
            "keine workspace-Identitätsquelle. Das Ereignis "
            "workspace.identity.assigned, aus dem eine workspace_id stammen müsste, "
            "existiert im Produktcode nicht. Ein Pfad, ein Profilname oder ein neu "
            "erzeugter Wert wäre keine workspace_id, sondern eine Erfindung; der "
            "Schlüssel wird deshalb nicht geschrieben.",
        )

    if not profile.is_record_id(key.scope_id):
        raise ArtifactKeyNotWritable(
            GateReason.INVALID_SCOPE_ID,
            f"scope_id ist {key.scope_id!r} und damit keine kanonische Record-Kennung "
            f"des Profils {getattr(profile, 'id', '?')!r} (erwartete Form: "
            f"{profile.record_id(7)!r}). Über den Kontext ist damit nichts gesagt: "
            "geprüft wurde die Form, und sie trägt nicht.",
        )

    if key.scope_id != current_record_id:
        raise ArtifactKeyNotWritable(
            GateReason.SCOPE_ID_CONTEXT_MISMATCH,
            f"scope_id ist {key.scope_id!r}, der aktuelle Record-Kontext ist aber "
            f"{current_record_id!r}. Beide sind für dieses Profil formgültig — das hat "
            "dieses Tor für beide Seiten gemessen. Genau deshalb genügt die Form nicht: "
            "zwei gültige Kennungen sind nicht derselbe Kontext.",
        )

    graph = build_graph(profile)

    if key.kind not in graph.artifacts:
        raise ArtifactKeyNotWritable(
            GateReason.KIND_NOT_IN_ACTIVE_GRAPH,
            f"kind ist {key.kind!r}; der aus dem Profil "
            f"{getattr(profile, 'id', '?')!r} gebaute aktive Graph erzeugt diese "
            f"Artefaktart nicht. Er erzeugt: {sorted(graph.artifacts)}. Das ist kein "
            "Urteil über die Art im Allgemeinen, sondern über diesen Schreibpfad.",
        )

    # KEIN try/except um diesen Aufruf. Ein ``GraphError`` bleibt ein
    # ``GraphError``, eine unerwartete Ausnahme bleibt sie selbst. Die
    # Vorgängerfassung fing pauschal und etikettierte jede Ursache als
    # fehlenden Vertrag — ein maschinenlesbarer Grund, der im Fehlerfall das
    # Falsche behauptet, ist schlimmer als keiner.
    graph.contract_for(key.kind)

    return key
