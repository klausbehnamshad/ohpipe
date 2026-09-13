"""Rotphase zu Scheibe 4a — zwei Zusicherungen, die heute fallen müssen.

4a speist die drei Zustandsachsen aus dem `ArtifactContract` statt aus `Kind`
(E2, *„Rollen statt `Kind`"*). Diese Datei beschreibt, **woran man das
erkennt**, bevor jemand es baut. Kein Produktivcode.

Beide Marker sind in **beide Richtungen** gemessen — heute rot an der
Zielassertion, unter minimal nachgestellter 4a grün. Diese zwei Messungen sind
seit Serie 3c Auslieferungsbedingung für jeden `xfail(strict)`: Der erste
Anlauf von T3 war rot aus einem Grund, den er gar nicht prüfen wollte, und wäre
deshalb auch nach der Umsetzung rot geblieben — ein Wartemarker auf etwas
Unerreichbares.

Und beide Marker sind **Einachsentests**. T7 sichert die Bindungsachse zu und
nicht den Status: `transcript.revision` bleibt nach der Bindungskorrektur
zunächst auf `STOP`, weil die Ableitungsachse noch offen ist. Ein Marker, der
beide Achsen zugleich verlangt, wartet wieder auf zwei Dinge.
"""

from __future__ import annotations

import json
from pathlib import Path

from ohpipe.domain.state import ArtifactState, DecisionState, DerivationState, SourceBinding

from ._forge import cli, place_object
from ._forge import forge as forge_unkeyed

#: Das Ingressartefakt. Seine Eingabe ist eine Datei ausserhalb des Systems,
#: kein ``ArtifactKey`` — es hat weder Anker noch Beleg noch Entscheidung.
INGRESS = "transcript.revision"

#: Die drei Halbsätze, aus denen die READY-Erklärung heute zusammengesetzt ist.
GEBUNDEN = "aktuell gebunden"
EINGABEN = "Eingaben unverändert"
VERANTWORTET = "von einem Menschen verantwortet"


def _welt(tmp_path: Path) -> Path:
    wurzel = tmp_path / "daten"
    assert cli("init", root=wurzel).returncode == 0
    return wurzel


def _artefakt(wurzel: Path, name: str) -> dict:
    ergebnis = cli("status", "--json", root=wurzel)
    rec = json.loads(ergebnis.stdout)["details"]["records"][0]
    assert rec["findings"] == [], rec["findings"]
    return rec["artifacts"][name]


# --------------------------------------------------- T6 · die Erklärungszeile


def test_ready_explanation_names_inputs_when_derivation_is_current():
    """Gegenrichtung zu T6, muss heute grün sein und grün bleiben.

    Wo eine Ableitung existiert und aktuell ist, **soll** die Erklärung sie
    nennen. Ohne diese Zusicherung könnte der Fix für T6 darin bestehen, den
    Halbsatz überall zu löschen.
    """
    st = ArtifactState(SourceBinding.BOUND, DerivationState.CURRENT, DecisionState.ACCEPTED)
    assert st.status.value == "READY", st
    assert EINGABEN in st.explanation, st.explanation


def test_ready_explanation_omits_inputs_when_derivation_not_applicable():
    """Ein Artefakt ohne Ableitung bekommt keine Erklärung, die eine behauptet.

    Gemessen, heute: **beide** READY-Kombinationen tragen denselben Satz.

        bound / current        / accepted -> „aktuell gebunden, Eingaben
                                             unverändert, von einem Menschen
                                             verantwortet"
        bound / not_applicable / accepted -> derselbe Satz            <- falsch

    Die zweite Zeile ist der Zustand **jedes menschlich bestätigten Artefakts**
    heute — `transcript.confirmed`, `metadata.confirmed`, `release.approved`.
    Der Defekt ist also nicht neu mit 4a; er läuft seit jeher durch
    ``status --json``. Nach 4a träfe derselbe Satz noch mehr Kombinationen.

    Die zwei positiven Zeilen vor der Zielzeile sind kein Beiwerk: Ohne sie
    wäre die Zielzeile auch von einer leeren Erklärung erfüllt.
    """
    st = ArtifactState(SourceBinding.BOUND, DerivationState.NOT_APPLICABLE, DecisionState.ACCEPTED)

    assert st.status.value == "READY", st  # Wächter: es geht um die READY-Zeile
    assert GEBUNDEN in st.explanation, st.explanation  # wahr, muss dastehen
    assert VERANTWORTET in st.explanation, st.explanation  # wahr, muss dastehen

    assert EINGABEN not in st.explanation, (
        "Die Erklärung behauptet 'Eingaben unverändert' für ein Artefakt, dessen "
        f"Ableitungsachse not_applicable ist: {st.explanation!r}"
    )


# ---------------------------------------------------- T7 · die Bindungsachse


def test_a_drifted_anchor_still_says_drifted(tmp_path: Path):
    """Gegenprobe zu T7, damit der Marker nicht „N/A für alles" durchwinkt.

    Ein Ankerergebnis, das sich nicht schliessen lässt, muss weiterhin
    ``drifted`` melden. Ohne diese Zusicherung wäre T7 auch dann grün, wenn 4a
    die Bindungsachse pauschal auf ``not_applicable`` setzte — und damit die
    Ankerdrift stillstellte, die Demo-Moment 2 zeigt.
    """
    wurzel = _welt(tmp_path)
    sha = place_object(wurzel, b"eine Transkriptfassung")
    forge_unkeyed(
        wurzel,
        [
            {"kind": "artifact.produced", "payload": {"artifact": INGRESS, "sha256": sha}},
            {"kind": "anchor.checked", "payload": {"artifact": INGRESS, "outcome": "ambiguous"}},
        ],
    )
    assert _artefakt(wurzel, INGRESS)["source_binding"] == "drifted"


def test_anchorless_artifact_is_not_unknown(tmp_path: Path):
    """Ein Artefakt, das per Vertrag keinen Anker hat, steht nicht auf ``UNKNOWN``.

    Der Name steht so in den Abnahmekriterien von ADR 0027; er ist nicht
    erfunden, er wird hier eingelöst.

    **Mit C2 eingelöst — der Marker ist weg, der Test bleibt.** Gemessen vor C2,
    `transcript.revision` mit nichts als einem `artifact.produced`:
    ``source_binding = unknown``, und weil `UNKNOWN → STOP` ganz oben in der
    Leiter steht, schrieb diese Achse auch die Erklärung. Gemessen unter der
    minimalen C2-Umsetzung: ``XPASS(strict)``, also die Grünrichtung in
    derselben Zeile, an der er rot war. Erst danach ist der ``xfail`` gefallen.

    Der Test bleibt stehen, weil er die Eigenschaft prüft und nicht das
    Ereignis ihrer Herstellung: Ein späterer Umbau, der die Bindungsachse
    wieder pauschal fail-closed setzte, ginge sonst unbemerkt durch.

    **Warum die Assertion die Zeichenkette aus ``to_json`` vergleicht und nicht
    den Enumwert:** Sie stammt aus der Rotphase, in der
    ``SourceBinding.NOT_APPLICABLE`` noch nicht existierte — ein Test, der ihn
    importierte, wäre kein roter Test gewesen, sondern ein Sammelfehler. Sie
    bleibt so: Geprüft wird die Ausgabe an der Operatorgrenze, und die trägt
    Zeichenketten.

    **Warum hier kein Status zugesichert wird:** Diese Zeile sichert eine
    Achse zu. Den Status von `transcript.revision` sichert
    ``test_transcript_revision_is_ready_on_bytes_alone`` zu, einachsig
    getrennt davon.
    """
    wurzel = _welt(tmp_path)
    sha = place_object(wurzel, b"eine Transkriptfassung")
    forge_unkeyed(
        wurzel,
        [{"kind": "artifact.produced", "payload": {"artifact": INGRESS, "sha256": sha}}],
    )

    achse = _artefakt(wurzel, INGRESS)["source_binding"]
    assert achse == "not_applicable", (
        f"{INGRESS} hat per Vertrag keinen Anker, meldet aber {achse!r}. "
        "unknown ist fail-closed und deshalb dauerhaft STOP."
    )
