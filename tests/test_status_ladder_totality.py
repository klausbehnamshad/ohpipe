"""Die Statusleiter ist total — kein Zustand fällt hinten heraus.

``ArtifactState.status`` endet mit ``return Status.STOP  # unerreichbar bei
vollständiger Abdeckung — absichtlich rot``. Der Kommentar ist eine Behauptung
über *alle* Kombinationen der drei Achsen. Bisher hat sie niemand geprüft.

**Woher dieser Test kommt.** Die Abnahme für Scheibe 4a verlangte, dass
``SourceBinding.NOT_APPLICABLE`` und ``DecisionState.NOT_APPLICABLE``
*existieren*. Genau das gebaut — nur die zwei Enumwerte, Leiter unberührt —
und der Zustand, den 4b herstellen soll, stand auf ``STOP`` mit der Erklärung
*„nicht abgedeckter Zustand"*. Die Abnahmezeile war abhakbar und das Ergebnis
trotzdem rot. Dieser Test macht aus „drei Zeilen Python gegen die Leiter" eine
Maschine, die bei jedem Lauf mitläuft.

Er ist **heute grün**, bleibt es durch 4a hindurch, und geht in der Sekunde
rot, in der jemand einen Enumwert hinzufügt, ohne die Endklausel zu erweitern.
Gemessen: mit ``SourceBinding.NOT_APPLICABLE`` allein fallen zwei der dann 64
Kombinationen auf den Auffangfall.
"""

from __future__ import annotations

import inspect
import itertools

import pytest

from ohpipe.domain.state import (
    ArtifactState,
    DecisionState,
    DerivationState,
    LegacyDisposition,
    SourceBinding,
)
from ohpipe.policies.exit_contract import Status

#: Der Satz, den ``explanation`` genau dann liefert, wenn die Leiter hinten
#: herausgefallen ist. Er steht hier AUSGESCHRIEBEN und wird nicht aus
#: ``state.py`` importiert — sonst prüfte der Test den Code gegen sich selbst
#: und zöge bei einer Umbenennung stillschweigend mit.
AUFFANGFALL = "nicht abgedeckter Zustand"

ALLE_KOMBINATIONEN = list(itertools.product(SourceBinding, DerivationState, DecisionState))


#: Die drei Zahlen aus den Abnahmekriterien zu C2, ausgeschrieben. Sie stehen
#: hier als SOLLWERT und werden gegen die Enums gemessen — nicht andersherum.
#: Ohne sie wäre die Totalität unten auch dann grün, wenn jemand einen Enumwert
#: WEGnähme: Weniger Kombinationen fallen ebenfalls nicht durch.
KOMBINATIONEN = 80
READY_KOMBINATIONEN = 8
AUFFANGFAELLE = 0

READY_EXPLANATION_CASES = (
    (
        SourceBinding.BOUND,
        DerivationState.CURRENT,
        DecisionState.ACCEPTED,
        "aktuell gebunden, Eingaben unverändert, von einem Menschen verantwortet",
    ),
    (
        SourceBinding.BOUND,
        DerivationState.CURRENT,
        DecisionState.NOT_APPLICABLE,
        "aktuell gebunden, Eingaben unverändert",
    ),
    (
        SourceBinding.BOUND,
        DerivationState.NOT_APPLICABLE,
        DecisionState.ACCEPTED,
        "aktuell gebunden, von einem Menschen verantwortet",
    ),
    (
        SourceBinding.BOUND,
        DerivationState.NOT_APPLICABLE,
        DecisionState.NOT_APPLICABLE,
        "aktuell gebunden",
    ),
    (
        SourceBinding.NOT_APPLICABLE,
        DerivationState.CURRENT,
        DecisionState.ACCEPTED,
        "Eingaben unverändert, von einem Menschen verantwortet",
    ),
    (
        SourceBinding.NOT_APPLICABLE,
        DerivationState.CURRENT,
        DecisionState.NOT_APPLICABLE,
        "Eingaben unverändert",
    ),
    (
        SourceBinding.NOT_APPLICABLE,
        DerivationState.NOT_APPLICABLE,
        DecisionState.ACCEPTED,
        "von einem Menschen verantwortet",
    ),
    (
        SourceBinding.NOT_APPLICABLE,
        DerivationState.NOT_APPLICABLE,
        DecisionState.NOT_APPLICABLE,
        "keine Bindung, kein Ableitungsbeleg und keine menschliche Entscheidung erforderlich",
    ),
)

READY_EXPLANATION_IDS = (
    "bound-current-accepted",
    "bound-current-not_applicable",
    "bound-not_applicable-accepted",
    "bound-not_applicable-not_applicable",
    "not_applicable-current-accepted",
    "not_applicable-current-not_applicable",
    "not_applicable-not_applicable-accepted",
    "not_applicable-not_applicable-not_applicable",
)


def test_the_three_axes_span_exactly_the_expected_number_of_combinations():
    """4 x 4 x 5 = 80, von Hand gegen die Enums gemessen.

    Die Zahl steht in den Abnahmekriterien zu C2 und ist deshalb hier eine
    Zusicherung. Sie fällt in beide Richtungen: bei einem zusätzlichen wie bei
    einem entfernten Achsenwert.
    """
    assert len(ALLE_KOMBINATIONEN) == KOMBINATIONEN, (
        f"{len(SourceBinding)} x {len(DerivationState)} x {len(DecisionState)} = "
        f"{len(ALLE_KOMBINATIONEN)}, erwartet {KOMBINATIONEN}. Ein Achsenwert ist "
        "dazugekommen oder verschwunden — Endklausel und diese Zahl gemeinsam nachziehen."
    )


def test_exactly_eight_combinations_are_ready():
    """Genau acht Kombinationen ergeben ``READY`` — nicht sieben, nicht neun.

    ``test_the_ladder_never_answers_ready_by_accident`` prüft, dass keine
    UNZULÄSSIGE Kombination grün wird. Das lässt die andere Richtung offen: Eine
    Endklausel, die eine zulässige Kombination vergisst, bliebe dort unbemerkt
    und fiele erst irgendeinem Statustest auf. Diese Zeile schliesst sie.
    """
    fertig = sorted(
        (b.value, v.value, d.value)
        for b, v, d in ALLE_KOMBINATIONEN
        if ArtifactState(b, v, d).status.value == "READY"
    )
    assert len(fertig) == READY_KOMBINATIONEN, (
        f"{len(fertig)} statt {READY_KOMBINATIONEN} Kombinationen ergeben READY: {fertig}"
    )


@pytest.mark.parametrize(
    ("binding", "derivation", "decision", "expected"),
    READY_EXPLANATION_CASES,
    ids=READY_EXPLANATION_IDS,
)
def test_ready_explanation_is_composed_from_exactly_the_applicable_axes(
    binding,
    derivation,
    decision,
    expected,
):
    state = ArtifactState(
        binding,
        derivation,
        decision,
        enabled=True,
        disposition=LegacyDisposition.OK,
    )

    assert state.status is Status.READY
    assert state.explanation == expected


def test_ready_explanation_matrix_has_exactly_the_ready_combination_count():
    assert len(READY_EXPLANATION_CASES) == READY_KOMBINATIONEN


def test_the_number_of_uncovered_combinations_is_zero():
    """Dieselbe Aussage wie die Totalität — aber als Zahl, nicht als Liste.

    Die Abnahme zu C2 nennt ``0 Auffangfälle`` als eigenes Kriterium. Ein
    Kriterium, das nur als leere Liste irgendwo mit abfällt, ist im
    Abnahmeprotokoll nicht ablesbar.
    """
    durchgefallen = [
        (b.value, v.value, d.value)
        for b, v, d in ALLE_KOMBINATIONEN
        if ArtifactState(b, v, d).explanation == AUFFANGFALL
    ]
    assert len(durchgefallen) == AUFFANGFAELLE, durchgefallen


def test_the_uncovered_sentinel_is_still_the_one_we_watch():
    """Der Wächter unten hängt an einer Zeichenkette — also wird sie festgenagelt.

    Benennt jemand den Satz um, fände ``test_status_ladder_is_total`` nie
    wieder etwas und bliebe für immer grün: ein Wächter, der über nichts
    wacht. Dasselbe Muster wie ``test_the_known_gap_is_exactly_these_three``.
    """
    quelle = inspect.getsource(ArtifactState.explanation.fget)
    assert AUFFANGFALL in quelle, (
        "Der Auffangfall in ArtifactState.explanation heißt nicht mehr "
        f"{AUFFANGFALL!r}. Dann prüft test_status_ladder_is_total nichts mehr — "
        "beide Stellen gemeinsam nachziehen."
    )


def test_the_ladder_covers_every_combination_of_the_three_axes():
    """Keine Kombination der drei Achsen fällt auf den Auffangfall.

    Das Produkt wird über die Enums selbst gebildet, nicht über eine Liste von
    Werten. Ein neuer Enumwert erweitert deshalb automatisch die Prüfung —
    genau das ist der Sinn: Die Lücke, die 4a sonst aufreißt, meldet sich von
    selbst.
    """
    durchgefallen = [
        (b.value, v.value, d.value)
        for b, v, d in ALLE_KOMBINATIONEN
        if ArtifactState(b, v, d).explanation == AUFFANGFALL
    ]
    assert durchgefallen == [], (
        f"{len(durchgefallen)} von {len(ALLE_KOMBINATIONEN)} Kombinationen fallen auf den "
        f"Auffangfall am Ende von ArtifactState.status: {durchgefallen}. "
        "Ein neuer Achsenwert braucht eine Endklausel, die ihn kennt."
    )


def test_the_ladder_never_answers_ready_by_accident():
    """Gegenrichtung: Totalität darf nicht durch ein grosszügiges READY entstehen.

    Ohne diese Zusicherung wäre der Test oben auch dann grün, wenn jemand die
    Endklausel auf ``return Status.READY`` setzte — dann fiele nichts mehr
    heraus, und alles wäre fertig. ``READY`` verlangt auf **jeder** Achse einen
    Wert, der Erfüllung oder Nichtzuständigkeit bedeutet.
    """
    erlaubt_bindung = {SourceBinding.BOUND}
    erlaubt_ableitung = {DerivationState.CURRENT, DerivationState.NOT_APPLICABLE}
    erlaubt_entscheidung = {DecisionState.ACCEPTED}

    # Nach 4a kommen NOT_APPLICABLE auf Bindung und Entscheidung dazu; der Test
    # liest die Mengen deshalb nachsichtig über den Namen, nicht über Identität.
    def zulaessig(wert) -> bool:
        return wert.value == "not_applicable"

    verdaechtig = [
        (b.value, v.value, d.value)
        for b, v, d in ALLE_KOMBINATIONEN
        if ArtifactState(b, v, d).status.value == "READY"
        and not (
            (b in erlaubt_bindung or zulaessig(b))
            and (v in erlaubt_ableitung or zulaessig(v))
            and (d in erlaubt_entscheidung or zulaessig(d))
        )
    ]
    assert verdaechtig == [], f"READY auf einer Kombination, die es nicht sein darf: {verdaechtig}"


@pytest.mark.parametrize("achse", ["source_binding", "derivation_state", "decision_state"])
def test_every_axis_actually_influences_the_status(achse):
    """Und noch eine Gegenrichtung: jede Achse muss überhaupt etwas bewirken.

    Eine Leiter, die eine Achse ignoriert, ist ebenfalls „total" — und falsch.
    Geprüft wird, dass es für jede Achse mindestens zwei Werte gibt, die bei
    sonst gleichen Achsen zu verschiedenen Status führen.
    """
    gesehen: dict[tuple, set[str]] = {}
    for b, v, d in ALLE_KOMBINATIONEN:
        werte = {"source_binding": b, "derivation_state": v, "decision_state": d}
        rest = tuple(sorted((k, x.value) for k, x in werte.items() if k != achse))
        gesehen.setdefault(rest, set()).add(ArtifactState(b, v, d).status.value)
    assert any(len(s) > 1 for s in gesehen.values()), (
        f"{achse} ändert bei keiner Belegung der anderen beiden Achsen den Status — "
        "die Achse wird von der Leiter nicht gelesen."
    )
