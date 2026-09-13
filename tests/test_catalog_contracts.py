"""Vertragsmessung des Katalogpfads (E2-N, Streichungsvermerk V2 Abschnitt 3).

Die drei Ableitungen und die drei Bestaetigungen teilen jeweils ihre Vertraege —
das ist kein Zufall, sondern die Aussage: ``metadata`` und ``abstract`` tragen
als Entwuerfe denselben Rang, und ``release.preview`` unterscheidet sich von
ihnen in GENAU einem Feld — der Bindung, denn eine Vorschau hat keine Textanker
(E2-N Nr. 5). Die drei Bestaetigungen sind zeichengleich: ein menschlich
verantwortetes, gebundenes Ergebnis ohne eigenen Beleg (E2-N Nr. 6).
"""

from __future__ import annotations

from ohpipe.domain.step import DEFAULT_GRAPH

_AXES = ("binding_required", "provenance_required", "decision_required")


def _c(name: str):
    return DEFAULT_GRAPH.contract_for(name)


def test_metadata_and_abstract_drafts_carry_the_same_contract():
    assert _c("metadata.draft") == _c("abstract.draft")


def test_release_preview_differs_from_the_drafts_in_exactly_binding_required():
    draft = _c("metadata.draft")
    preview = _c("release.preview")
    diffs = {f for f in _AXES if getattr(draft, f) != getattr(preview, f)}
    assert diffs == {"binding_required"}, diffs
    assert preview.binding_required is False


def test_the_three_confirmations_carry_the_same_contract():
    metadata = _c("metadata.confirmed")
    assert _c("abstract.confirmed") == metadata
    assert _c("release.approved") == metadata
    assert (metadata.binding_required, metadata.provenance_required, metadata.decision_required) == (
        True,
        False,
        True,
    )


def test_the_export_declares_exactly_the_input_the_graph_requires():
    """Woran das Erbe des Ausgangs haengt — gemessen, nicht angenommen.

    ``_inherit_egress_decision`` vergleicht die Belegeingaben von
    ``export.bundle`` als MENGE mit ``Step.requires``. Eine zusaetzliche
    Eingabe im Beleg, auch eine wahre, nimmt dem Ausgang damit die geerbte
    Entscheidung; eine fehlende ebenso. ``export.py`` schreibt deshalb genau
    eine Eingabe, und dieser Fall haelt die beiden Stellen aneinander: waechst
    die Vorbedingung im Graphen, faellt er, statt dass der Ausgang still
    aufhoert zu erben.
    """
    from ohpipe.application.export import UPSTREAM

    assert set(DEFAULT_GRAPH.producer_of("export.bundle").requires) == {UPSTREAM}


def test_the_egress_contract_demands_binding_provenance_and_a_decision():
    """E2-N Nr. 8: der Ausgang verlangt alle drei Achsen.

    ``decision_required`` bleibt wahr — das WENN steckt in der Erfuellung
    (geerbt), nicht im Vertragswert. Ein Vertrag, der die Entscheidung fuer den
    Egress fallen liesse, machte das Erben zur Nettigkeit statt zur Bedingung.
    """
    bundle = _c("export.bundle")
    assert (bundle.binding_required, bundle.provenance_required, bundle.decision_required) == (
        True,
        True,
        True,
    )
    assert _c("analysis.bundle") == bundle
