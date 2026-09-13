"""Rotphase zu C5 — die geerbte Egressentscheidung, als berechneter Zustand.

Entschieden am 09.08.2026 als **12a** und **13a**, festgeschrieben in
`docs/PLAN_SCHEIBE-C.md`:

* Die geerbte Entscheidung ist **ausschliesslich berechneter Replay-Zustand**.
  Niemand schreibt ein maschinelles ``decision.recorded`` auf ein
  Egress-Artefakt.
* Träger der Kette ist ``receipt.recorded.inputs``, weil die Egressrolle
  ``provenance_required = true`` trägt. Der Satz im Modulkopf von
  ``test_input_refs_payload.py``, der gegen Receipts spricht, ist ausdrücklich
  auf Rollen mit ``provenance_required = false`` beschränkt.

Die Kette, vollständig::

    receipt.output_sha256  ==  aktueller Hash des Egress-Artefakts
    set(receipt.inputs)    ==  {"release.approved"}  bzw. {"analysis.approved"}
    der referenzierte Hash ==  aktueller Hash des Upstream-Artefakts
    und auf GENAU diesem Hash steht VORHER im Journal ein ACCEPT

**Warum die erwartete Eingabemenge hier ausgeschrieben steht.** Im
Produktivcode darf sie später aus ``producer.requires`` abgeleitet werden.
Ein Test, der das täte, prüfte den Graphen gegen sich selbst — dieselbe Regel
wie bei ``ARTIFACTS`` und ``model_made`` in ``tests/test_forgery.py``.

Kein Produktivcode in dieser Datei.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ohpipe.application.replay import replay
from ohpipe.domain.step import (
    DEFAULT_GRAPH,
    ArtifactContract,
    Kind,
    Step,
    StepGraph,
)
from ohpipe.policies.authority import Authority

from ._forge import cli, place_object
from ._forge import forge as forge_unkeyed

#: Beide Egresspaare, von Hand geführt. E2-N Nummer 7 erklärt sie für
#: strukturgleich; geprüft wird das hier und nicht vorausgesetzt.
FREIGABE = "release.approved"
EGRESS = "export.bundle"
FREIGABE_ANALYSE = "analysis.approved"
EGRESS_ANALYSE = "analysis.bundle"

FRUEH = "2026-09-01T09:00:00+00:00"
SPAET = "2026-09-01T17:00:00+00:00"


def _welt(tmp_path: Path) -> Path:
    wurzel = tmp_path / "daten"
    assert cli("init", root=wurzel).returncode == 0
    return wurzel


def _record(wurzel: Path) -> dict:
    return json.loads(cli("status", "--json", root=wurzel).stdout)["details"]["records"][0]


def _erzeugt(artefakt: str, sha: str) -> dict:
    return {"kind": "artifact.produced", "payload": {"artifact": artefakt, "sha256": sha}}


def _entscheidung(artefakt: str, sha: str, wann: str) -> dict:
    return {
        "kind": "decision.recorded",
        "payload": {
            "artifact": artefakt,
            "subject_sha256": sha,
            "verdict": "ACCEPT",
            "reference": f"PI-{artefakt}",
            "actor": "kbs",
            "at": wann,
        },
    }


def _beleg(artefakt: str, ausgabe: str, eingaben: dict[str, str]) -> dict:
    return {
        "kind": "receipt.recorded",
        "payload": {
            "artifact": artefakt,
            "output_sha256": ausgabe,
            "inputs": eingaben,
            "code_version": "0.1.0",
        },
    }


def _anker(artefakt: str) -> dict:
    """Der geprüfte Anker auf dem Freigabeartefakt.

    Seit C2 bindet ``is_human_artifact`` nicht mehr von selbst: ``binding_required``
    steht für ``release.approved`` und ``analysis.approved`` auf ``true``, also
    braucht die Freigabe echte Ankerevidenz. Ohne sie stünde sie auf ``unknown``
    und damit auf ``STOP`` — und jeder Marker unten wäre rot, weil die Kette schon
    oben scheitert, statt weil die Vererbung fehlt. Genau davor warnt der Wächter
    ``test_the_upstream_release_is_accepted_on_its_own``.
    """
    return {"kind": "anchor.checked", "payload": {"artifact": artefakt, "outcome": "exact"}}


def _kette(wurzel: Path, freigabe: str, egress: str, *, entscheidung_wann: str, zuerst: str):
    """Baut die vollständige Egresskette. ``zuerst`` sagt, was vorn steht."""
    from .test_forgery import wellformed_chain
    from ._p3_evidence import INPUTS, ancestors, bindings

    prefix = [
        e for e in wellformed_chain(wurzel) if e["payload"].get("artifact") in ancestors(freigabe)
    ]
    source_sha = prefix[0]["payload"]["sha256"]
    oben = place_object(wurzel, b"die freigegebene Fassung")
    unten = place_object(wurzel, b"das erzeugte Buendel")
    freigabeteil = [
        _erzeugt(freigabe, oben),
        _anker(freigabe),
        _entscheidung(freigabe, oben, entscheidung_wann),
    ]
    freigabeteil[-1]["payload"].update(bindings(freigabe, source_sha))
    freigabeteil.append(_beleg(freigabe, oben, {role: source_sha for role in INPUTS[freigabe]}))
    egressteil = [_erzeugt(egress, unten), _beleg(egress, unten, {freigabe: oben})]
    reihenfolge = freigabeteil + egressteil if zuerst == "freigabe" else egressteil + freigabeteil
    forge_unkeyed(wurzel, prefix + reihenfolge)
    return oben, unten


# ------------------------------------------------- Gegenproben, heute gruen


def test_the_upstream_release_is_accepted_on_its_own(tmp_path: Path):
    """Wächter für alle Marker unten: die Freigabe selbst trägt.

    Ohne sie wäre jeder Marker auch dann rot, wenn die Kette schon oben
    scheiterte — dann wartete er auf etwas, das mit der Vererbung nichts zu
    tun hat. Genau der Fehler, den T3 in Serie 3b hatte.
    """
    wurzel = _welt(tmp_path)
    _kette(wurzel, FREIGABE, EGRESS, entscheidung_wann=FRUEH, zuerst="freigabe")

    rec = _record(wurzel)
    assert rec["findings"] == [], rec["findings"]
    assert rec["artifacts"][FREIGABE]["decision_state"] == "accepted"
    assert rec["artifacts"][FREIGABE]["status"] == "READY"


def test_a_later_release_does_not_retroactively_authorise_an_export(tmp_path: Path):
    """Eine spätere Freigabe autorisiert einen früheren Exportbeleg nicht.

    **Heute grün, und das ist kein Erfolg, sondern der Ausgangszustand:** es
    gibt überhaupt keine Vererbung, also auch keine rückwirkende. Diese
    Zusicherung steht hier, damit C5 die Reihenfolge nicht mitverliert. Sie
    ist dieselbe Regel, die
    ``src/ohpipe/application/replay.py::_bind_model_receipt`` schon trägt —
    *„im Journal (bis hierher)"*.

    Gemessen, heute: ``decision_state = undecided``. Nach C5 muss sie es
    bleiben, obwohl die Kette formal vollständig ist — nur eben in der
    falschen Reihenfolge.
    """
    wurzel = _welt(tmp_path)
    _kette(wurzel, FREIGABE, EGRESS, entscheidung_wann=SPAET, zuerst="egress")

    rec = _record(wurzel)
    assert rec["findings"] == [], rec["findings"]
    zustand = rec["artifacts"][EGRESS]["decision_state"]
    assert zustand != "accepted", (
        f"{EGRESS} hat die Entscheidung geerbt, obwohl die Freigabe erst NACH "
        f"dem Beleg im Journal steht: {zustand!r}"
    )


# ------------------------------------------------------------ die Marker


def test_an_exact_earlier_release_chain_inherits_the_egress_decision(tmp_path: Path):
    """Die vollständige Kette erfüllt die Entscheidungsachse des Egressartefakts.

    Gemessen, heute — Freigabe akzeptiert, Beleg mit
    ``inputs = {"release.approved": <ihr Hash>}`` und passendem
    ``output_sha256``::

        release.approved   decision_state = accepted   status = READY
        export.bundle      decision_state = undecided  status = STOP

    Die Ableitungsachse steht bereits auf ``current`` — der Beleg wird also
    gelesen. Was fehlt, ist allein die Vererbung: E2-N Nummer 8 verlangt
    ``decision_required = true``, erfüllt durch die Kette, und heute erfüllt
    die Kette nichts.

    **Warum kein Status zugesichert wird.** Nach der Vererbung allein bleibt
    ``export.bundle`` auf ``STOP``, solange die Bindungsachse ohne Anker auf
    ``unknown`` steht — das ist C2s Sache, nicht C5s. Ein Marker, der beide
    Achsen verlangte, wartete auf zwei Dinge.
    """
    wurzel = _welt(tmp_path)
    _kette(wurzel, FREIGABE, EGRESS, entscheidung_wann=FRUEH, zuerst="freigabe")

    rec = _record(wurzel)
    assert rec["findings"] == [], rec["findings"]  # Waechter: die Kette kam an
    assert rec["artifacts"][EGRESS]["derivation_state"] == "current"  # Waechter: Beleg gelesen

    zustand = rec["artifacts"][EGRESS]["decision_state"]
    assert zustand == "accepted", (
        f"{EGRESS} steht auf {zustand!r}, obwohl eine exakte InputRef-Kette auf "
        f"ein frueher akzeptiertes {FREIGABE} im Journal steht."
    )


def test_a_direct_accept_on_the_egress_artifact_does_not_satisfy_the_contract(tmp_path: Path):
    """Ein Mensch, der das Bündel direkt abnickt, ersetzt die Kette nicht.

    Gemessen, heute — ``export.bundle`` mit Bytes und einem gültigen
    ``decision.recorded`` ACCEPT, **ohne jeden Beleg und ohne Upstream**::

        export.bundle   decision_state = accepted     <- falsch

    Das ist die Kante, die das System verlässt. E2 lässt dort *„keine zweite
    menschliche Entscheidung"* zu, WENN die Kette beweisbar ist — und
    verlangt sie nicht als Ersatz, wenn sie es nicht ist. Ein direkter ACCEPT
    ist beides nicht: er beweist keine Herkunft und ist doch wirksam.

    Diese Zusicherung ist die Gegenrichtung zur Vererbung. Ohne sie liesse
    sich C5 dadurch einlösen, dass die Achse einfach leichter erfüllbar wird.
    """
    wurzel = _welt(tmp_path)
    sha = place_object(wurzel, b"das erzeugte Buendel")
    forge_unkeyed(wurzel, [_erzeugt(EGRESS, sha), _entscheidung(EGRESS, sha, FRUEH)])

    rec = _record(wurzel)
    assert rec["findings"] == [], rec["findings"]  # Waechter: die Entscheidung ist gueltig

    zustand = rec["artifacts"][EGRESS]["decision_state"]
    assert zustand != "accepted", (
        f"{EGRESS} steht auf {zustand!r} allein wegen eines direkten ACCEPT — "
        "ohne Beleg, ohne Upstream, ohne nachgewiesene Herkunft."
    )


def test_the_analysis_bundle_inherits_by_the_same_rule(tmp_path: Path):
    """Die Symmetrie aus E2-N Nummer 7, einmal ausgemessen statt behauptet.

    ``analysis.approve`` (HUMAN) → ``analysis.approved`` → ``analysis.export``
    (EGRESS, ``leaves_system=True``) → ``analysis.bundle``. Gemessen ist die
    Symmetrie im Graphen angelegt; hier wird zugesichert, dass sie auch im
    Zustand gilt und nicht nur in der Tabelle.

    Ohne diesen Marker liesse sich C5 an genau einem Paar einlösen, und der
    zweite Egresspfad bliebe ungeprüft — bei einer Kante, die das System
    verlässt.
    """
    wurzel = _welt(tmp_path)
    _kette(wurzel, FREIGABE_ANALYSE, EGRESS_ANALYSE, entscheidung_wann=FRUEH, zuerst="freigabe")

    rec = _record(wurzel)
    assert rec["findings"] == [], rec["findings"]
    assert rec["artifacts"][EGRESS_ANALYSE]["derivation_state"] == "current"

    zustand = rec["artifacts"][EGRESS_ANALYSE]["decision_state"]
    assert zustand == "accepted", (
        f"{EGRESS_ANALYSE} steht auf {zustand!r}, obwohl eine exakte "
        f"InputRef-Kette auf ein frueher akzeptiertes {FREIGABE_ANALYSE} vorliegt."
    )


# --------------------------------------- C5 · isolierte Vertragswaechter

UPSTREAM_A = "a" * 64
UPSTREAM_B = "b" * 64
OUTPUT_A = "c" * 64
OUTPUT_B = "d" * 64


def _event(kind: str, payload: dict) -> SimpleNamespace:
    return SimpleNamespace(record_id="R", kind=kind, payload=payload, at=FRUEH)


def _produced(artifact: str, sha256: str) -> SimpleNamespace:
    return _event("artifact.produced", {"artifact": artifact, "sha256": sha256})


def _decided(
    artifact: str,
    sha256: str,
    verdict: str = "ACCEPT",
    *,
    reference: str = "PI-c5-a",
) -> SimpleNamespace:
    return _event(
        "decision.recorded",
        {
            "artifact": artifact,
            "subject_sha256": sha256,
            "verdict": verdict,
            "reference": reference,
            "actor": "kbs",
            "at": FRUEH,
        },
    )


def _receipt(artifact: str, output: str, inputs: dict[str, str]) -> SimpleNamespace:
    return _event(
        "receipt.recorded",
        {
            "artifact": artifact,
            "output_sha256": output,
            "inputs": inputs,
            "code_version": "c5-test",
        },
    )


def _base_chain(
    *,
    upstream: str = FREIGABE,
    egress: str = EGRESS,
    upstream_sha: str = UPSTREAM_A,
    output_sha: str = OUTPUT_A,
) -> list[SimpleNamespace]:
    return [
        _produced(upstream, upstream_sha),
        _decided(upstream, upstream_sha),
        _produced(egress, output_sha),
        _receipt(egress, output_sha, {upstream: upstream_sha}),
    ]


def _view(
    events: list[SimpleNamespace],
    *,
    graph: StepGraph = DEFAULT_GRAPH,
    authority: Authority = Authority.AUTHENTICATED,
):
    return replay(events, graph=graph, authority=authority)["R"]


def _decision_state(view, artifact: str) -> str:
    return view.to_json()["artifacts"][artifact]["decision_state"]


def test_a_receipt_for_other_output_bytes_does_not_inherit():
    events = _base_chain()[:-1]
    events.append(_receipt(EGRESS, OUTPUT_B, {FREIGABE: UPSTREAM_A}))

    view = _view(events)

    assert _decision_state(view, EGRESS) != "accepted"


@pytest.mark.parametrize(
    "inputs",
    [
        {"anderer.input": UPSTREAM_A},
        {FREIGABE: UPSTREAM_A, "anderer.input": UPSTREAM_A},
        {FREIGABE_ANALYSE: UPSTREAM_A},
    ],
    ids=["missing", "extra", "wrong"],
)
def test_a_receipt_with_the_wrong_input_key_set_does_not_inherit(inputs):
    events = _base_chain()[:-1]
    events.append(_receipt(EGRESS, OUTPUT_A, inputs))

    view = _view(events)

    assert _decision_state(view, EGRESS) != "accepted"


def test_a_receipt_for_old_upstream_bytes_does_not_inherit():
    events = [
        _produced(FREIGABE, UPSTREAM_A),
        _produced(FREIGABE, UPSTREAM_B),
        _decided(FREIGABE, UPSTREAM_B),
        _produced(EGRESS, OUTPUT_A),
        _receipt(EGRESS, OUTPUT_A, {FREIGABE: UPSTREAM_A}),
    ]

    view = _view(events)

    assert _decision_state(view, EGRESS) != "accepted"


def test_an_accept_for_old_upstream_bytes_does_not_inherit():
    events = [
        _produced(FREIGABE, UPSTREAM_A),
        _decided(FREIGABE, UPSTREAM_A),
        _produced(FREIGABE, UPSTREAM_B),
        _produced(EGRESS, OUTPUT_A),
        _receipt(EGRESS, OUTPUT_A, {FREIGABE: UPSTREAM_B}),
    ]

    view = _view(events)

    assert _decision_state(view, EGRESS) != "accepted"


def test_new_egress_bytes_invalidate_inherited_evidence():
    events = _base_chain()
    assert _decision_state(_view(events), EGRESS) == "accepted"

    events.append(_produced(EGRESS, OUTPUT_B))
    assert _decision_state(_view(events), EGRESS) != "accepted"

    events.append(_produced(EGRESS, OUTPUT_A))
    assert _decision_state(_view(events), EGRESS) != "accepted"

    events.append(_receipt(EGRESS, OUTPUT_A, {FREIGABE: UPSTREAM_A}))
    assert _decision_state(_view(events), EGRESS) == "accepted"


def test_new_upstream_bytes_invalidate_inherited_evidence():
    events = _base_chain()
    assert _decision_state(_view(events), EGRESS) == "accepted"

    events.append(_produced(FREIGABE, UPSTREAM_B))
    assert _decision_state(_view(events), EGRESS) != "accepted"

    events.append(_produced(FREIGABE, UPSTREAM_A))
    assert _decision_state(_view(events), EGRESS) != "accepted"

    events.append(_receipt(EGRESS, OUTPUT_A, {FREIGABE: UPSTREAM_A}))
    assert _decision_state(_view(events), EGRESS) == "accepted"


def test_repeating_the_same_hash_preserves_inherited_evidence():
    events = _base_chain()
    events.append(_produced(FREIGABE, UPSTREAM_A))
    events.append(_produced(EGRESS, OUTPUT_A))

    assert _decision_state(_view(events), EGRESS) == "accepted"


def test_an_accept_for_a_different_upstream_artifact_does_not_inherit():
    events = [
        _produced(FREIGABE, UPSTREAM_A),
        _produced(FREIGABE_ANALYSE, UPSTREAM_A),
        _decided(FREIGABE_ANALYSE, UPSTREAM_A),
        _produced(EGRESS, OUTPUT_A),
        _receipt(EGRESS, OUTPUT_A, {FREIGABE: UPSTREAM_A}),
    ]

    view = _view(events)

    assert _decision_state(view, EGRESS) != "accepted"


def _authorise_undo(events, artifact, sha, *, before=None):
    registration = SimpleNamespace(
        kind="instance.registered",
        record_id=None,
        payload={
            "coder_id": "kbs",
            "source": "mensch",
            "label": "synthetic",
            "reference": "P3-REGISTER",
        },
    )
    events.insert(0, registration)
    withdrawal = _decided(artifact, sha, "WITHDRAW", reference="P3-WITHDRAW")
    if before is None:
        events.append(withdrawal)
        undo = _decided(artifact, sha, "UNDO", reference="P3-UNDO")
        events.append(undo)
    else:
        position = events.index(before)
        events.insert(position, withdrawal)
        undo = before
    undo.payload["undo_of"] = f"P3-WITHDRAW@{sha[:12]}"


@pytest.mark.parametrize("verdict", ["REJECT", "WITHDRAW", "UNDO"])
def test_the_latest_journalled_upstream_decision_wins_across_reused_reference_ids(verdict):
    events = [
        _produced(FREIGABE, UPSTREAM_A),
        _decided(FREIGABE, UPSTREAM_A, reference="PI-c5-a"),
        _decided(FREIGABE, UPSTREAM_A, reference="PI-c5-b"),
        _decided(FREIGABE, UPSTREAM_A, verdict, reference="PI-c5-a"),
        _produced(EGRESS, OUTPUT_A),
        _receipt(EGRESS, OUTPUT_A, {FREIGABE: UPSTREAM_A}),
    ]

    if verdict == "UNDO":
        _authorise_undo(events, FREIGABE, UPSTREAM_A, before=events[3])

    view = _view(events)

    assert _decision_state(view, EGRESS) != "accepted"


@pytest.mark.parametrize("verdict", ["REJECT", "WITHDRAW", "UNDO"])
def test_an_authorised_later_upstream_revocation_invalidates_without_revival(verdict):
    events = _base_chain()
    events.append(_decided(FREIGABE, UPSTREAM_A, verdict, reference="PI-c5-revoke"))
    if verdict == "UNDO":
        _authorise_undo(events, FREIGABE, UPSTREAM_A, before=events[-1])
    assert _decision_state(_view(events), EGRESS) != "accepted"

    events.append(_decided(FREIGABE, UPSTREAM_A, reference="PI-c5-reaccept"))
    assert _decision_state(_view(events), EGRESS) != "accepted"

    events.append(_receipt(EGRESS, OUTPUT_A, {FREIGABE: UPSTREAM_A}))
    if verdict == "WITHDRAW":
        assert _decision_state(_view(events), EGRESS) != "accepted"
    else:
        assert _decision_state(_view(events), EGRESS) == "accepted"


@pytest.mark.parametrize("verdict", ["REJECT", "WITHDRAW", "UNDO"])
def test_an_authorised_later_egress_revocation_invalidates_without_revival(verdict):
    events = _base_chain()
    events.append(_decided(EGRESS, OUTPUT_A, verdict, reference="PI-c5-revoke"))
    if verdict == "UNDO":
        _authorise_undo(events, EGRESS, OUTPUT_A, before=events[-1])
    assert _decision_state(_view(events), EGRESS) != "accepted"

    events.append(_decided(EGRESS, OUTPUT_A, reference="PI-c5-reaccept"))
    assert _decision_state(_view(events), EGRESS) != "accepted"

    events.append(_receipt(EGRESS, OUTPUT_A, {FREIGABE: UPSTREAM_A}))
    if verdict == "WITHDRAW":
        assert _decision_state(_view(events), EGRESS) != "accepted"
    else:
        assert _decision_state(_view(events), EGRESS) == "accepted"


def _internal_contract_graph() -> StepGraph:
    source = "internal.source.c5"
    artifact = "internal.prov-and-dec.c5"
    return StepGraph(
        steps=(
            Step(name="internal-source-c5", kind=Kind.DETERMINISTIC, produces=(source,)),
            Step(
                name="internal-prov-dec-c5",
                kind=Kind.DETERMINISTIC,
                requires=(source,),
                produces=(artifact,),
            ),
        ),
        contracts={
            source: ArtifactContract(
                binding_required=False,
                provenance_required=False,
                decision_required=False,
            ),
            artifact: ArtifactContract(
                binding_required=False,
                provenance_required=True,
                decision_required=True,
            ),
        },
    )


def test_an_internal_provenance_and_decision_artifact_is_not_egress():
    graph = _internal_contract_graph()
    artifact = "internal.prov-and-dec.c5"
    contract = graph.contract_for(artifact)
    producer = graph.producer_of(artifact)
    assert contract.provenance_required is True
    assert contract.decision_required is True
    assert producer.leaves_system is False

    events = [_produced(artifact, OUTPUT_A), _decided(artifact, OUTPUT_A)]
    view = _view(events, graph=graph)

    assert view.facts[artifact].is_egress is False
    assert _decision_state(view, artifact) == "accepted"


def _custom_egress_graph() -> StepGraph:
    upstream = "custom.release.c5"
    egress = "custom.bundle.c5"
    return StepGraph(
        steps=(
            Step(name="custom-release-c5", kind=Kind.DETERMINISTIC, produces=(upstream,)),
            Step(
                name="custom-egress-c5-f3",
                kind=Kind.EGRESS,
                requires=(upstream,),
                produces=(egress,),
                leaves_system=True,
            ),
        ),
        contracts={
            upstream: ArtifactContract(
                binding_required=False,
                provenance_required=False,
                decision_required=True,
            ),
            egress: ArtifactContract(
                binding_required=False,
                provenance_required=True,
                decision_required=True,
            ),
        },
    )


def test_a_custom_named_leaves_system_artifact_is_egress_in_the_passed_graph():
    graph = _custom_egress_graph()
    upstream = "custom.release.c5"
    egress = "custom.bundle.c5"
    producer = graph.producer_of(egress)
    assert producer.name == "custom-egress-c5-f3"
    assert producer.leaves_system is True
    assert egress not in DEFAULT_GRAPH.artifacts

    view = _view(
        _base_chain(upstream=upstream, egress=egress),
        graph=graph,
    )

    assert view.graph is graph
    assert view.facts[egress].is_egress is True
    assert _decision_state(view, egress) == "accepted"


@pytest.mark.parametrize("verdict", ["REJECT", "WITHDRAW", "UNDO"])
def test_a_provisional_upstream_revocation_does_not_replace_or_invalidate(verdict):
    events = _base_chain()
    events.append(_decided(FREIGABE, UPSTREAM_A, verdict, reference="PI-c5-provisional"))

    view = _view(events, authority=Authority.UNAUTHENTICATED)

    assert view.provisional
    assert view.effective_decision_by_artifact[FREIGABE].verdict.value == "ACCEPT"
    assert _decision_state(view, EGRESS) == "accepted"


@pytest.mark.parametrize("verdict", ["REJECT", "WITHDRAW", "UNDO"])
def test_a_provisional_egress_revocation_does_not_replace_or_invalidate(verdict):
    events = _base_chain()
    events.append(_decided(EGRESS, OUTPUT_A, verdict, reference="PI-c5-provisional"))

    view = _view(events, authority=Authority.UNAUTHENTICATED)

    assert view.provisional
    assert EGRESS not in view.effective_decision_by_artifact
    assert _decision_state(view, EGRESS) == "accepted"
