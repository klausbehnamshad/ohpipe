#!/usr/bin/env python3
"""Mutationsprobe — die stärkere der beiden Messungen.

Abdeckung findet ungelaufene Zeilen. Sie findet keine unbewiesenen Zusagen:
Die vier Tests, die am 04.08. drei überlebende Mutanten geschlossen haben,
haben die Abdeckung um **null** Prozentpunkte bewegt. Die Zeilen waren
gemessen, das Verhalten war es nicht.

Deshalb liegt hier eine Liste benannter Mutationen mit der Erwartung, WELCHER
Test fallen muss. Das ist schärfer als „irgendein Test fällt":

* Fällt kein Test, ist die Zusage unbewiesen — der eigentliche Befund.
* Fällt ein **anderer** Test als der erwartete, sind die Tests verhakt: Einer
  von beiden prüft etwas anderes, als sein Name sagt.

**Warum das ein Skript ist und keine Handarbeit.** Bei der ersten Probe von
Hand lief eine Zeitgrenze ab, der Prozess wurde getötet, und eine Mutation
blieb im Baum stehen. Der nächste Messlauf lief gegen einen mutierten Stand,
und ein völlig gesunder Test sah aus wie ein Defekt. Genau die Klasse Fehler,
gegen die dieses Repository gebaut ist — ein Prüfer, der aus einem Grund
falsch antwortet, den niemand vermutet.

**Die erste Fassung dieses Skripts hat denselben Fehler gemacht.** Sie stellte
in ``finally`` wieder her, lief in dieselbe Zeitgrenze, bekam ``SIGTERM`` — und
``finally`` läuft bei ``SIGTERM`` nicht. K6 blieb im Baum stehen. Ein Werkzeug,
das genau den Fehler nicht verhindert, für den es geschrieben wurde, ist
schlimmer als keins: Es erzeugt Vertrauen.

Drei Vorkehrungen, gestaffelt, weil keine allein reicht:

1. ``finally`` — der Normalfall.
2. Signalhandler für ``SIGTERM``/``SIGINT`` — der Abbruchfall.
3. **Eine Eingangsprüfung gegen git.** Sie ist die einzige, die auch
   ``SIGKILL``, einen Stromausfall und einen abgestürzten Interpreter
   überlebt. Ist eine Zieldatei beim Start verändert, läuft nichts — der Lauf
   verweigert sich laut, statt gegen einen vergifteten Baum zu messen.

    python tools/mutanten.py            # alle (rund 20 s je Mutation)
    python tools/mutanten.py K3         # nur eine
"""

from __future__ import annotations

import hashlib
import difflib
import os
import re
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Mutation:
    id: str
    datei: str
    alt: str
    neu: str
    was: str
    """Was die Mutation kaputt macht — in einem Satz, für die Ausgabe."""
    faellt: tuple[str, ...] = field(default_factory=tuple)
    """Testfunktionen, die fallen MÜSSEN (ohne Parametrierungssuffix)."""
    kippt: tuple[str, ...] = field(default_factory=tuple)
    """``xfail``-Marker, die diese Mutation nach ``XPASS(strict)`` kippen DARF.

    Die zweite Hälfte von Regel 4. ``faellt`` beantwortet „fällt der gemeinte
    Test"; diese Liste beantwortet „fällt **nur** er". Leere Liste heisst: die
    Mutation darf die ``xfail``-Summe nicht bewegen.

    **Knoten-IDs, mit Parametrierungssuffix**, im Unterschied zu ``faellt``.
    Genau daran ist die Vorgängerfassung vorbeigegangen: sie zog
    parametrisierte Fälle auf den Testnamen zusammen, und sieben umgeschlagene
    Marker erschienen als ``(+3 weitere)``. Eine Zusammenfassung, die eine
    Sieben zu einer Drei macht, ist keine Zusammenfassung.
    """


MUTANTEN: tuple[Mutation, ...] = (
    Mutation(
        id="K1",
        datei="src/ohpipe/application/replay.py",
        alt="    if r.truncated:",
        neu="    if False and r.truncated:",
        was="abgeschnittener Lauf wird beim Belegbau nicht mehr abgewiesen",
        faellt=("test_a_truncated_model_receipt_is_refused_on_the_way_through_the_journal",),
    ),
    Mutation(
        id="K2",
        datei="src/ohpipe/application/replay.py",
        alt="            binding = SourceBinding.DRIFTED",
        neu="            binding = SourceBinding.BOUND",
        was="Ankerdrift wird als gebunden gemeldet",
        faellt=("test_a_non_closable_reanchor_outcome_marks_the_source_binding_as_drifted",),
    ),
    Mutation(
        id="K3",
        datei="src/ohpipe/application/replay.py",
        # Seit C2 liegt die Staleness-Zeile eine Ebene tiefer: Der Belegblock
        # fragt zuerst, OB ein Beleg vorliegt, und erst darin, ob er aufgeht.
        # Der alte Anker mit zwölf Leerzeichen traf die Zeile weiterhin — als
        # Teilzeichenkette der eingerückten. Er war damit eindeutig und
        # trotzdem falsch: Er beschrieb eine Zeile, die es nicht mehr gibt,
        # und die nächste Einrückungsänderung hätte ihn still danebentreffen
        # lassen. Anker beschreiben die Zeile, die sie meinen.
        alt="                derivation = DerivationState.STALE",
        neu="                derivation = DerivationState.CURRENT",
        was="Beleg auf alte Bytes gilt als aktuell",
        faellt=("test_regenerating_an_artifact_after_its_receipt_makes_the_derivation_stale",),
    ),
    Mutation(
        id="K4",
        datei="src/ohpipe/domain/receipt.py",
        alt='FINISH_CLEAN = frozenset({FINISH_OK, "end_turn", "eos", "stop_sequence"})',
        neu="FINISH_CLEAN = frozenset({FINISH_OK})",
        was="fremde Adapter mit eos/end_turn gelten als abgeschnitten",
        faellt=(
            "test_the_allowlist_of_clean_finish_reasons_is_exactly_this_list",
            "test_every_clean_finish_reason_passes_through_the_journal",
        ),
    ),
    Mutation(
        id="K5",
        datei="src/ohpipe/application/replay.py",
        alt="            ReanchorOutcome.UNIQUE_MOVE.value,\n",
        neu="",
        was="eindeutig verschobenes Zitat wird grundlos zum Reviewfall",
        faellt=("test_both_machine_closable_outcomes_stay_bound",),
    ),
    # -- Der Vertrag (Rotphase B1) ----------------------------------------
    #
    # Diese zwei decken einen DAUERWAECHTER ab, keinen Rotmarker. Er hat seit C2
    # Zaehne: der ArtifactContract steuert die Achsen, und V1/V2 stellen die zwei
    # Stellen nach, an denen ein Vertrag die Eigenschaft brechen koennte.
    #
    # V1 ist bewusst NICHT `if False and ...`. Diese Fassung war gemessen und
    # verworfen: Sie loescht den Verdiktpfad ganz und laesst dabei
    # test_rejection_expires_with_its_bytes XPASSen — einen fremden
    # xfail(strict) zu ADR 0027 Punkt 6. Ein Mutant, der einen unbeteiligten
    # Marker umkippt, misst nicht mehr, was er meint. Die Fassung unten ist
    # contract-getrieben: `not self.contract.decision_required` schaltet den
    # Verdiktzweig NUR fuer `decision_required=True`-Artefakte ab — genau darauf
    # faellt test_an_authenticated_verdict_is_not_overridden (es fuehrt ein
    # solches Artefakt) — und laesst ihn fuer `decision_required=False` aktiv, zu
    # denen test_rejection_expires_with_its_bytes gehoert; der fremde Marker
    # bewegt sich also nicht.
    Mutation(
        id="V1",
        datei="src/ohpipe/application/replay.py",
        alt='        if self.decided_verdict in ("REJECT", "WITHDRAW"):',
        neu='        if self.decided_verdict in ("REJECT", "WITHDRAW") '
        "and not self.contract.decision_required:",
        was="ein Vertrag MIT Entscheidungspflicht laesst einen authentifizierten "
        "Widerruf/eine Ablehnung verschwinden (Einwilligungs-Bypass, contract-getrieben)",
        faellt=("test_an_authenticated_verdict_is_not_overridden",),
    ),
    # V2 deckt eine Zusage ab, die bisher GAR KEINEN Mutanten hatte: die
    # Leiterstufe REJECTED/WITHDRAWN -> EXCLUDED. Ihr Eigentuemer
    # test_rejected_and_withdrawn_are_excluded_not_stop steht seit Serie 1 da
    # und war unbewiesen.
    Mutation(
        id="V2",
        datei="src/ohpipe/domain/state.py",
        alt="        if self.decision_state in (DecisionState.REJECTED, DecisionState.WITHDRAWN):",
        neu="        if False and self.decision_state in "
        "(DecisionState.REJECTED, DecisionState.WITHDRAWN):",
        was="die Leiterstufe, die ein Verdikt aus dem Betrieb nimmt, faellt weg",
        faellt=(
            "test_rejected_and_withdrawn_are_excluded_not_stop",
            "test_an_authenticated_verdict_is_not_overridden",
        ),
    ),
    # C2 hat die drei Achsen korrekt aus dem ArtifactContract gespeist. Zwei
    # Gegenrichtungen standen danach trotzdem ohne Zaehne da: Weder das
    # Ignorieren der Provenienzpflicht noch der Rueckfall vom uebergebenen
    # Profilgraphen auf DEFAULT_GRAPH liess die damalige 607er-Suite fallen.
    # V3/V4 sind der dauerhafte Nachweis des Nachtrags.
    Mutation(
        id="V3",
        datei="src/ohpipe/application/replay.py",
        alt="        elif self.contract.provenance_required:",
        neu="        elif False and self.contract.provenance_required:",
        was="Bytes ohne Receipt gelten trotz Provenienzpflicht als nicht zustaendig",
        faellt=(
            "test_provenance_required_without_a_receipt_stays_unverifiable_and_stops",
            "test_replay_uses_the_childlux_graph_contract_for_pii_spans",
        ),
    ),
    Mutation(
        id="V4",
        datei="src/ohpipe/application/replay.py",
        alt="                contract=graph.contract_for(name),",
        neu="                contract=DEFAULT_GRAPH.contract_for(name),",
        was="der Fold nimmt den Sandbox-Vertrag statt des uebergebenen Profilgraphen",
        faellt=("test_replay_uses_the_childlux_graph_contract_for_pii_spans",),
    ),
    # C3 setzt die READY-Erklaerung aus den tatsaechlich erfuellten Achsen
    # zusammen. V5-V9 decken den historischen Rueckfall, jede Achsenbedingung
    # und den sonst unsichtbaren Leerfall einzeln ab.
    Mutation(
        id="V5",
        datei="src/ohpipe/domain/state.py",
        alt="            teile: list[str] = []",
        neu=(
            '            return "aktuell gebunden, Eingaben unverändert, '
            'von einem Menschen verantwortet"'
        ),
        was="READY faellt auf den historischen festen Dreifachsatz zurueck",
        faellt=(
            "test_ready_explanation_is_composed_from_exactly_the_applicable_axes",
            "test_ready_explanation_omits_inputs_when_derivation_not_applicable",
        ),
        kippt=(),
    ),
    Mutation(
        id="V6",
        datei="src/ohpipe/domain/state.py",
        alt="            if self.source_binding is SourceBinding.BOUND:",
        neu="            if False and self.source_binding is SourceBinding.BOUND:",
        was="der Bindungsbestandteil fehlt trotz aktueller Bindung",
        faellt=(
            "test_ready_explanation_is_composed_from_exactly_the_applicable_axes",
            "test_ready_explanation_omits_inputs_when_derivation_not_applicable",
        ),
        kippt=(),
    ),
    Mutation(
        id="V7",
        datei="src/ohpipe/domain/state.py",
        alt="            if self.derivation_state is DerivationState.CURRENT:",
        neu="            if False and self.derivation_state is DerivationState.CURRENT:",
        was="der Ableitungsbestandteil fehlt trotz aktuellem Beleg",
        faellt=(
            "test_ready_explanation_is_composed_from_exactly_the_applicable_axes",
            "test_ready_explanation_names_inputs_when_derivation_is_current",
        ),
        kippt=(),
    ),
    Mutation(
        id="V8",
        datei="src/ohpipe/domain/state.py",
        alt="            if self.decision_state is DecisionState.ACCEPTED:",
        neu="            if False and self.decision_state is DecisionState.ACCEPTED:",
        was="der Entscheidungsbestandteil fehlt trotz menschlicher Annahme",
        faellt=(
            "test_ready_explanation_is_composed_from_exactly_the_applicable_axes",
            "test_ready_explanation_omits_inputs_when_derivation_not_applicable",
        ),
        kippt=(),
    ),
    Mutation(
        id="V9",
        datei="src/ohpipe/domain/state.py",
        alt="            if not teile:",
        neu="            if False and not teile:",
        was="dreimal NOT_APPLICABLE ergibt READY mit leerer Erklaerung",
        faellt=("test_ready_explanation_is_composed_from_exactly_the_applicable_axes",),
        kippt=(),
    ),
    # E13 deckt die Zusage aus ADR 0027 Punkt 10 ab: ein Name, den kein
    # Schritt erzeugt, bekommt keine Zeile. Ohne diesen Mutanten waeren die
    # vier gruenen Zusicherungen in test_graph_membership_red.py eine
    # Behauptung — sie sind seit dieser Serie gruen, und Grun beweist nichts.
    Mutation(
        id="E13",
        datei="src/ohpipe/application/replay.py",
        alt="        if name not in erzeugbar:",
        neu="        if False and name not in erzeugbar:",
        was="die Graphzugehoerigkeit wird nicht mehr geprueft — jeder erfundene "
        "Name bekommt wieder eine Zeile in der Zustandstabelle",
        faellt=("test_an_event_on_a_name_no_step_produces_gets_no_row",),
    ),
    Mutation(
        id="K6",
        datei="src/ohpipe/application/replay.py",
        alt="            if outcome not in VALID_OUTCOMES:",
        neu="            if False and outcome not in VALID_OUTCOMES:",
        was="erfundenes Ankerergebnis färbt rot, ohne die Ursache zu nennen",
        faellt=("test_an_unknown_anchor_outcome_says_so_instead_of_quietly_drifting",),
    ),
    # -- Der Schreibpfad ---------------------------------------------------
    #
    # Klaus' Sonde für Block 2, wörtlich: je Ereignisart ein Pflichtfeld aus
    # der Allowlist entfernen und prüfen, dass genau ein benannter Test fällt.
    # E1 ist die allgemeine Fassung — sie schaltet die Pflichtfeldprüfung
    # komplett ab und muss den parametrierten Test über ALLE Arten fällen.
    Mutation(
        id="E1",
        datei="src/ohpipe/domain/events.py",
        alt="    fehlend = sorted(spec.pflicht - schluessel)",
        neu="    fehlend = []",
        was="Pflichtfelder werden nicht mehr geprüft",
        faellt=("test_every_kind_refuses_a_payload_that_is_missing_one_required_field",),
    ),
    Mutation(
        id="E2",
        datei="src/ohpipe/domain/events.py",
        alt="    fremd = sorted(schluessel - spec.erlaubt)",
        neu="    fremd = []",
        was="unbekannte Felder wandern still ins append-only Journal",
        faellt=("test_an_unremarkable_unknown_field_is_refused_too",),
        # Seit C5 sind die sieben input_refs-Marker gruen. E2 bewegt deshalb
        # keinen Marker mehr; die Werkzeugzusage fuer deklarierte Kippungen
        # bleibt mit einem synthetischen Mutanten separat getestet.
        kippt=(),
    ),
    # -- Scheibe C5: input_refs -------------------------------------------
    Mutation(
        id="E14",
        datei="src/ohpipe/domain/events.py",
        alt="        if not isinstance(refs, dict) or not refs:",
        neu="        if False and (not isinstance(refs, dict) or not refs):",
        was="input_refs akzeptiert leere oder nicht objektfoermige Werte",
        faellt=("test_input_refs_is_refused_for_its_content_not_its_name",),
    ),
    Mutation(
        id="E15",
        datei="src/ohpipe/domain/events.py",
        alt="            if rolle not in erlaubte_rollen:",
        neu="            if False and rolle not in erlaubte_rollen:",
        was="eine nicht deklarierte input_refs-Rolle wird akzeptiert",
        faellt=(
            "test_input_refs_refuses_an_unknown_role_for_the_role_not_the_field",
            "test_an_unknown_input_ref_role_is_not_echoed",
        ),
    ),
    Mutation(
        id="E16",
        datei="src/ohpipe/domain/events.py",
        alt="            if not SHA256_RE.fullmatch(wert):",
        neu="            if False and not SHA256_RE.fullmatch(wert):",
        was="input_refs-Werte muessen das sha256-Format nicht mehr erfuellen",
        faellt=("test_input_refs_is_refused_for_its_content_not_its_name",),
    ),
    Mutation(
        id="E17",
        datei="src/ohpipe/domain/events.py",
        alt='            "note record_id input_refs",',
        neu='            "note record_id",',
        was="input_refs faellt aus der optionalen Nutzlast von decision.recorded",
        faellt=("test_a_decision_may_carry_input_refs",),
    ),
    Mutation(
        id="E18",
        datei="src/ohpipe/domain/events.py",
        alt="            if not isinstance(wert, str):",
        neu="            if False and not isinstance(wert, str):",
        was="ein nur zu sha256 stringifizierbarer Nicht-String gilt als Eingabebezug",
        faellt=("test_a_stringifiable_non_string_is_not_an_input_ref_hash",),
    ),
    Mutation(
        id="E3",
        datei="src/ohpipe/domain/events.py",
        alt="    verdaechtig = sorted(schluessel & KLARTEXTVERDACHT)",
        neu="    verdaechtig = []",
        was="der Klartextverdacht wird nicht mehr benannt",
        faellt=("test_fields_that_typically_carry_a_surface_form_are_refused_by_name",),
    ),
    Mutation(
        id="E4",
        datei="src/ohpipe/domain/events.py",
        alt="    if innen is not None and record_id is not None and innen != record_id:",
        neu="    if False:",
        was="Hülle und Nutzlast dürfen verschiedene Records nennen",
        faellt=("test_a_record_id_in_the_payload_must_agree_with_the_envelope",),
    ),
    Mutation(
        id="E5",
        datei="src/ohpipe/application/ingest.py",
        alt="    ledger.require_write(rid)",
        neu="    pass",
        was="die Schreibwache steht nicht mehr — der Kern von Block 2",
        faellt=("test_ingest_refuses_a_record_that_belongs_to_the_legacy_system",),
    ),
    # Der frühere E6 mutierte den Bytegleichheits-Vergleich in `ingest` und
    # ÜBERLEBTE: Der Cue-Parser lehnt schon beim Parsen ab, was er nicht
    # verlustfrei wiedergeben kann. Klaus' Einwand dazu war richtig — ein
    # Stolperdraht, den kein Test auslösen kann, ist auch unsichtbar, wenn er
    # reisst. Er steht jetzt als E11 wieder in der Liste, gepinnt von einem
    # Test, der den unerreichbaren Zustand am Parser vorbei konstruiert.
    Mutation(
        id="E6",
        datei="src/ohpipe/application/ingest.py",
        alt="    if suffix not in FORMATE:",
        neu="    if False:",
        was="das Format wird aus dem Inhalt geraten statt an der Endung erkannt",
        faellt=("test_ingest_does_not_guess_the_format_from_content",),
    ),
    Mutation(
        id="E8",
        datei="src/ohpipe/project.py",
        alt="        return ContentStore(self.root)",
        neu="        return ContentStore(self.root / 'objects')",
        was="P0 aus Runde 8 — ingest schreibt nach objects/objects/",
        faellt=("test_ingest_and_doctor_use_the_same_store",),
    ),
    Mutation(
        id="E9",
        datei="src/ohpipe/application/ingest.py",
        # Die alte Fassung mutierte den Listenausdruck, der die Duplikate VOR
        # dem Anhaengen suchte. Genau der ist bei der Reparatur des
        # Nebenlaeufigkeitsbefunds gestorben — und damit stand die Zusage
        # "sequenziell idempotent" ohne Mutationsdeckung da, waehrend die
        # Liste weiter siebzehn fallende Mutanten behauptete. Eine Reparatur
        # kann einer aelteren Zusage die Deckung nehmen; wer den Code aendert,
        # aendert auch die Pruefer, die darauf zeigen.
        alt='        duplikat=lambda e: e.payload.get("sha256") == address,',
        neu="        duplikat=lambda e: False,",
        was="derselbe Befehl zweimal erzeugt zwei source.ingested",
        faellt=(
            "test_ingesting_the_same_bytes_twice_appends_nothing",
            "test_concurrent_ingest_of_the_same_bytes_writes_exactly_once",
        ),
    ),
    Mutation(
        id="E10",
        datei="src/ohpipe/project.py",
        alt="        if legacy == THIS_RUNTIME:",
        neu="        if False:",
        was="ein Produktionsprofil darf sich selbst zum Alt-Runtime erklären",
        faellt=("test_legacy_runtime_is_treated_like_the_other_two_safety_switches",),
    ),
    Mutation(
        id="E11",
        datei="src/ohpipe/application/ingest.py",
        alt="    if dok.render_bytes() != roh:",
        neu="    if False:",
        was="der Verlustfreiheits-Stolperdraht reisst unbemerkt",
        faellt=("test_the_lossless_tripwire_still_fires_when_it_is_reached",),
    ),
    Mutation(
        id="E12",
        datei="src/ohpipe/journal.py",
        # Die neue Zusage aus der Reparatur: Pruefung UND Anhaengen liegen in
        # DERSELBEN Sperre. Sie hatte bisher gar keine Mutation — die alte E9
        # deckte den Vorgaengerzustand, die neue Zusage nichts. Diese Mutation
        # hebt den Scan wieder aus der Sperre und stellt damit exakt den
        # Zustand her, der acht gleichzeitige Aufrufe acht Mal schreiben liess.
        alt="""        with self._exclusive():
            for e in self:
                if e.kind != kind or e.record_id != record_id:
                    continue
                if duplikat is None or duplikat(e):
                    return None
            return self._append_locked(kind, payload, record_id=record_id)""",
        neu="""        for e in self:
            if e.kind != kind or e.record_id != record_id:
                continue
            if duplikat is None or duplikat(e):
                return None
        with self._exclusive():
            return self._append_locked(kind, payload, record_id=record_id)""",
        was="Pruefung und Anhaengen liegen wieder auf verschiedenen Seiten der Sperre",
        faellt=("test_concurrent_ingest_of_the_same_bytes_writes_exactly_once",),
    ),
    Mutation(
        id="E7",
        datei="src/ohpipe/journal.py",
        alt="        if self._kopf is not None and groesse == self._groesse_nach_schreiben:",
        neu="        if self._kopf is not None:",
        was="der gemerkte Kopf wird nicht verworfen, wenn jemand anders anhängt",
        faellt=("test_the_cached_head_is_dropped_when_someone_else_appended",),
    ),
    # -- E8: journalexterne Graphbindung ---------------------------------
    # F1-F7 decken die fünf ausführbaren Zusagen der E8-Serie und die beiden
    # realen Paketbefunde: Anlegeakt und
    # Speicherort, benannter Vergleich, ausdrücklicher Upgradeakt und die
    # eigene Behandlung eines vor E8 entstandenen Journals. Der Literal-Pin
    # ist absichtlich ein Testwert und keine zweite Produktkonstante.
    Mutation(
        id="F1",
        datei="src/ohpipe/project.py",
        alt='        return self.governance / "graph-contract.json"',
        neu='        return self.governance / "graph-binding.json"',
        was="die E8-Bindung driftet auf einen nicht vereinbarten Speicherpfad",
        faellt=("test_init_pins_the_literal_graph_outside_the_journal",),
    ),
    Mutation(
        id="F2",
        datei="src/ohpipe/project.py",
        alt="        if binding.profile != self.profile.id or binding.graph_sha256 != running:",
        neu="        if False:",
        was="ein abweichender gebundener Graph gilt als CURRENT",
        faellt=("test_a_mismatch_is_named_and_never_silently_rebound",),
    ),
    Mutation(
        id="F3",
        datei="src/ohpipe/cli/main.py",
        alt="    if args.target != running:",
        neu="    if False:",
        was="graph-upgrade ignoriert den vom Menschen bestätigten Zielhash",
        faellt=("test_the_upgrade_rejects_an_unconfirmed_value_without_change",),
    ),
    Mutation(
        id="F4",
        datei="src/ohpipe/project.py",
        alt="            return GraphBindingState.UNBOUND, None, running",
        neu="            return GraphBindingState.CURRENT, None, running",
        was="ein vor E8 entstandenes Journal ohne Bindung läuft als CURRENT durch",
        faellt=("test_a_pre_e8_journal_has_a_named_unbound_state",),
    ),
    Mutation(
        id="F5",
        datei="src/ohpipe/project.py",
        alt='            "profile": self.profile.id,',
        neu='            "profile": "sandbox",',
        was="jede Graphbindung behauptet das Sandbox-Profil",
        faellt=("test_childlux_init_binds_its_own_profile_and_literal",),
    ),
    Mutation(
        id="F6",
        datei="src/ohpipe/cli/main.py",
        alt="        path.lstat()",
        neu="        if not path.exists():\n            raise FileNotFoundError(path)",
        was="ein gebrochener Graphbindungs-Link gilt wieder als fehlender Eintrag",
        faellt=("test_a_dangling_binding_is_a_safety_stop_for_doctor_and_status",),
    ),
    Mutation(
        id="F7",
        datei="src/ohpipe/cli/main.py",
        alt=(
            '    next_command = _e8_operator_command(ws, profile_arg, "graph-upgrade", '
            '"--to", running)'
        ),
        neu=(
            '    next_command = shlex.join(["ohpipe", "--profile", profile_arg, '
            '"graph-upgrade", "--to", running])'
        ),
        was="das zustandsändernde Upgrade-NEXT verliert seine explizite Datenwurzel",
        faellt=("test_the_emitted_upgrade_next_changes_only_its_explicit_root",),
    ),
    # -- Scheibe C4: usable / have (E4) -----------------------------------
    # Jeder neu eingefuehrte semantische Conditional in `usable`/`have` bekommt
    # einen gezielten Mutanten samt fallendem GRUENEN Waechter. V10/V11/V13/V14
    # teilen den usable-Return als `alt`, V12 die have-Comprehension; jede
    # Mutation laeuft einzeln gegen frischen HEAD. Alle `kippt=()`: der C4-Marker
    # ist seit C4 gruen und faellt regulaer, kein xfail-Marker bewegt sich.
    Mutation(
        id="V10",
        datei="src/ohpipe/application/replay.py",
        alt="        return self.sha256 is not None and self.state(enabled).status is Status.READY",
        neu="        return self.state(enabled).status is Status.READY",
        was="die Byteklausel faellt weg — ein Status-READY ohne Bytes gilt als nutzbar",
        faellt=("test_bytes_are_a_separate_clause_from_status",),
    ),
    Mutation(
        id="V11",
        datei="src/ohpipe/application/replay.py",
        alt="        return self.sha256 is not None and self.state(enabled).status is Status.READY",
        neu="        return self.sha256 is not None "
        "and self.state(enabled).status is not Status.EXCLUDED",
        was="usable prueft nur noch NICHT-EXCLUDED — jeder Nicht-READY-Zustand gilt als nutzbar",
        faellt=("test_a_non_ready_artifact_is_not_usable",),
    ),
    Mutation(
        id="V12",
        datei="src/ohpipe/application/replay.py",
        alt="        return {name for name, facts in self.facts.items() if facts.usable(self.enabled)}",
        neu="        return {name for name, facts in self.facts.items() if facts.usable()}",
        was="have reicht enabled nicht durch — ein deaktivierter Record gilt als nutzbar",
        faellt=("test_a_disabled_record_yields_an_empty_have",),
    ),
    Mutation(
        id="V13",
        datei="src/ohpipe/application/replay.py",
        alt="        return self.sha256 is not None and self.state(enabled).status is Status.READY",
        neu="        return self.sha256 is not None and self.state(enabled).status is Status.READY "
        "and self.state(enabled).source_binding is SourceBinding.BOUND",
        was="usable verengt ueber die Bindungsachse — ein all-N/A-Artefakt gilt als nicht nutzbar",
        faellt=("test_a_contract_free_artifact_with_bytes_is_usable",),
    ),
    Mutation(
        id="V14",
        datei="src/ohpipe/application/replay.py",
        alt="        return self.sha256 is not None and self.state(enabled).status is Status.READY",
        neu="        return self.sha256 is not None",
        was="usable faellt auf reine Bytepraesenz zurueck — ein ausgeschlossenes Artefakt gilt als nutzbar",
        faellt=(
            "test_an_excluded_artifact_with_bytes_leaves_have",
            "test_a_non_ready_artifact_is_not_usable",
        ),
    ),
    # -- Scheibe C5: geerbte Egressentscheidung --------------------------
    Mutation(
        id="V15",
        datei="src/ohpipe/application/replay.py",
        alt="    if facts.receipt_for != facts.sha256:",
        neu="    if False and facts.receipt_for != facts.sha256:",
        was="ein Receipt fuer andere Egressbytes vererbt die Entscheidung",
        faellt=("test_a_receipt_for_other_output_bytes_does_not_inherit",),
    ),
    Mutation(
        id="V16",
        datei="src/ohpipe/application/replay.py",
        alt="    if set(facts.receipt_inputs) != upstream_needed:",
        neu="    if not upstream_needed.issubset(set(facts.receipt_inputs)):",
        was="die Receipt-Inputmenge darf zusaetzliche Rollen enthalten",
        faellt=("test_a_receipt_with_the_wrong_input_key_set_does_not_inherit",),
    ),
    Mutation(
        id="V17",
        datei="src/ohpipe/application/replay.py",
        alt=(
            "    if upstream_facts is None or facts.receipt_inputs.get(upstream) "
            "!= upstream_facts.sha256:"
        ),
        neu="    if upstream_facts is None:",
        was="der Receipt-Inputhash muss nicht zu den aktuellen Upstreambytes passen",
        faellt=("test_a_receipt_for_old_upstream_bytes_does_not_inherit",),
    ),
    Mutation(
        id="V18",
        datei="src/ohpipe/application/replay.py",
        alt="    if effective.subject_sha256 != upstream_facts.sha256:",
        neu="    if False and effective.subject_sha256 != upstream_facts.sha256:",
        was="das wirksame ACCEPT darf sich auf alte Upstreambytes beziehen",
        faellt=("test_an_accept_for_old_upstream_bytes_does_not_inherit",),
    ),
    Mutation(
        id="V19",
        datei="src/ohpipe/application/replay.py",
        alt="        elif self.inherited_decision is not None:",
        neu="        elif False and self.inherited_decision is not None:",
        was="die gebundene geerbte Entscheidung wird in der Achse ignoriert",
        faellt=(
            "test_an_exact_earlier_release_chain_inherits_the_egress_decision",
            "test_the_analysis_bundle_inherits_by_the_same_rule",
        ),
    ),
    Mutation(
        id="V20",
        datei="src/ohpipe/application/replay.py",
        alt="            and not self.is_egress",
        neu="            and True",
        was="ein direktes ACCEPT erfuellt auch auf Egress die Entscheidungsachse",
        faellt=("test_a_direct_accept_on_the_egress_artifact_does_not_satisfy_the_contract",),
    ),
    Mutation(
        id="V21",
        datei="src/ohpipe/application/replay.py",
        alt="        if (facts.is_egress and facts.name == changed_artifact) or (",
        neu="        if False or (",
        was="neue Egressbytes lassen die geerbte Evidenz stehen",
        faellt=("test_new_egress_bytes_invalidate_inherited_evidence",),
    ),
    Mutation(
        id="V22",
        datei="src/ohpipe/application/replay.py",
        alt="            evidence is not None and evidence.upstream_artifact == changed_artifact",
        neu="            False",
        was="neue Upstreambytes lassen die geerbte Evidenz stehen",
        faellt=("test_new_upstream_bytes_invalidate_inherited_evidence",),
    ),
    Mutation(
        id="V23",
        datei="src/ohpipe/application/replay.py",
        alt="    effective = view.effective_decision_by_artifact.get(upstream)",
        neu=("    effective = next(iter(view.effective_decision_by_artifact.values()), None)"),
        was="der aktuelle Zustand wird nicht artefaktgebunden aus der Map gelesen",
        faellt=("test_an_accept_for_a_different_upstream_artifact_does_not_inherit",),
    ),
    Mutation(
        id="V24",
        datei="src/ohpipe/application/replay.py",
        alt="    effective = view.effective_decision_by_artifact.get(upstream)",
        neu="    effective = next(reversed(view.decisions.values()), None)",
        was="der ID-Index ersetzt die journalisierte aktuelle Entscheidung je Artefakt",
        faellt=("test_the_latest_journalled_upstream_decision_wins_across_reused_reference_ids",),
    ),
    Mutation(
        id="V25",
        datei="src/ohpipe/application/replay.py",
        alt="        if evidence is not None and evidence.upstream_artifact == artifact:",
        neu="        if False:",
        was="ein wirksames spaeteres Upstream-Nicht-ACCEPT invalidiert die Evidenz nicht",
        faellt=("test_an_authorised_later_upstream_revocation_invalidates_without_revival",),
    ),
    Mutation(
        id="V26",
        datei="src/ohpipe/application/replay.py",
        alt="        if facts.is_egress and facts.name == artifact:",
        neu="        if False:",
        was="ein wirksames direktes Egress-Nicht-ACCEPT invalidiert die Evidenz nicht",
        faellt=("test_an_authorised_later_egress_revocation_invalidates_without_revival",),
    ),
    Mutation(
        id="V27",
        datei="src/ohpipe/application/replay.py",
        alt=(
            "    return {artifact for step in graph if step.leaves_system "
            "for artifact in step.produces}"
        ),
        neu=(
            "    return {artifact for step in graph for artifact in step.produces "
            "if graph.contract_for(artifact).provenance_required and "
            "graph.contract_for(artifact).decision_required}"
        ),
        was="Egress wird aus provenance_required und decision_required abgeleitet",
        faellt=("test_an_internal_provenance_and_decision_artifact_is_not_egress",),
    ),
    Mutation(
        id="V28",
        datei="src/ohpipe/application/replay.py",
        alt=(
            "    return {artifact for step in graph if step.leaves_system "
            "for artifact in step.produces}"
        ),
        neu='    return {"export.bundle", "analysis.bundle"}',
        was="Egress ist auf die zwei heutigen Artefaktnamen fest verdrahtet",
        faellt=("test_a_custom_named_leaves_system_artifact_is_egress_in_the_passed_graph",),
    ),
    Mutation(
        id="V29",
        datei="src/ohpipe/application/replay.py",
        alt="    egress_made = _egress_artifacts(graph)",
        neu="    egress_made = _egress_artifacts(DEFAULT_GRAPH)",
        was="die Egressrolle stammt aus DEFAULT_GRAPH statt aus dem Laufgraphen",
        faellt=("test_a_custom_named_leaves_system_artifact_is_egress_in_the_passed_graph",),
    ),
    Mutation(
        id="V30",
        datei="src/ohpipe/application/replay.py",
        alt=(
            "            if not authority.may_confer_exclusion and d.verdict is not Verdict.ACCEPT:"
        ),
        neu=(
            "            if False and not authority.may_confer_exclusion "
            "and d.verdict is not Verdict.ACCEPT:"
        ),
        was="provisorische Nicht-ACCEPT-Entscheidungen umgehen das gemeinsame Autoritaetsgate",
        faellt=(
            "test_a_provisional_upstream_revocation_does_not_replace_or_invalidate",
            "test_a_provisional_egress_revocation_does_not_replace_or_invalidate",
        ),
    ),
    # -- Scheibe B1: ArtifactKey ------------------------------------------
    #
    # Drei Zusagen der B1-Grenze, jede mit eigenem Mutanten. Die Grenze nennt
    # sie in den Punkten 1 bis 4; ein Satz in einer Grenze, den kein Mutant
    # angreift, ist eine Behauptung.
    #
    # ZUR REICHWEITE DES WERKZEUGS an dieser Datei: `src/ohpipe/domain/
    # artifact_key.py` ist im Baum der B1-Rotphase noch NICHT eingecheckt.
    # `git diff --name-only HEAD --` meldet fuer eine unverfolgte Datei
    # nichts — weder unveraendert noch mutiert (gemessen: 0 Zeilen in beiden
    # Faellen). Die Eingangspruefung (Stufe 3) und die Gegenprobe "genau eine
    # Datei mutiert" sind fuer diese Datei damit wirkungslos, solange sie
    # unverfolgt ist; die Gegenprobe liest die leere Menge sogar als "kein
    # git" und ueberspringt. Es tragen: `finally`, der Signalhandler und die
    # inhaltsbasierte Schlusspruefung `stehen`, die ueber sha256 laeuft und
    # von git unabhaengig ist. Mit dem B1-Checkpoint faellt diese Einschraenkung
    # weg.
    Mutation(
        id="S1",
        datei="src/ohpipe/domain/artifact_key.py",
        alt="        raise InvalidArtifactKey(_KEIN_MASSSTAB)",
        neu="        return",
        was="ein nichtleerer instance_id wird geschrieben, obwohl kein normativer "
        "Formatmassstab hinterlegt ist (Grenze Punkt 3)",
        faellt=(
            "test_nichtleerer_instance_id_bleibt_bis_zum_formatmassstab_gesperrt",
            "test_die_zurueckweisung_behauptet_keine_formatpruefung",
            "test_unit_id_ist_kein_sonderfall",
        ),
    ),
    Mutation(
        id="S2",
        datei="src/ohpipe/domain/artifact_key.py",
        alt='        if self.instance_id == "":\n'
        "            raise InvalidArtifactKey(_LEERE_ZEICHENKETTE)",
        neu='        if self.instance_id == "":\n            return',
        was="die leere Zeichenkette wird als Singletondarstellung durchgelassen (Grenze Punkt 2)",
        faellt=(
            "test_leere_zeichenkette_ist_keine_singletondarstellung",
            "test_die_zwei_zurueckweisungen_nennen_verschiedene_ursachen",
        ),
    ),
    Mutation(
        id="S3",
        datei="src/ohpipe/domain/artifact_key.py",
        alt="        fehlend = [feld for feld in cls.FIELDS if feld not in data]",
        neu="        fehlend: list[str] = []",
        was="ein abwesendes Feld wird nicht mehr als abwesend benannt und faellt "
        "als KeyError statt als InvalidArtifactKey (Grenze Punkt 1)",
        faellt=(
            "test_ein_fehlendes_feld_ist_nicht_der_volle_schluessel",
            "test_abwesend_und_null_sind_verschiedene_faelle",
        ),
    ),
    # --- P1: Schritt-Registry und continue -------------------------------
    Mutation(
        id="R1",
        datei="src/ohpipe/application/steps.py",
        alt="        if missing:",
        neu="        if False and missing:",
        was="ein Handler, der behauptet und nicht belegt, laeuft als Erfolg weiter",
        faellt=("test_a_handler_that_claims_without_evidence_is_a_stop",),
    ),
    Mutation(
        id="R2",
        datei="src/ohpipe/application/steps.py",
        alt='                and (s.cost == "cheap" or ctx.confirm)',
        neu="                and True",
        was="teure Schritte laufen ohne ausdrueckliche Bestaetigung",
        faellt=(
            "test_a_fresh_record_reaches_the_model_step_without_a_single_finding",
            "test_after_a_confirmed_transcript_continue_asks_before_the_model_step",
            "test_continue_runs_the_cheap_handler_and_waits_before_the_costly_one",
            "test_the_next_after_a_deferred_model_step_runs_as_it_stands",
        ),
    ),
    Mutation(
        id="R3",
        datei="src/ohpipe/application/steps.py",
        alt="        if set(h.produces) != set(step.produces):",
        neu="        if False:",
        was="ein Handler darf etwas anderes erzeugen als sein Schritt",
        faellt=("test_the_registry_checker_flags_forged_handlers",),
    ),
    Mutation(
        id="R4",
        datei="src/ohpipe/application/steps.py",
        alt="        gates=tuple(s for s in pending if s.human_gate),",
        neu="        gates=graph.plan(view.have).gates,",
        was="continue meldet Halte, die erst hinter einem noch fehlenden Schritt liegen",
        faellt=(
            "test_a_fresh_record_reaches_the_model_step_without_a_single_finding",
            "test_after_a_confirmed_transcript_continue_asks_before_the_model_step",
            "test_an_input_step_carries_a_check_and_no_next",
            "test_an_unbuilt_step_is_named_and_never_recommended",
            "test_and_then_the_model_step_runs_and_the_chain_stands_before_coverage",
            "test_continue_runs_the_cheap_handler_and_waits_before_the_costly_one",
            "test_continue_runs_the_model_step_and_halts_before_coverage",
            "test_over_the_cli_the_clean_run_carries_the_chain_to_coverage",
            "test_the_next_after_a_deferred_model_step_runs_as_it_stands",
        ),
    ),
    # --- P2: l1.suggest und der aufgezeichnete Adapter --------------------
    Mutation(
        id="R5",
        datei="src/ohpipe/application/l1_suggest.py",
        alt="    probe.validate(decision)\n",
        neu="    pass\n",
        was="der Beleg wird erst nach dem Lesen der Antwort geprueft; ein abgeschnittener "
        "Lauf faellt als Parsefehler statt als Vertragsbruch",
        faellt=(
            "test_a_truncated_run_leaves_no_byte_behind",
            "test_continue_reports_the_truncated_run_as_a_stop_with_the_contract_wording",
            "test_demo_moment_3_over_the_cli_the_run_fails_and_writes_nothing",
        ),
    ),
    Mutation(
        id="R6",
        datei="src/ohpipe/application/l1_suggest.py",
        alt="        if hits != 1:",
        neu="        if hits == 0:",
        was="ein mehrdeutiges Zitat bekommt einen Anker auf den ersten Treffer",
        faellt=("test_a_quote_that_is_not_unique_in_its_segment_fails_the_whole_run",),
    ),
    Mutation(
        id="R7",
        datei="src/ohpipe/application/l1_suggest.py",
        alt="    if GATE_ARTIFACT not in view.have or decision is None or not decision.is_accepting:",
        neu="    if False:",
        was="der Modellschritt laeuft ohne bestaetigtes Transkript los",
        faellt=("test_without_a_confirmed_transcript_the_adapter_is_never_called",),
    ),
    Mutation(
        id="R8",
        datei="src/ohpipe/adapters/models/fixture.py",
        alt="        return ModelResponse(text, FINISH_LENGTH, int(params.num_predict or 0), digest)",
        neu="        return ModelResponse(text, FINISH_OK, int(params.num_predict or 0), digest)",
        was="die Aufzeichnung meldet einen abgeschnittenen Lauf als sauber beendet",
        faellt=(
            "test_a_truncated_run_leaves_no_byte_behind",
            "test_continue_reports_the_truncated_run_as_a_stop_with_the_contract_wording",
            "test_demo_moment_3_over_the_cli_the_run_fails_and_writes_nothing",
            "test_the_length_fixture_ends_with_length_and_a_cut_document",
        ),
    ),
    # --- L1 bis L4: die vier Luecken vor Demo-Moment 1 -------------------
    Mutation(
        id="R9",
        datei="src/ohpipe/application/ingest.py",
        alt='        "artifact": "transcript.revision",\n'
        '        "output_sha256": plan.revision_sha256,',
        neu='        "artifact": "transcript.segment_projection",\n'
        '        "output_sha256": plan.revision_sha256,',
        was="der Projektionsbeleg traegt wieder einen Namen, den kein Graphschritt erzeugt",
        faellt=(
            "test_a_fresh_record_reaches_the_model_step_without_a_single_finding",
            "test_all_three_b3b_receipts_carry_the_graph_name_and_keep_their_kind",
            "test_and_then_the_model_step_runs_and_the_chain_stands_before_coverage",
            "test_the_declared_srt_input_lies_in_the_store",
        ),
    ),
    Mutation(
        id="R10",
        datei="src/ohpipe/application/fulltext.py",
        alt='        "output_sha256": plan.revision_sha256,\n'
        '        "inputs": {\n'
        '            "source": plan.source_sha256,',
        neu='        "output_sha256": plan.source_sha256,\n'
        '        "inputs": {\n'
        '            "source": plan.source_sha256,',
        was="der getrennte Volltextbeleg gibt wieder die Quelle als Ausgabe aus und "
        "entwertet damit die Fassung",
        faellt=("test_the_separate_fulltext_receipt_does_not_devalue_the_revision",),
    ),
    Mutation(
        id="R11",
        datei="src/ohpipe/application/confirmation.py",
        alt="    _anchor_confirmed(journal, plan.marker.record_id)\n    return b3b_report(",
        neu="    return b3b_report(",
        was="die Bestaetigung schreibt keine Bindungsevidenz; die Bindungsachse bleibt UNKNOWN",
        faellt=(
            "test_a_fresh_record_reaches_the_model_step_without_a_single_finding",
            "test_a_repeated_confirm_restores_a_missing_binding_evidence",
            "test_and_then_the_model_step_runs_and_the_chain_stands_before_coverage",
            "test_confirm_writes_the_binding_evidence_and_makes_the_gate_ready",
            "test_the_null_run_repairs_the_binding_evidence_too",
        ),
    ),
    Mutation(
        id="R12",
        datei="src/ohpipe/cli/main.py",
        alt='            and event.payload.get("output_sha256") == assignment.sha256',
        neu="            and True",
        was="der Ingest glaubt dem Journal, statt die Sprachzuordnung nachzurechnen",
        faellt=("test_ingest_recomputes_the_assignment_and_refuses_an_unattested_one",),
    ),
    Mutation(
        id="R13",
        datei="src/ohpipe/application/ingest.py",
        alt="        pre_intent_objects=(\n            plan.assignment.draft.raw_bytes,\n",
        neu="        pre_intent_objects=(\n",
        was="die als Eingabe deklarierten SRT-Bytes werden nicht abgelegt; der Beleg "
        "zeigt ins Leere",
        faellt=(
            "test_a_fresh_record_reaches_the_model_step_without_a_single_finding",
            "test_and_then_the_model_step_runs_and_the_chain_stands_before_coverage",
            "test_the_declared_srt_input_lies_in_the_store",
        ),
    ),
    # R14 und R15 zielen nicht auf Produktcode, sondern auf die ausgelieferten
    # Beispieldaten. Das ist Absicht: der Durchstich brach nicht an einer
    # Funktion, sondern an einer Datei — die Kette lief im Autorenfenster gegen
    # eine eingebaute SRT-Konstante und auf dem Rechner des Vorfuehrenden gegen
    # examples/synthetic/SANDBOX-001.srt. Ein Mutant, der nur src trifft, kann
    # diesen Ausfall nicht nachstellen.
    Mutation(
        id="R14",
        datei="examples/synthetic/SANDBOX-001.srt",
        alt="ZEITZEUGIN: D'Iesse war knapp",
        neu="D'Iesse war knapp",
        was="einer Cue der ausgelieferten Beispieldatei fehlt der Sprecher — genau der "
        "Abbruch, den das Autorenfenster nicht sah",
        faellt=(
            "test_the_shipped_example_carries_a_speaker_on_every_cue",
            "test_the_shipped_example_stays_multilingual",
            "test_the_shipped_example_runs_the_whole_chain_through_the_cli",
            "test_the_shipped_example_is_not_touched_by_the_chain",
            "test_the_demo_script_itself_runs_green",
        ),
    ),
    Mutation(
        id="R15",
        datei="examples/synthetic/durchstich.sh",
        alt='split("deu deu ltz fra deu", s, " ")',
        neu='split("deu deu deu deu deu", s, " ")',
        was="das Vorfuehrskript deutscht das Beispiel ein; die Kette liefe gruen und "
        "bewiese nichts ueber den ISO-639-3-Wortschatz",
        faellt=("test_the_demo_script_itself_runs_green",),
    ),
    # R16 und R17 zielen auf den Ausgang. Beide Mutationen sehen harmlos aus:
    # eine zusaetzliche WAHRE Eingabe im Beleg, und eine weggelassene
    # Bindungsevidenz. Genau daran haengt aber, ob export.bundle die Freigabe
    # erben darf — ein Ausgang, der still aufhoert zu erben, faellt sonst
    # nirgends auf, weil er weiter Bytes schreibt.
    Mutation(
        id="R16",
        datei="src/ohpipe/application/export.py",
        alt="        inputs={UPSTREAM: upstream_sha},",
        neu='        inputs={UPSTREAM: upstream_sha, "release.preview": upstream_sha},',
        was="der Ausgangsbeleg nennt eine zusaetzliche Eingabe; die Belegeingaben sind "
        "nicht mehr die Vorbedingung des Graphen, und die Entscheidung wird nicht geerbt",
        faellt=(
            "test_the_shipped_example_reaches_the_export_bundle_over_the_cli",
            "test_the_demo_script_itself_runs_green",
        ),
    ),
    Mutation(
        id="R17",
        datei="src/ohpipe/application/export.py",
        alt="        inputs={UPSTREAM: upstream_sha},\n        bind=True,",
        neu="        inputs={UPSTREAM: upstream_sha},\n        bind=False,",
        was="das Bundle wird ohne Bindungsevidenz abgelegt; die Bindungsachse bleibt "
        "UNKNOWN und der Ausgang nie READY",
        faellt=(
            "test_the_shipped_example_reaches_the_export_bundle_over_the_cli",
            "test_the_demo_script_itself_runs_green",
        ),
    ),
    # R18 und R19 zielen auf die zwei Zusicherungen, die man am leichtesten
    # verliert, ohne dass etwas rot wird: eine Pruefung, die nur noch im Build
    # laeuft, und ein Ausgang, der aufhoert deterministisch zu sein.
    Mutation(
        id="R18",
        datei="src/ohpipe/cli/main.py",
        alt="    egress_violations = check_egress_gates(graph)\n"
        '    details["egress_gates"] = "verletzt" if egress_violations else "geschlossen"\n',
        neu="    egress_violations = []\n",
        was="doctor prueft die Egressinvariante nicht mehr; sie waere wieder nur eine "
        "Aussage der Testsuite ueber ein anderes Objekt",
        faellt=(
            "test_doctor_reports_the_egress_gates_as_closed",
            "test_the_demo_script_itself_runs_green",
        ),
    ),
    Mutation(
        id="R19",
        datei="src/ohpipe/application/export.py",
        alt='            "record_id": record_id,\n            "release": {',
        neu='            "record_id": record_id,\n'
        '            "exported_at": __import__("time").time_ns(),\n'
        '            "release": {',
        was="das Bundle traegt einen Zeitstempel; zwei Exporte desselben Records sind "
        "nicht mehr byteweise gleich",
        # Gemessen, nicht vermutet: das Vorfuehrskript bleibt gruen. Jeder
        # Export schreibt seinen eigenen Beleg mit, der Kettenzustand stimmt
        # also weiter — sichtbar wird der Verlust NUR im Vergleich zweier
        # Laeufe. Genau deshalb braucht der Determinismus einen eigenen Fall.
        faellt=("test_two_exports_of_the_same_record_are_byte_identical",),
    ),
    # R20 zielt auf die Stelle, an der die Maschine anfinge zu waehlen. Sie
    # sieht aus wie eine Vereinfachung und ist der ganze Unterschied zwischen
    # "legt Kandidaten vor" und "entscheidet".
    Mutation(
        id="R20",
        datei="src/ohpipe/application/anchors.py",
        alt="                needs_human=ergebnis.needs_human,",
        neu="                needs_human=False,",
        was="der Ankerbericht erklaert jeden Anker fuer maschinell schliessbar; eine "
        "Mehrdeutigkeit verschwindet lautlos aus der Auskunft",
        faellt=(
            "test_a_correction_makes_one_anchor_ambiguous_and_the_machine_does_not_choose",
            "test_the_demo_script_itself_runs_green",
            "test_the_demo_script_ignores_a_foreign_ohpipe_on_the_path",
        ),
    ),
    # R21 und R22 sind die zwei Haelften derselben Zeile. Die eine nimmt der
    # Sperre die Wirkung, die andere nimmt ihr die Grenze. Beide sehen aus wie
    # eine Vereinfachung.
    Mutation(
        id="R21",
        datei="src/ohpipe/application/export.py",
        alt="    if ws.profile.production and offen:",
        neu="    if False and offen:",
        was="die Sperre feuert nirgends mehr; ein produktives Profil laesst einen "
        "Katalogeintrag ohne consent_status und accessRights hinaus",
        faellt=(
            "test_a_production_profile_refuses_to_export_a_record_without_its_mandatory_fields",
        ),
    ),
    Mutation(
        id="R22",
        datei="src/ohpipe/application/export.py",
        alt="    if ws.profile.production and offen:",
        neu="    if offen:",
        was="die Sperre feuert ueberall; die synthetische Uebungswelt kaeme nicht mehr "
        "bis zum Bundle, und das Vorfuehrskript braeche ab",
        faellt=(
            "test_the_shipped_example_reaches_the_export_bundle_over_the_cli",
            "test_the_demo_script_itself_runs_green",
        ),
    ),
    # -- Der Ollama-Adapter (Scheibe 1) -----------------------------------
    #
    # Sechs Mutationen, eine je Zusage. Sie sitzen absichtlich NICHT an den
    # Meldungstexten, sondern an den sechs Stellen, an denen der Adapter etwas
    # PRUEFT: Ein Adapter, der freundlich meldet und nichts prueft, waere in
    # der Abdeckung nicht von einem zu unterscheiden, der beides tut.
    Mutation(
        id="O1",
        datei="src/ohpipe/adapters/models/ollama.py",
        alt="    if name not in ALLOWED_HOSTS:",
        neu="    if False and name not in ALLOWED_HOSTS:",
        was="die Hostregel faellt weg; ein Modellserver auf einem fremden Rechner waere "
        "eine Datenabgabe, ueber die kein Konfigurationswert entscheiden darf",
        faellt=("test_01_a_foreign_host_is_refused_before_any_connection",),
    ),
    Mutation(
        id="O2",
        datei="src/ohpipe/adapters/models/ollama.py",
        alt="                if digest != self.cfg.model_digest:",
        neu="                if False and digest != self.cfg.model_digest:",
        was="der Pin wird nicht mehr geprueft; derselbe Tag traegt morgen ein anderes "
        "Gewicht, und der Beleg nennt trotzdem denselben Namen",
        faellt=("test_14_a_digest_that_differs_from_the_pin_stops_the_run",),
    ),
    Mutation(
        id="O3",
        datei="src/ohpipe/adapters/models/ollama.py",
        alt='                "stream": False,\n                "think": False,\n',
        neu='                "stream": False,\n',
        was="`think` wird nicht mehr gesendet; ein denkendes Modell verbraucht sein Budget "
        "im Denktext, und die Antwort kaeme leer zurueck",
        faellt=("test_17_the_generate_body_is_exactly_the_agreed_one",),
    ),
    Mutation(
        id="O4",
        datei="src/ohpipe/adapters/models/ollama.py",
        alt="        if tokens > self.cfg.num_predict:",
        neu="        if False and tokens > self.cfg.num_predict:",
        was="eine Laufzeit, die num_predict ignoriert, faellt nicht mehr auf; der Beleg "
        "nennt dann eine Grenze, die der Lauf nicht hatte",
        faellt=("test_21_an_eval_count_above_num_predict_stops_the_run",),
    ),
    Mutation(
        id="O5",
        datei="src/ohpipe/adapters/models/ollama.py",
        alt='            if not isinstance(eintrag, dict) or eintrag.get("digest") != erwartet:',
        neu='            if not isinstance(eintrag, dict) or eintrag.get("name") != self.cfg.model:',
        was="Schritt 7 vergleicht wieder den NAMEN statt des Digests; derselbe Digest unter "
        "einem zweiten Tag gaelte als fremd, und ein passender Name saegte ueber das "
        "Gewicht nichts (Pruefvermerk B-1)",
        faellt=("test_23_the_loaded_runner_is_found_by_digest_and_not_by_name",),
    ),
    Mutation(
        id="O6",
        datei="src/ohpipe/adapters/models/ollama.py",
        alt="            if zweiter_text != text or zweiter_finish != finish:",
        neu="            if False and (zweiter_text != text or zweiter_finish != finish):",
        was="die Wiederholungsprobe laeuft, vergleicht aber nichts; im Beleg staende dann "
        "eine Zusage ueber Determiniertheit, die niemand geprueft hat",
        faellt=("test_25_the_repeat_probe_is_a_promise_the_run_has_to_keep",),
    ),
    # -- Der Metadateneingang (06.09.2026) --------------------------------
    #
    # Drei Mutationen an drei Zusagen, die ohne einander nichts wert sind: die
    # Datei muss unter einem produktiven Profil DA sein, sie muss ihren eigenen
    # Record nennen, und ihre Bytes muessen im Beleg stehen. Faellt eine davon,
    # traegt der Katalogeintrag eine Rechtezusage, deren Herkunft niemand mehr
    # aufloest.
    Mutation(
        id="M1",
        datei="src/ohpipe/application/catalog.py",
        alt="    elif ctx.ws.profile.production:",
        neu="    elif False and ctx.ws.profile.production:",
        was="ein produktives Profil leitet wieder ohne Eingabedatei ab; der Entwurf ist "
        "dann endgueltig unvollstaendig, weil metadata.derive kein zweites Mal laeuft",
        faellt=("test_without_an_input_file_a_production_profile_stops_and_names_the_path",),
    ),
    Mutation(
        id="M2",
        datei="src/ohpipe/policies/metadata.py",
        alt='    if inhalt["record_id"] != record_id:',
        neu='    if False and inhalt["record_id"] != record_id:',
        was="eine falsch zugeordnete Eingabedatei laeuft durch; der Dateiname allein ist "
        "keine Pruefung, und im Katalogeintrag waere der Fehler nicht mehr sichtbar",
        faellt=("test_a_record_id_that_does_not_match_the_call_is_an_error",),
    ),
    Mutation(
        id="M3",
        datei="src/ohpipe/application/catalog.py",
        alt='        inputs["metadata.input"] = adresse\n',
        neu="",
        was="die Rohbytes der Eingabe stehen nicht mehr im Beleg; der Katalogeintrag laesst "
        "sich nicht mehr auf die Bytes zurueckfuehren, die ein Mensch getippt hat",
        faellt=("test_the_raw_bytes_go_into_the_store_and_their_digest_into_the_receipt",),
    ),
    # -- Der zweite Satz der Exportsperre (06.09.2026) ---------------------
    #
    # Die Mutation nimmt den Vergleich, nicht den Aufruf: Die Sperre laeuft
    # weiter, liest die Datei weiter und laesst alles durch. Genau so saehe der
    # Ausfall in der Abdeckung aus wie ein Erfolg -- die Zeile ist gemessen,
    # das Verhalten nicht.
    Mutation(
        id="M4",
        datei="src/ohpipe/application/export.py",
        alt="    if jetzt != erwartet:",
        neu="    if False and jetzt != erwartet:",
        was="eine nach dem Entwurf geaenderte Metadateneingabe faellt am Ausgang nicht mehr "
        "auf; der Katalogeintrag geht mit der alten Rechtezusage hinaus, und niemand "
        "sieht, dass daneben eine andere Datei liegt (offene Stelle O-2)",
        faellt=("test_a_changed_input_file_blocks_the_export_and_says_why",),
    ),
    # -- Der doctor-Vorlauf und der Prueferumbau (06.09.2026) --------------
    #
    # D1 nimmt dem Vorlauf die Modellpruefung: Der Loader laeuft weiter, also
    # faellt ein kaputtes TOML noch auf, aber ein `consent_status` ausserhalb
    # des Profilvokabulars nicht mehr -- und genau der ist der Fall, den ein
    # Operator nicht selbst sieht.
    Mutation(
        id="D1",
        datei="src/ohpipe/cli/main.py",
        alt='            befunde.append(f"{pfad.name}: {problem}")\n',
        neu="",
        was="der doctor-Vorlauf meldet Modellbefunde nicht mehr; ein consent_status "
        "ausserhalb des Profilvokabulars faellt erst auf, wenn der Katalogeintrag "
        "steht und metadata.derive nicht mehr laeuft",
        faellt=("test_a_consent_status_outside_the_profile_vocabulary_is_a_finding",),
    ),
    # D2 dreht den Prueferumbau zurueck: wieder das Dateisystem statt git.
    # Der Fall dazu misst gegen ein frisches Repositorium, faellt also
    # unabhaengig davon, was gerade im Arbeitsbaum liegt.
    Mutation(
        id="D2",
        datei="tests/test_ci_config.py",
        alt='        ["git", "ls-files", "-z", "--", "*.py"],',
        neu='        ["git", "ls-files", "-z", "--", "src/*.py"],',
        was="der Lintpruefer sieht nur noch src; ein neues versioniertes Verzeichnis mit "
        "Python bliebe ungeprueft, und der Job sagte weiter sauber",
        faellt=("test_an_unversioned_directory_with_python_does_not_move_the_check",),
    ),
    # -- Ein JSON-Dokument und vollstaendige Segment-IDs (06.09.2026) -----
    # P1, P2 und P8 entfallen mit Kommareparatur und Beispielzeile.
    Mutation(
        id="P9",
        datei="src/ohpipe/adapters/models/ollama.py",
        alt='                "format": ANSWER_SCHEMA,\n',
        neu="",
        was="das JSON-Schema fehlt im Request; die Struktur waere wieder nur erbeten",
        faellt=("test_17_the_generate_body_is_exactly_the_agreed_one",),
    ),
    Mutation(
        id="P10",
        datei="src/ohpipe/application/l1_suggest.py",
        alt="    if missing or foreign or duplicates:",
        neu="    if False and (missing or foreign or duplicates):",
        was="O-3: fehlende, fremde und doppelte Segment-IDs erreichen die Ankerbildung",
        faellt=("test_o3_rejects_wrong_ids_before_anchoring_or_writing",),
    ),
    Mutation(
        id="P11",
        datei="src/ohpipe/application/l1_suggest.py",
        alt='            or type(row.get("segment")) is not int',
        neu='            or not isinstance(row.get("segment"), int)',
        was="bool wird als integer akzeptiert und false kann Segment 0 vertreten",
        faellt=("test_result_entries_require_exact_fields_and_types",),
    ),
    # -- quote verlaesst den Modellvertrag (06.09.2026) --------------------
    #
    # Vier Mutationen an vier Zusagen, die zusammen einen Satz ergeben: Das
    # Modell nennt Segment und Code, die Belegstelle kommt von hier, und das
    # Artefakt sagt beides. Faellt eine davon, traegt der Katalog eine Spanne,
    # die wie eine Wahl des Modells aussieht und keine ist.
    Mutation(
        id="P3",
        datei="src/ohpipe/application/l1_suggest.py",
        alt="            or set(row) != ANTWORTFELDER\n",
        neu="",
        was="ein Ergebniseintrag mit Zusatzfeldern rutscht durch; ein Modell auf dem alten "
        "Vertrag schickt weiter quote, niemand sieht es, und der Beleg traegt eine "
        "Belegstelle aus einer anderen Quelle als der, die das Modell gemeint hat",
        faellt=("test_an_entry_that_still_carries_a_quote_falls_because_the_contract_has_none",),
    ),
    Mutation(
        id="P4",
        datei="src/ohpipe/application/l1_suggest.py",
        alt="                anchor=Anchor.create(rev, start, end),\n",
        neu="                anchor=Anchor.create(rev, start, start + 1),\n",
        was="die Ankerspanne ist nicht mehr das Segment; die Deckung in l1.coverage "
        "bliebe formal richtig, waehrend die Belegstelle auf ein einzelnes Zeichen zeigt",
        faellt=("test_the_anchor_is_the_segment_span_and_not_something_the_model_chose",),
    ),
    Mutation(
        id="P5",
        datei="src/ohpipe/application/l1_suggest.py",
        alt="        if start >= end:\n",
        neu="        if False and start >= end:\n",
        was="ein Segment ohne Text laeuft in einen ValueError aus Anchor.create; ein "
        "Traceback fuer einen Zustand, den die Projektion ausdruecklich zulaesst",
        faellt=("test_a_segment_without_text_has_no_place_to_anchor_and_is_a_finding",),
    ),
    Mutation(
        id="P6",
        datei="src/ohpipe/application/l1_suggest.py",
        alt='                "source": ANCHOR_SOURCE,\n',
        neu="",
        was="der einzelne Vorschlag sagt nicht mehr, woher seine Spanne kommt; wer eine "
        "Zeile allein ansieht, liest ein ganzes Segment als Zitat und haelt es fuer die "
        "Stelle, die das Modell gewaehlt hat",
        faellt=("test_the_artifact_says_which_half_is_the_models_and_which_is_not",),
    ),
    Mutation(
        id="P7",
        datei="src/ohpipe/application/l1_suggest.py",
        alt='        "provenance": {"code": "model", "anchor": ANCHOR_SOURCE},\n',
        neu="",
        was="das Artefakt nennt die Arbeitsteilung nicht mehr im Kopf; model sagt dann "
        "nur noch, WELCHES Modell lief, nicht wofuer es einsteht",
        faellt=("test_the_artifact_says_which_half_is_the_models_and_which_is_not",),
    ),
)


def _hash(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


#: Die zwei pytest-Exitcodes, die ein Testergebnis darstellen. Jeder andere
#: Exitcode ist ein Laufabbruch und darf nie als Mutationsergebnis gelten.
PYTEST_ALLES_GRUEN = 0
PYTEST_TESTS_GEFALLEN = 1


@dataclass(frozen=True)
class Lauf:
    """Ein pytest-Lauf, VOLLSTAENDIG erfasst.

    Die Vorgängerfassung nahm ``subprocess.run(...).stdout`` und liess das
    ``CompletedProcess`` fallen. Der Exitcode war damit nicht ungelesen,
    sondern **unerreichbar**. Gemessen am 10.08. gegen den eigenen Baum, mit
    einem Fehler, der sammelt und erst beim Aufbau fällt:

        pytest    533 passed, 43 xfailed, 1 error    rc=1   FAILED-Zeilen: 0
        Werkzeug  "Grundlauf: 43 xfail, keine Fehlschlaege."          rc=0

    Die Suite war rot, das Werkzeug erklärte die Bezugsmenge für gesund und
    meldete Erfolg. Ein Prüfer, der aus einem Grund grün antwortet, den
    niemand vermutet, ist schlimmer als keiner.

    ``stdout`` UND ``stderr`` gehören zusammen zur Diagnose: ein Exitcode ohne
    die zugehörige Ausgabe ist kein Messwert (Regel 17).
    """

    rc: int
    stdout: str
    stderr: str
    namen: frozenset[str]
    """Gefallene Testfunktionen OHNE Parametrierungssuffix — für ``faellt``."""
    knoten: frozenset[str]
    """Gefallene Knoten-IDs MIT Suffix — für die xfail-Buchhaltung."""
    xfail: int | None
    """Die ``xfail``-Summe dieses Laufs, oder ``None``, wenn nicht ablesbar."""
    fehler: tuple[str, ...]
    """Namen aus ``ERROR``-Zeilen: Collection, Setup und Teardown gleichermassen."""
    fehlerzahl: int
    """Die Fehlerzahl aus der Summenzeile — sie steht auch da, wenn kein Name fällt."""

    @property
    def hat_fehler(self) -> bool:
        return bool(self.fehler) or self.fehlerzahl > 0

    def diagnose(self, grenze: int = 12) -> str:
        """Exitcode plus die letzten Zeilen von stdout und stderr.

        Ausgeschrieben und nicht auf stdout beschränkt: der Fall, der diese
        ganze Härtung ausgelöst hat, stand in der Summenzeile von stdout —
        aber ein Aufruffehler (Exitcode 4) steht auf stderr, und wer nur eine
        der beiden liest, sieht je nach Fehlerart nichts.
        """
        teile = [f"pytest Exitcode {self.rc}"]
        for name, text in (("stdout", self.stdout), ("stderr", self.stderr)):
            zeilen = [z for z in text.splitlines() if z.strip()][-grenze:]
            teile.append(f"--- {name} ---\n" + ("\n".join(zeilen) if zeilen else "(leer)"))
        return "\n".join(teile)


def _summenzeile(stdout: str) -> str:
    """Die letzte nichtleere Zeile — dort und nur dort stehen die Zahlen.

    Die Zahlen aus dem GANZEN Text zu ziehen war die erste Fassung; ein
    Testname, der ``2 errors`` enthält, hätte sie verdorben. Der Umfang ist
    eine Zeile, und das ist ein Umfang.
    """
    zeilen = [z for z in stdout.splitlines() if z.strip()]
    return zeilen[-1] if zeilen else ""


def _auswerten(fertig: subprocess.CompletedProcess[str]) -> Lauf:
    """Aus einem vollständigen ``CompletedProcess`` ein vollständiges :class:`Lauf`."""
    namen: set[str] = set()
    knoten: set[str] = set()
    fehler: list[str] = []
    for zeile in fertig.stdout.splitlines():
        if zeile.startswith("FAILED "):
            rest = zeile.split(" ", 1)[1].split(" ")[0]
            if "::" in rest:
                knoten.add(rest)
                namen.add(rest.split("::")[-1].split("[")[0])
        elif zeile.startswith("ERROR "):
            fehler.append(zeile.split(" ", 1)[1].split(" ")[0])
    summe = _summenzeile(fertig.stdout)
    x = re.search(r"(\d+) xfailed", summe)
    e = re.search(r"(\d+) errors?\b", summe)
    return Lauf(
        rc=fertig.returncode,
        stdout=fertig.stdout,
        stderr=fertig.stderr,
        namen=frozenset(namen),
        knoten=frozenset(knoten),
        xfail=int(x.group(1)) if x else None,
        fehler=tuple(fehler),
        # Ein ERROR ohne Namenszeile gibt es: ein Teardownfehler nach dem
        # letzten Test steht in der Summenzeile und sonst nirgends. Deshalb
        # zaehlen BEIDE Quellen, und `hat_fehler` fragt nach beiden.
        fehlerzahl=int(e.group(1)) if e else 0,
    )


def _pytest(*argumente: str) -> Lauf:
    """Ein pytest-Aufruf mit den Optionen dieses Werkzeugs.

    ``-o addopts=`` ist nicht Kosmetik. ``pyproject.toml`` setzt
    ``addopts = "-q"``; mit argv ``-q`` wird daraus ``-qq``, und **unter
    ``-qq`` druckt pytest die Summenzeile gar nicht**. Die Vorgängerfassung
    hing damit an einer Zeile in einer fremden Datei und hätte die
    ``xfail``-Summe nie lesen können. Der Job ``zahlen`` setzt seine Optionen
    aus demselben Grund selbst.
    """
    return _auswerten(
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-o",
                "addopts=",
                "-q",
                "-p",
                "no:cacheprovider",
                *argumente,
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
        )
    )


def _lauf() -> Lauf:
    """Ein vollständiger Suitelauf."""
    return _pytest()


def _markierte_knoten() -> tuple[frozenset[str], str | None]:
    """Die Knoten-IDs aller ``xfail``-markierten Fälle — ABGELEITET.

    Aus der Sammlung, nicht aus einer gepflegten Liste. Eine Liste im Werkzeug
    wäre dasselbe Driftproblem eine Ebene höher: sie ginge beim ersten neuen
    Marker still daneben, und das Werkzeug meldete dann Kollateral, wo keines
    ist — oder schlimmer, keines, wo welches ist.

    Liefert die Menge **und** einen Befund. Auch hier wird der Exitcode
    gelesen: eine Sammlung, die mit 2 endet, kann eine vollständig aussehende
    Menge liefern — gemessen am 10.08., 43 Namen aus einem Lauf, der
    abgebrochen ist. Eine plausible Zahl aus einem gescheiterten Lauf ist die
    teuerste Sorte Messwert.
    """
    lauf = _pytest("--collect-only", "-m", "xfail")
    if lauf.rc != PYTEST_ALLES_GRUEN:
        return frozenset(), f"Sammellauf endete mit Exitcode {lauf.rc}.\n{lauf.diagnose()}"
    if lauf.hat_fehler:
        return frozenset(), f"Sammellauf meldet ERRORs: {lauf.fehler}\n{lauf.diagnose()}"
    knoten = {
        z.strip()
        for z in lauf.stdout.splitlines()
        if "::" in z and not z.startswith(("FAILED", "ERROR"))
    }
    return frozenset(knoten), None


def grundlauf_befund(lauf: Lauf, markiert: frozenset[str]) -> str | None:
    """Ist der unmutierte Bezugslauf ueberhaupt gueltig? ``None`` = ja.

    Fünf Bedingungen, jede einzeln benannt. Die dritte ist die, die gefehlt
    hat: ein ``ERROR`` vergiftet den Bezug, ohne eine einzige ``FAILED``-Zeile
    zu erzeugen, und jeder Vergleich darunter misst dann gegen einen kranken
    Ausgangswert.
    """
    if lauf.rc != PYTEST_ALLES_GRUEN:
        return f"der Grundlauf endet mit Exitcode {lauf.rc}, erwartet 0.\n{lauf.diagnose()}"
    if lauf.namen:
        return f"der Grundlauf hat Fehlschlaege: {sorted(lauf.namen)}\n{lauf.diagnose()}"
    if lauf.hat_fehler:
        return (
            f"der Grundlauf meldet {lauf.fehlerzahl} ERROR(s): {list(lauf.fehler)}. "
            f"Ein Error vergiftet den Bezug, ohne ein FAILED zu erzeugen.\n{lauf.diagnose()}"
        )
    if lauf.xfail is None:
        return f"die xfail-Summe ist nicht ablesbar.\n{lauf.diagnose()}"
    if len(markiert) != lauf.xfail:
        return (
            f"{len(markiert)} markierte Faelle, aber xfail-Summe {lauf.xfail}. "
            "Solange beide Zahlen nicht uebereinstimmen, sagt die Buchhaltung darunter nichts."
        )
    return None


def bewerte(
    m: Mutation, lauf: Lauf, markiert: frozenset[str], xfail_basis: int
) -> tuple[str | None, str]:
    """Ein Mutantenlauf, bewertet. Liefert ``(Befund oder None, Anzeigezeile)``.

    Als eigene, **reine** Funktion, damit die Regressionstests sie ohne Suite
    und ohne Mutation aufrufen koennen. Die Vorgaengerfassung stand mitten in
    ``main`` zwischen Dateischreiben und Signalhandler; sie war nur
    ueberpruefbar, indem man elf Minuten Mutantenlauf startete — also gar
    nicht.

    Die Reihenfolge der Zweige ist die Aussage:

    1. Jeder Exitcode ausser 0 und 1 ist ein Laufabbruch, kein Testergebnis.
    2. Ein zusaetzlicher ERROR ist ein Befund, AUCH wenn der gemeinte Test
       faellt. Ein Mutant darf nie mit Error gruen werden.
    3. Exitcode 0 heisst "ueberlebt" — und ist damit ein Befund ueber die
       Zusage, kein technischer Fehler.
    """
    if lauf.rc not in (PYTEST_ALLES_GRUEN, PYTEST_TESTS_GEFALLEN):
        return (
            f"{m.id}: LAUFABBRUCH — pytest Exitcode {lauf.rc}, das ist kein Testergebnis.\n"
            f"{lauf.diagnose()}",
            f"  {m.id}  LAUFABBRUCH  Exitcode {lauf.rc}",
        )
    if lauf.hat_fehler:
        return (
            f"{m.id}: ERROR im Mutantenlauf ({lauf.fehlerzahl}): {list(lauf.fehler)}. "
            f"Ein Mutant darf nicht mit Error gruen werden.\n{lauf.diagnose()}",
            f"  {m.id}  ERROR      {list(lauf.fehler)}",
        )
    if lauf.rc == PYTEST_ALLES_GRUEN or not lauf.namen:
        return (
            f"{m.id}: UEBERLEBT — {m.was}. Die Zusage ist unbewiesen.",
            f"  {m.id}  UEBERLEBT  {m.was}",
        )
    fehlend = [t for t in m.faellt if t not in lauf.namen]
    if fehlend:
        return (
            f"{m.id}: erwartete Tests fielen NICHT ({', '.join(fehlend)}); "
            f"gefallen sind stattdessen: {', '.join(sorted(lauf.namen))}",
            f"  {m.id}  VERHAKT   erwartet {fehlend}, gefallen {sorted(lauf.namen)}",
        )
    # Die zweite Haelfte von Regel 4. Ein gefallener Knoten, der einen
    # xfail-Marker traegt, ist kein Fehlschlag, sondern ein XPASS(strict) —
    # der Marker ist umgeschlagen. Genau diese Menge verschwand frueher in der
    # Klammer "(+N weitere)".
    gekippt = sorted(lauf.knoten & markiert)
    unerwartet = sorted(set(gekippt) - set(m.kippt))
    ausgeblieben = sorted(set(m.kippt) - set(gekippt))
    if unerwartet:
        return (
            f"{m.id}: KOLLATERAL — diese xfail-Marker sind mit umgeschlagen, "
            f"ohne dass die Mutation sie deklariert: {', '.join(unerwartet)}",
            f"  {m.id}  KOLLATERAL {len(unerwartet)} Marker: {unerwartet}",
        )
    if ausgeblieben:
        return (
            f"{m.id}: deklarierte Marker sind NICHT umgeschlagen: "
            f"{', '.join(ausgeblieben)}. Die Deklaration ist veraltet.",
            f"  {m.id}  DEKLARATION VERALTET  {ausgeblieben}",
        )
    # Die Buchhaltung, unabhaengig von den Namen nachgerechnet: jeder gekippte
    # Marker fehlt genau einmal in der Summe.
    soll_xfail = xfail_basis - len(gekippt)
    if lauf.xfail != soll_xfail:
        return (
            f"{m.id}: xfail-Summe ist {lauf.xfail}, erwartet {soll_xfail} "
            f"(Basis {xfail_basis} minus {len(gekippt)} deklariert gekippte).",
            f"  {m.id}  SUMME     {lauf.xfail} statt {soll_xfail}",
        )
    # Die gekippten Marker sind schon gezaehlt; sie hier ein zweites Mal als
    # "weitere Testfunktionen" zu drucken, machte aus sieben Knoten drei Namen
    # und damit genau die Zusammenfassung, gegen die dieser Umbau steht.
    gekippte_namen = {k.split("::")[-1].split("[")[0] for k in gekippt}
    rest = sorted(lauf.namen - set(m.faellt) - gekippte_namen)
    zusatz = f" · {len(gekippt)} Marker gekippt, deklariert" if gekippt else ""
    weitere = f" · {len(rest)} weitere Testfunktionen: {rest}" if rest else ""
    return (None, f"  {m.id}  gefallen  {', '.join(m.faellt)}{zusatz}{weitere}")


# ---------------------------------------------------------------------------
# E1 · Zustaende, Inhaltsbaseline und Exklusivitaet
#
# Der Befund, den dieser Block schliesst: die Eingangspruefung lief allein
# ueber ``git diff --name-only HEAD --`` und lieferte fuer VIER verschiedene
# Zustaende dieselbe leere Liste — sauberer verfolgter Bestand, unverfolgte
# Zieldatei, kein Git, Git-Fehler. Nach dem Schreiben einer Mutation wurde
# derselbe leere Wert als Anlass genommen, die Gegenprobe auf genau eine
# veraenderte Zieldatei zu ueberspringen. In der Rotphase einer neuen, noch
# unverfolgten Produktdatei waren damit beide Vorkehrungen wirkungslos.
#
# Die Antwort ist keine bessere git-Frage, sondern eine Trennung der
# Zustaendigkeiten: **git bleibt Herkunfts- und Sauberkeitsfuehler**, aber die
# Aussage, WELCHE Dateien die gerade ausgefuehrte Mutation bewegt hat, kommt
# ausschliesslich aus Dateibytes. Sie darf nicht von Verfolgung abhaengen und
# bei fehlendem git nicht entfallen.
# ---------------------------------------------------------------------------

#: Halt vor dem Grundlauf: verfolgter Schmutz, unbrauchbares Template,
#: fehlende Zieldatei, Git-Fehler. Kein Suitelauf hat stattgefunden.
HALT_VOR_GRUNDLAUF = 2

#: Die Startbytes stehen nach dem Lauf nicht wieder da. Werkzeugfehler.
WIEDERHERSTELLUNG_FEHLGESCHLAGEN = 3

#: Die Abweichungsmenge nach dem Mutationsschreibvorgang ist nicht genau die
#: Zieldatei der ausgewaehlten Mutation. Der teure Suitelauf unterbleibt.
HALT_VOR_SUITELAUF = 4

#: Die drei Klassen der HEAD-Sonde `git rev-parse --verify -q HEAD`. Jeder
#: andere Wert ist ein Fehler: ein Exitcode traegt seine Bedeutung nicht mit
#: sich herum, sondern von der Frage, die ihn erzeugt hat.
HEAD_VORHANDEN = 0
HEAD_UNGEBOREN = 1

#: Exitcode, mit dem git ein `fatal:` quittiert — darunter „kein Worktree".
#: Nur an der EINEN Sonde unten wird er so gelesen; jeder andere Exitcode aus
#: jedem Aufruf ist ein Fehler und kein Zustand.
GIT_FATAL = 128


#: Das auszufuehrende Programm. Als Konstante, weil die Herkunft einer
#: Ausnahme daran gemessen wird und nicht am Meldungstext.
GIT_BINARY = "git"


class Gitmodus(str, Enum):
    """In welcher Lage das Werkzeug git ueberhaupt befragen konnte."""

    WORKTREE = "worktree"
    KEIN_GIT = "kein-git"
    FEHLER = "fehler"


class Gitklasse(str, Enum):
    """Die sechs unterscheidbaren Befunde. F2 trennt die letzten beiden Paare.

    Vor F2 zog das Werkzeug zwei Paare zusammen: jede ``OSError``-Ausnahme
    galt als fehlendes Binary (fail-open bei EACCES), und jeder Nichtnullwert
    der HEAD-Sonde galt als Repository ohne HEAD (ein rc 129 erschien als
    staged Schmutz). Beides sind Faelle derselben Klasse wie der E1-Befund
    selbst — verschiedene Zustaende ueber einen Wert dargestellt.
    """

    NORMAL = "verfolgter Bestand mit aufloesbarem HEAD"
    OHNE_HEAD = "Repository ohne aufloesbaren HEAD"
    KEIN_BINARY = "fehlendes Git-Binary"
    KEIN_WORKTREE = "kein Git-Worktree"
    AUSNAHME = "unerwartete Ausnahme beim Git-Prozess"
    UNERWARTETER_RC = "unerwarteter Git-Rueckgabewert"


@dataclass(frozen=True)
class Gitlage:
    """Die Zustaende, getrennt — nicht mehr ueber eine leere Liste zusammengezogen.

    Jede Menge traegt ihre eigene Frage: ``verfolgt_sauber`` kommt aus
    ``git ls-files`` minus den beiden Diffs, ``staged`` aus
    ``git diff --cached HEAD``, ``unstaged`` aus ``git diff``, ``unverfolgt``
    aus „liegt auf der Platte und ``ls-files`` kennt sie nicht".
    """

    modus: Gitmodus
    klasse: Gitklasse = Gitklasse.NORMAL
    verfolgt_sauber: tuple[str, ...] = ()
    staged: tuple[str, ...] = ()
    unstaged: tuple[str, ...] = ()
    unverfolgt: tuple[str, ...] = ()
    fehlend: tuple[str, ...] = ()
    diagnose: str = ""

    @property
    def schmutzig(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.staged) | set(self.unstaged)))


@dataclass(frozen=True)
class Prozessausnahme:
    """Eine Ausnahme beim Start oder Lauf des Gitprozesses — ohne Prozessergebnis.

    **Warum ``filename`` und nicht der Meldungstext.** Gemessen im Baucontainer
    unter CPython 3.11: ein fehlendes Programm liefert ``FileNotFoundError``
    mit ``filename`` = dem auszufuehrenden Programm, ein fehlendes
    Arbeitsverzeichnis denselben Ausnahmetyp mit ``filename`` = dem
    Verzeichnis. Der Meldungstext ist in beiden Faellen identisch. Die Herkunft
    steht also im Feld, nicht im Text.
    """

    klasse: str
    errnummer: int | None
    meldung: str
    dateiname: str | None
    fehlendes_binary: bool

    def als_diagnose(self, was: str) -> str:
        teile = [f"{was} warf {self.klasse}"]
        if self.errnummer is not None:
            teile.append(f"errno {self.errnummer}")
        if self.dateiname:
            teile.append(f"betroffen: {self.dateiname}")
        teile.append(self.meldung or "(keine Meldung)")
        # Kein erfundener git-Exitcode: zu dieser Ausnahme gehoert keiner.
        return " · ".join(teile) + "\nZu dieser Ausnahme gehoert kein Prozessergebnis."


def _git(*argumente: str) -> subprocess.CompletedProcess[str] | Prozessausnahme:
    """Ein lesender git-Aufruf.

    Liefert entweder das Prozessergebnis oder — bei einer Ausnahme vor oder
    waehrend der Ausfuehrung — eine :class:`Prozessausnahme`. Die Vorgaenger-
    fassung gab in beiden Ausnahmefaellen ``None`` und liess den Aufrufer
    daraus „kein Git" lesen; bei ``EACCES`` lief das Werkzeug damit fail-open
    weiter.
    """
    try:
        return subprocess.run(
            [GIT_BINARY, "--no-optional-locks", *argumente],
            cwd=REPO,
            capture_output=True,
            text=True,
        )
    except OSError as fehler:
        dateiname = getattr(fehler, "filename", None)
        return Prozessausnahme(
            klasse=type(fehler).__name__,
            errnummer=fehler.errno,
            meldung=str(fehler),
            dateiname=dateiname,
            fehlendes_binary=isinstance(fehler, FileNotFoundError) and dateiname == GIT_BINARY,
        )


def _null_liste(text: str) -> list[str]:
    return [z for z in text.split("\0") if z]


def _ausnahmelage(was: str, ausnahme: Prozessausnahme, fehlend: tuple[str, ...]) -> Gitlage:
    """Nur das tatsaechlich fehlende Binary ist ``KEIN_GIT``; alles andere haelt."""
    if ausnahme.fehlendes_binary:
        return Gitlage(
            modus=Gitmodus.KEIN_GIT,
            klasse=Gitklasse.KEIN_BINARY,
            fehlend=fehlend,
            diagnose=ausnahme.als_diagnose(was),
        )
    return Gitlage(
        modus=Gitmodus.FEHLER,
        klasse=Gitklasse.AUSNAHME,
        fehlend=fehlend,
        diagnose=ausnahme.als_diagnose(was),
    )


def _rcfehlerlage(
    was: str, fertig: subprocess.CompletedProcess[str], fehlend: tuple[str, ...]
) -> Gitlage:
    return Gitlage(
        modus=Gitmodus.FEHLER,
        klasse=Gitklasse.UNERWARTETER_RC,
        fehlend=fehlend,
        diagnose=(
            f"{was} endete mit Exitcode {fertig.returncode}.\n"
            f"--- stdout ---\n{fertig.stdout.strip() or '(leer)'}\n"
            f"--- stderr ---\n{fertig.stderr.strip() or '(leer)'}"
        ),
    )


def gitlage(dateien: list[str]) -> Gitlage:
    """Die Zustaende, einzeln benannt — sechs Klassen, keine zusammengezogen.

    Die Repositoriumssonde ist ``git rev-parse --git-dir``: Exitcode 0 heisst
    Worktree, Exitcode 128 heisst „kein Repository" — und **nur an dieser
    Sonde** wird 128 so gelesen. Die HEAD-Sonde kennt genau drei Klassen
    (0, 1, alles andere). Jeder sonstige Exitcode und jede Ausnahme, die nicht
    das fehlende Binary identifiziert, ist ``FEHLER``: der Zustand, in dem das
    Werkzeug nichts weiss und deshalb nicht den bequemsten der uebrigen
    annehmen darf.
    """
    vorhanden = tuple(sorted(d for d in dateien if (REPO / d).exists()))
    fehlend = tuple(sorted(set(dateien) - set(vorhanden)))

    sonde = _git("rev-parse", "--git-dir")
    if isinstance(sonde, Prozessausnahme):
        return _ausnahmelage("git rev-parse --git-dir", sonde, fehlend)
    if sonde.returncode == GIT_FATAL:
        return Gitlage(
            modus=Gitmodus.KEIN_GIT,
            klasse=Gitklasse.KEIN_WORKTREE,
            fehlend=fehlend,
            diagnose=f"kein git-Worktree: {sonde.stderr.strip() or '(keine Meldung)'}",
        )
    if sonde.returncode != 0:
        return _rcfehlerlage("git rev-parse --git-dir", sonde, fehlend)

    gelistet = _git("ls-files", "-z", "--", *dateien)
    if isinstance(gelistet, Prozessausnahme):
        return _ausnahmelage("git ls-files", gelistet, fehlend)
    if gelistet.returncode != 0:
        return _rcfehlerlage("git ls-files", gelistet, fehlend)
    verfolgt = set(_null_liste(gelistet.stdout))

    kopf = _git("rev-parse", "--verify", "-q", "HEAD")
    if isinstance(kopf, Prozessausnahme):
        return _ausnahmelage("git rev-parse --verify -q HEAD", kopf, fehlend)
    if kopf.returncode == HEAD_VORHANDEN:
        gestaged = _git("diff", "--cached", "--name-only", "-z", "HEAD", "--", *dateien)
        if isinstance(gestaged, Prozessausnahme):
            return _ausnahmelage("git diff --cached HEAD", gestaged, fehlend)
        if gestaged.returncode != 0:
            return _rcfehlerlage("git diff --cached HEAD", gestaged, fehlend)
        staged = set(_null_liste(gestaged.stdout))
        klasse = Gitklasse.NORMAL
        hinweis = ""
    elif kopf.returncode == HEAD_UNGEBOREN:
        # Ein Repository ohne Commit. Kein Fehler und kein Grund, den Bestand
        # fuer sauber zu erklaeren: ohne HEAD gibt es keine Bezugsgroesse,
        # gegen die etwas sauber sein koennte.
        staged = set(verfolgt)
        klasse = Gitklasse.OHNE_HEAD
        hinweis = (
            "kein aufloesbarer HEAD: jede verfolgte Zieldatei gilt als staged, "
            "keine als gegen HEAD sauber"
        )
    else:
        return _rcfehlerlage("git rev-parse --verify -q HEAD", kopf, fehlend)

    ungestaged = _git("diff", "--name-only", "-z", "--", *dateien)
    if isinstance(ungestaged, Prozessausnahme):
        return _ausnahmelage("git diff", ungestaged, fehlend)
    if ungestaged.returncode != 0:
        return _rcfehlerlage("git diff", ungestaged, fehlend)
    unstaged = set(_null_liste(ungestaged.stdout))

    return Gitlage(
        modus=Gitmodus.WORKTREE,
        klasse=klasse,
        verfolgt_sauber=tuple(sorted(verfolgt - staged - unstaged)),
        staged=tuple(sorted(staged)),
        unstaged=tuple(sorted(unstaged)),
        unverfolgt=tuple(sorted(set(vorhanden) - verfolgt)),
        fehlend=fehlend,
        diagnose=hinweis,
    )


def lagezeile(lage: Gitlage) -> str:
    """Ein Etikett, das Quelle, Klasse und Zaehlart nennt (E1-8, F2-3).

    Es sagt nie „sauber laut Git" ueber eine Datei, die git gar nicht kennt,
    und es unterscheidet das fehlende Binary vom fehlenden Worktree.
    """
    if lage.modus is Gitmodus.KEIN_GIT:
        return (
            f"Gitlage: kein Git — {lage.klasse.value} ({lage.diagnose}). Der Lauf geht weiter; "
            "Templatepruefung, Inhaltsbaseline, Gegenprobe und Wiederherstellung tragen "
            "unveraendert."
        )
    teile = [
        f"{len(lage.verfolgt_sauber)} verfolgt und gegen HEAD sauber",
        f"{len(lage.unverfolgt)} unverfolgt",
    ]
    if lage.unverfolgt:
        teile.append(f"unverfolgt: {list(lage.unverfolgt)}")
    zusatz = f" · {lage.klasse.value}" if lage.klasse is not Gitklasse.NORMAL else ""
    hinweis = f" · {lage.diagnose}" if lage.diagnose else ""
    return (
        "Gitlage (Zaehlart: git ls-files, git diff --cached HEAD, git diff): "
        + ", ".join(teile)
        + zusatz
        + hinweis
        + ". Die Laufbaseline stammt aus Dateibytes, nicht aus dieser Zeile."
    )


def startbaseline(dateien: list[str]) -> tuple[dict[str, bytes] | None, str | None]:
    """Die Inhaltsbaseline, VOR dem Grundlauf (E1-5).

    Sie wird nicht nach dem Grundlauf und nicht nach der ersten Mutation
    gebildet: eine Baseline, die nach einem Schreibvorgang entsteht, kann den
    Schreibvorgang nicht mehr sehen.
    """
    basis: dict[str, bytes] = {}
    for d in sorted(dateien):
        pfad = REPO / d
        try:
            basis[d] = pfad.read_bytes()
        except OSError as fehler:
            return None, f"Zieldatei {d} ist nicht lesbar: {fehler}"
    return basis, None


def templatebefund(ausgewaehlt: list[Mutation]) -> str | None:
    """Jedes im Lauf relevante Ausgangsmuster genau einmal — vor dem Grundlauf (E1-3).

    Das ist die Vorkehrung, die eine unverfolgte Zieldatei ueberhaupt
    zulaessig macht: git kann hier nicht sagen, ob schon ein Mutant steht,
    also sagt es das Muster. Null Vorkommen heisst in aller Regel: ein
    frueherer Lauf ist gestorben und hat seine Mutation stehen lassen.
    """
    for m in ausgewaehlt:
        pfad = REPO / m.datei
        try:
            text = pfad.read_text(encoding="utf-8")
        except OSError as fehler:
            return f"{m.id}: Zieldatei {m.datei} ist nicht lesbar: {fehler}"
        anzahl = text.count(m.alt)
        if anzahl != 1:
            return (
                f"{m.id}: das Ausgangsmuster kommt in {m.datei} {anzahl}x vor, erwartet genau 1x. "
                "Bei 0 steht dort vermutlich schon die Mutation eines abgebrochenen Laufs; "
                "bei mehr als 1 ist der Anker nicht eindeutig. In beiden Faellen waere die "
                "Laufbaseline geraten, und es laeuft keine Suite."
            )
    return None


def abweichung(dateien: list[str], baseline: dict[str, bytes]) -> tuple[str, ...]:
    """Welche Zieldateien weichen JETZT von der Startbaseline ab — aus Bytes.

    Unabhaengig von git-Verfolgung und vom Vorhandensein von git. Eine
    fehlende Datei zaehlt als Abweichung: sie ist nicht mehr die Startdatei.
    """
    abweichend = []
    for d in sorted(dateien):
        pfad = REPO / d
        try:
            jetzt = pfad.read_bytes()
        except OSError:
            abweichend.append(d)
            continue
        if jetzt != baseline.get(d):
            abweichend.append(d)
    return tuple(abweichend)


def _schreibe_mutation(ziel: Path, alt: str, neu: str) -> None:
    """Der eine Schreibschritt. Eigene Funktion, damit die Gegenprobe unter ihm messbar ist."""
    ziel.write_text(ziel.read_text(encoding="utf-8").replace(alt, neu), encoding="utf-8")


def _abweichungssatz(m: Mutation, abw: tuple[str, ...], lage: Gitlage) -> str:
    if not abw:
        grund = (
            "keine einzige Zieldatei weicht ab. Der Schreibvorgang hat nichts bewegt; "
            "ein Suitelauf haette den unmutierten Baum gemessen und den Mutanten als "
            "gefallen oder ueberlebt gebucht, ohne dass es eine Mutation gab"
        )
    elif len(abw) > 1:
        grund = f"{len(abw)} Zieldateien weichen ab: {list(abw)}. Das Werkzeug hat Rueckstand"
    else:
        grund = (
            f"es weicht {abw[0]} ab, ausgewaehlt war aber {m.datei}. "
            "Der Befund einer solchen Messung waere keiner Mutation zuzuordnen"
        )
    return (
        f"{m.id}: Abweichungsmenge gegen die Inhaltsbaseline dieses Laufs ist nicht "
        f"genau {{{m.datei}}} — {grund}. "
        f"(Zaehlart: sha256 je Zieldatei gegen die vor dem Grundlauf gelesenen Startbytes; "
        f"Gitmodus {lage.modus.value}, fuer diese Aussage ohne Belang.)"
    )


def main(argv: list[str], *, lauf=None, markierte=None) -> int:
    """Ein Mutationslauf.

    ``lauf`` und ``markierte`` sind einspeisbar, damit die Werkzeugtests die
    Zweige messen koennen, ohne je eine echte Suite zu starten — und damit
    „haelt VOR dem Suitelauf" als Zahl beobachtbar ist statt als Vermutung.
    """
    lauf = lauf or _lauf
    markierte = markierte or _markierte_knoten

    ausgewaehlt = [m for m in MUTANTEN if not argv or m.id in argv]
    if not ausgewaehlt:
        print(f"Keine Mutation passt auf {argv}. Bekannt: {[m.id for m in MUTANTEN]}")
        return HALT_VOR_GRUNDLAUF

    dateien = sorted({m.datei for m in MUTANTEN})

    # --- Vor jedem Suitelauf: die vier Tore ------------------------------
    lage = gitlage(dateien)
    if lage.modus is Gitmodus.FEHLER:
        kopfzeile = (
            "HALT vor dem Grundlauf: der git-Prozess warf eine Ausnahme."
            if lage.klasse is Gitklasse.AUSNAHME
            else "HALT vor dem Grundlauf: git antwortet mit einem unerwarteten Exitcode."
        )
        print(kopfzeile, f"Klasse: {lage.klasse.value}", lage.diagnose, sep="\n  ")
        return HALT_VOR_GRUNDLAUF
    if lage.fehlend:
        print(
            "HALT vor dem Grundlauf: Zieldateien fehlen.",
            f"fehlend: {list(lage.fehlend)}",
            sep="\n  ",
        )
        return HALT_VOR_GRUNDLAUF
    if lage.schmutzig:
        print(
            "HALT vor dem Grundlauf: verfolgte Zieldateien sind gegen HEAD veraendert.",
            f"staged:   {list(lage.staged)}",
            f"unstaged: {list(lage.unstaged)}",
            "Entweder liegt eine echte Aenderung vor — dann erst einchecken —,",
            "oder ein frueherer Lauf wurde getoetet und hat einen Mutanten stehen lassen.",
            "Das Werkzeug nimmt diesen Zustand nicht als Baseline und repariert ihn nicht.",
            sep="\n  ",
        )
        return HALT_VOR_GRUNDLAUF
    print(lagezeile(lage))

    basis, basisbefund = startbaseline(dateien)
    if basisbefund or basis is None:
        print("HALT vor dem Grundlauf: keine Inhaltsbaseline.", basisbefund, sep="\n  ")
        return HALT_VOR_GRUNDLAUF

    tbefund = templatebefund(ausgewaehlt)
    if tbefund:
        print("HALT vor dem Grundlauf: Ausgangsmuster passt nicht.", tbefund, sep="\n  ")
        return HALT_VOR_GRUNDLAUF

    # --- Ab hier erst laufen Suiten --------------------------------------
    markiert, sammelbefund = markierte()
    if sammelbefund:
        print("ABBRUCH: die Markermenge ist nicht ableitbar.", sammelbefund, sep="\n  ")
        return HALT_VOR_GRUNDLAUF

    grund = lauf()
    befund = grundlauf_befund(grund, markiert)
    if befund:
        print("ABBRUCH vor der ersten Mutation:", befund, sep="\n  ")
        return HALT_VOR_GRUNDLAUF
    xfail_basis = grund.xfail
    assert xfail_basis is not None  # grundlauf_befund hat das bereits geprueft
    print(f"Grundlauf: {xfail_basis} xfail, kein FAILED, kein ERROR, Exitcode 0.")

    def zuruecknehmen(*_):
        for d in dateien:
            (REPO / d).write_bytes(basis[d])

    def bei_signal(signum, _rahmen):
        # `finally` laeuft bei SIGTERM NICHT. Die erste Fassung dieses Skripts
        # hat genau daran einen Mutanten im Baum hinterlassen.
        zuruecknehmen()
        print(f"\nabgebrochen (Signal {signum}) — Mutation zurueckgenommen.")
        raise SystemExit(WIEDERHERSTELLUNG_FEHLGESCHLAGEN)

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, bei_signal)

    befunde: list[str] = []
    halt: tuple[int, str] | None = None
    try:
        for m in ausgewaehlt:
            zuruecknehmen()
            rest = abweichung(dateien, basis)
            if rest:
                halt = (
                    WIEDERHERSTELLUNG_FEHLGESCHLAGEN,
                    f"{m.id}: die Zieldateien {list(rest)} treffen die Startbaseline schon vor "
                    "der Mutation nicht. Werkzeugfehler, kein Mutationsergebnis.",
                )
                break

            _schreibe_mutation(REPO / m.datei, m.alt, m.neu)

            abw = abweichung(dateien, basis)
            if abw != (m.datei,):
                halt = (HALT_VOR_SUITELAUF, _abweichungssatz(m, abw, lage))
                break

            fund, zeile = bewerte(m, lauf(), markiert, xfail_basis)
            print(zeile)
            if fund:
                befunde.append(fund)
    finally:
        # KEIN `return` hier drin: ein `return` im `finally` verschluckt eine
        # Ausnahme aus dem `try` (ruff B012). Die Wiederherstellung wird
        # GEPRUEFT, nicht angenommen.
        zuruecknehmen()
        stehen = abweichung(dateien, basis)

    if stehen:
        print(
            "\nFEHLER: Zieldateien treffen die Startbaseline nach dem Lauf nicht:",
            *stehen,
            "(Zaehlart: Bytes gegen die vor dem Grundlauf gelesenen Startbytes.)",
            sep="\n  ",
        )
        return WIEDERHERSTELLUNG_FEHLGESCHLAGEN

    if halt is not None:
        code, satz = halt
        kopf = (
            "HALT vor dem Mutantensuitelauf:"
            if code == HALT_VOR_SUITELAUF
            else "FEHLER in der Wiederherstellung:"
        )
        print(kopf, satz, sep="\n  ")
        return code

    print()
    if befunde:
        print("MUTATIONSBEFUNDE:", *befunde, sep="\n  ")
        return 1
    # Die Exklusivitaetsbehauptung ist ERSATZLOS gestrichen. Sie lautete erst
    # "jede von dem Test, der sie meint" und dann "die gemeinten Tests fallen,
    # und nur sie" — beide Male behauptete der Satz mehr, als das Werkzeug
    # misst: E8, V2 und E9 lassen regulaer weitere Tests fallen.
    gekippt_gesamt = sum(len(m.kippt) for m in ausgewaehlt)
    print(
        f"{len(ausgewaehlt)} Mutationen, alle gefallen. Die gemeinten Tests fallen; "
        f"alle xfail-Kippungen sind deklariert, keine weitere. "
        f"xfail-Summe {xfail_basis}, {gekippt_gesamt} deklarierte Kippungen."
    )
    return 0


B3B_MUTANTEN: tuple[Mutation, ...] = (
    Mutation(
        "M01",
        "src/ohpipe/domain/token.py",
        'TOKEN_RE = re.compile(r"[A-Za-z0-9_.:@/+\\-]{3,64}\\Z")',
        'TOKEN_RE = re.compile(r"[\\w_.:@/+\\-]{3,64}\\Z")',
        "zentrale Tokenregel wieder auf Unicode-\\w stellen",
        ("test_unicode_word_character_never_enters_an_ascii_token",),
    ),
    Mutation(
        "M02",
        "src/ohpipe/domain/token.py",
        'TOKEN_RE = re.compile(r"[A-Za-z0-9_.:@/+\\-]{3,64}\\Z")',
        'TOKEN_RE = re.compile(r"[A-Za-z0-9_.:@/+\\-]{3,64}(?:\\n)?\\Z")',
        "Token-Endanker wieder auf Dollar-vor-Schluss-LF oeffnen",
        ("test_token_end_anchor_rejects_a_final_lf",),
    ),
    Mutation(
        "M03",
        "src/ohpipe/domain/events.py",
        "        fremd = sorted(set(payload) - specialised)",
        "        fremd = []",
        "fremde Felder in einer neuen Ereignishuellenform zulassen",
        ("test_new_event_envelope_refuses_a_foreign_payload_field",),
    ),
    Mutation(
        "M04",
        "src/ohpipe/application/replay.py",
        """                v.effective_decision_by_artifact.pop(name, None)
                f.decided_sha = None
                f.decided_verdict = None
""",
        "",
        "bei ungueltiger juengster Decision auf eine aeltere zurueckfallen",
        ("test_invalid_newest_decision_blocks_fallback_to_an_older_one",),
    ),
    Mutation(
        "M05",
        "src/ohpipe/application/replay.py",
        '    if p.get("record_id") and p["record_id"] != record_id:',
        "    if False:",
        "payload.record_id vor der DecisionRoutingKey-Auswahl filtern",
        ("test_decision_payload_record_is_checked_before_routing",),
    ),
    Mutation(
        "M06",
        "src/ohpipe/application/ingest.py",
        """        if not any(
            event.kind == RECEIPT_RECORDED and event.payload == receipt for event in journal
        ):
""",
        """        if False and not any(
            event.kind == RECEIPT_RECORDED and event.payload == receipt for event in journal
        ):
""",
        "historischen SRT-Record ohne Intentbezug mit Receipt nachruesten",
        ("test_produced_without_intent_bound_receipt_is_not_backfilled",),
    ),
    Mutation(
        "M07",
        "src/ohpipe/application/ingest.py",
        """            Effect(RECEIPT_RECORDED, receipt, plan.record_id),
            Effect(ARTIFACT_PRODUCED, produced, plan.record_id),
""",
        """            Effect(ARTIFACT_PRODUCED, produced, plan.record_id),
            Effect(RECEIPT_RECORDED, receipt, plan.record_id),
""",
        "ingest produced vor den segment_projection-Receipt schreiben",
        ("test_ingest_effect_order_is_receipt_before_produced",),
    ),
    Mutation(
        "M08",
        "src/ohpipe/application/ingest.py",
        """            "current_language_assignment_event_digest": plan.language_receipt_digest,
            "current_revision_sha256": None,
""",
        """            "current_revision_sha256": None,
""",
        "eine mutable causal_prestate-Rolle aus RetryIntent entfernen",
        ("test_ingest_retry_intent_keeps_all_mutable_causal_roles",),
    ),
    Mutation(
        "M09",
        "src/ohpipe/cli/main.py",
        '            reason="Zum bezeichneten Digest liegt kein gueltiger persistierter Intentbeleg vor.",\n            reason_code="STOP_B3B_INTENT_ABSENT",\n            check="ohpipe --json status",\n            details={"operation_result": "NONE", "retry_intent": retry},\n        )\n\n    required_fields = {',
        '            reason="Der Digest wird ohne persistierten Intent zugelassen.",\n            reason_code="READY_B3B_NULLDURCHGANG",\n            check="ohpipe --json status",\n            details={"operation_result": "NONE", "retry_intent": retry},\n        )\n\n    required_fields = {',
        "--retry-intent ohne journalfrueheren authentifizierten Intent erlauben",
        ("test_retry_digest_without_persisted_intent_is_a_stop",),
    ),
    Mutation(
        "M10",
        "src/ohpipe/domain/operation.py",
        """    if not trace.causal_prestate_equal or trace.foreign_relevant_in_window:
        return MatrixState.C
    if not actual:
""",
        """    if not trace.causal_prestate_equal:
        return MatrixState.C
    if not actual:
""",
        "Fremdbewegung bei teilweiser eigener Folge aus dem Headvergleich nehmen",
        ("test_partial_effect_with_foreign_window_movement_is_matrix_c",),
    ),
    Mutation(
        "M11",
        "src/ohpipe/domain/operation.py",
        """        if not trace.causal_prestate_equal or trace.foreign_relevant_in_window:
            return MatrixState.G
        return MatrixState.D
""",
        """        if trace.foreign_relevant_after_window:
            return MatrixState.C
        if not trace.causal_prestate_equal or trace.foreign_relevant_in_window:
            return MatrixState.G
        return MatrixState.D
""",
        "vollstaendige Matrix-D-Folge nach spaeterem Fremdappend zu C machen",
        ("test_complete_effect_stays_matrix_d_after_later_foreign_append",),
    ),
    Mutation(
        "M12",
        "src/ohpipe/store.py",
        "            self._fsync_dir(dir_fd)\n            return address",
        "            if False:\n                self._fsync_dir(dir_fd)\n            return address",
        "erforderlichen Verzeichnis-fsync eines neuen Storepfads auslassen",
        ("test_new_store_object_fsyncs_its_directory",),
    ),
    Mutation(
        "M13",
        "src/ohpipe/journal.py",
        "        os.fsync(fd)\n        # Erst NACH fsync merken.",
        "        if False:\n            os.fsync(fd)\n        # Erst NACH fsync merken.",
        "Journal-fsync vor Wirkungsnachweis auslassen",
        ("test_journal_fsync_precedes_effect_return",),
    ),
    Mutation(
        "M14",
        "src/ohpipe/application/fulltext.py",
        "        pre_intent_objects=(plan.raw_bytes,),",
        "        pre_intent_objects=(plan.source_path.read_bytes(),),",
        "Fulltext-Eingangspfad nach Vorschau erneut lesen",
        ("test_fulltext_writer_uses_once_read_plan_bytes",),
    ),
    Mutation(
        "M15",
        "src/ohpipe/application/operation_recovery.py",
        "    with workspace_write_lock(ws.root):",
        "    if True:",
        "einen der sieben Writer ausserhalb der gemeinsamen Sperrordnung schreiben",
        ("test_every_writer_enters_the_common_workspace_lock",),
    ),
    Mutation(
        "M16",
        "src/ohpipe/cli/main.py",
        '        if getattr(args, "confirm", False):',
        '        if False and getattr(args, "confirm", False):',
        "--retry-intent zusammen mit --confirm akzeptieren",
        ("test_retry_intent_and_confirm_are_rejected_together",),
    ),
    Mutation(
        "M17",
        "src/ohpipe/application/status.py",
        "    if uncertain:",
        "    if False and uncertain:",
        "status-Aggregation auf WIRKUNG_UNGEWISS und dessen next rueckwirken lassen",
        ("test_status_surfaces_uncertain_intent_with_retry_next",),
    ),
    Mutation(
        "M18",
        "src/ohpipe/application/iso6393.py",
        "    if existing:",
        "    if False and existing:",
        "nach ISO-Erstbindung erneut Provider oder lokalen Snapshot konsultieren",
        ("test_iso_writer_never_rereads_path_after_preview",),
    ),
    Mutation(
        "M19",
        "src/ohpipe/domain/instance.py",
        '            seq = getattr(event, "seq", 0)',
        '            seq = getattr(event, "at", 0)',
        "Register- oder Actor-Ordnung nach at statt nach seq bestimmen",
        ("test_registry_rejects_at_order_in_place_of_journal_seq",),
    ),
    Mutation(
        "M20",
        "src/ohpipe/domain/confirmation.py",
        "            activation_id=secrets.token_hex(32),",
        '            activation_id="0" * 64,',
        "bei A-zu-B-zu-A die historische activation_id wiederverwenden",
        ("test_new_confirmation_gets_a_fresh_activation_identity",),
    ),
    Mutation(
        "M21",
        "src/ohpipe/domain/language_assignment.py",
        """        if (
            len(language) != 3
""",
        """        language = language or "und"
        if (
            len(language) != 3
""",
        "fehlende language-Werte still auf und setzen",
        ("test_missing_language_is_never_defaulted_to_und",),
    ),
    Mutation(
        "M22",
        "src/ohpipe/domain/language_assignment.py",
        "        if index != canonical_index or digest != expected.sha256:",
        "        if index != canonical_index:",
        "segment_sha256 einer Mappingzeile bei der Zuordnung ignorieren",
        ("test_mapping_segment_digest_is_not_ignored",),
    ),
    Mutation(
        "M23",
        "src/ohpipe/application/ingest.py",
        '    if re.fullmatch(r"[0-9a-f]{64}", language_receipt_digest) is None:',
        '    if False and re.fullmatch(r"[0-9a-f]{64}", language_receipt_digest) is None:',
        "Ingest verwendet einen nicht aktuellen Sprach-Receipt",
        ("test_ingest_requires_a_full_current_language_receipt_digest",),
    ),
    Mutation(
        "M24",
        "src/ohpipe/application/transcript_language.py",
        "    intent, written = execute_intent(",
        "    intent, written = (_intent(ws, plan), ()) if True else execute_intent(",
        "transcript_language_prepare schreibt ohne Intent- oder Sperrbindung",
        ("test_language_prepare_writer_is_intent_bound",),
    ),
)


def b3b_main(argv: list[str]) -> int:
    """Vorcommit-Mutanten gegen die bytegebundene uncommittete B3b-Baseline."""
    selected = [m for m in B3B_MUTANTEN if not argv or m.id in argv]
    if not selected:
        print(f"Keine B3b-Mutation passt auf {argv}.")
        return HALT_VOR_GRUNDLAUF
    targets = sorted({m.datei for m in B3B_MUTANTEN})
    baseline = {name: (REPO / name).read_bytes() for name in targets}
    for mutation in selected:
        text = baseline[mutation.datei].decode("utf-8")
        count = text.count(mutation.alt)
        if count != 1:
            print(f"HALT {mutation.id}: Ausgangsmuster {count}x statt genau 1x.")
            return HALT_VOR_GRUNDLAUF

    command = [
        sys.executable,
        "-m",
        "pytest",
        "-o",
        "addopts=",
        "-q",
        "-p",
        "no:cacheprovider",
        "tests/test_b3b_no_side_effect_preview.py",
    ]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    base_run = subprocess.run(command, cwd=REPO, env=env, capture_output=True, text=True)
    if base_run.returncode != 0:
        print("HALT: B3b-Mutanten-Grundlauf ist rot.", base_run.stdout, base_run.stderr)
        return HALT_VOR_GRUNDLAUF
    print("B3b-Mutanten-Grundlauf: 27 passed, rc 0.")

    failures: list[str] = []

    def restore() -> None:
        for name, body in baseline.items():
            (REPO / name).write_bytes(body)

    def signal_restore(signum, _frame):
        restore()
        raise SystemExit(128 + signum)

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, signal_restore)

    try:
        for mutation in selected:
            restore()
            target = REPO / mutation.datei
            before = baseline[mutation.datei]
            mutated = before.decode("utf-8").replace(mutation.alt, mutation.neu).encode("utf-8")
            target.write_bytes(mutated)
            run = subprocess.run(command, cwd=REPO, env=env, capture_output=True, text=True)
            output = run.stdout + run.stderr
            killed = sorted(set(re.findall(r"FAILED\s+([^\s]+)", output)))
            expected = all(any(name in node for node in killed) for name in mutation.faellt)
            restored_sha = ""
            patch = "".join(
                difflib.unified_diff(
                    before.decode().splitlines(keepends=True),
                    mutated.decode().splitlines(keepends=True),
                    fromfile=f"a/{mutation.datei}",
                    tofile=f"b/{mutation.datei}",
                )
            ).rstrip()
            restore()
            restored_sha = hashlib.sha256(target.read_bytes()).hexdigest()
            baseline_sha = hashlib.sha256(before).hexdigest()
            mutation_sha = hashlib.sha256(mutated).hexdigest()
            print(
                f"{mutation.id} {mutation.was}\n"
                f"PFAD {mutation.datei}\n"
                f"BASELINE {baseline_sha}\nMUTATION {mutation_sha}\n"
                f"PATCH\n{patch}\n"
                f"KOMMANDO {' '.join(command)}\nRC {run.returncode}\n"
                f"KILLLISTE {killed}\nWIEDERHERSTELLUNG {restored_sha}"
            )
            if run.returncode == 0 or not expected or restored_sha != baseline_sha:
                failures.append(mutation.id)
    finally:
        restore()

    residual = [name for name in targets if (REPO / name).read_bytes() != baseline[name]]
    if failures or residual:
        print(f"MUTATIONSBEFUND failures={failures} residual={residual}")
        return 1
    print(
        f"{len(selected)} B3b-Pflichtmutanten, alle fachlich gefallen und bytegleich restauriert."
    )
    return 0


if __name__ == "__main__":
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "--b3b-precommit":
        raise SystemExit(b3b_main(arguments[1:]))
    raise SystemExit(main(arguments))
