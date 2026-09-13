"""Gemeinsame Speicherzuständigkeit pro Rolle und Referenz, nicht pro Hash."""

from ohpipe.domain import manual_context

from ..domain.p4b_events import ROLES
from ..protected_store import ProtectedStore, ProtectionError, ProtectionConfig


class ProtectionConfigurationFinding(str):
    """Fehlende Auswahl bleibt typisiert; andere Leser halten weiterhin an.

    Nur continue unterscheidet diesen Befund von Integritätsbefunden. Die
    Liste bleibt für bestehende Schutzprüfungen wahr und JSON-serialisierbar.
    """


class RegistryConfigurationFinding(ProtectionConfigurationFinding):
    """Fehlende P4c-Auswahl blockiert P4c, nicht die vorgelagerte P4b-Fallarbeit."""


def check_referenced(ws, view):
    from ..registry_store import ROLES as P4C_ROLES, RegistryStore, REGISTRY

    normal, protected, p4c = set(), set(), set()

    def add(role, sha):
        if not sha:
            return
        if manual_context.known(view.graph.profile_id) and role in P4C_ROLES:
            p4c.add((role, sha))
        elif manual_context.known(view.graph.profile_id) and role in ROLES.values():
            protected.add((role, sha))
        else:
            normal.add(sha)

    for role, (sha, _) in view.sources.items():
        add(role, sha)
    for d in view.effective_decision_by_artifact.values():
        add(d.artifact, d.subject_sha256)
        for role, sha in d.input_refs.items():
            add(role, sha)
    for role, f in view.facts.items():
        for sha in (f.sha256, f.receipt_for, f.decided_sha):
            add(role, sha)
        for source, sha in f.receipt_inputs.items():
            add(source, sha)
    findings = ws.store().check_referenced(normal)
    p4c_refs = [r for r in view.protected_refs if r["aad"]["domain"] == "ohpipe:p4c:protected"]
    p4b_refs = [r for r in view.protected_refs if r["aad"]["domain"] != "ohpipe:p4c:protected"]
    if p4c or p4c_refs:
        try:
            registry = RegistryStore(ws)
            for ref in p4c_refs:
                registry.check(ref, None if ref["role"] == REGISTRY else view.record_id)
            index = {(r["role"], r["sha256"]) for r in view.protected_artifacts if r in p4c_refs}
            if p4c - index:
                raise ProtectionError("P4c-Schutzverweis fehlt")
            head = registry.head()
            if head is None or head not in p4c_refs:
                raise ProtectionError("Registerkopf fehlt oder ist fremd")
        except ProtectionConfig as exc:
            findings.append(RegistryConfigurationFinding(str(exc)))
        except (ProtectionError, OSError):
            findings.append("P4c-Speicher-/Zugriffsprüfung fehlgeschlagen; Inhalt nicht entsiegelt")
    if not protected and not p4b_refs:
        return findings
    try:
        store = ProtectedStore(ws)
        for ref in p4b_refs:
            store.check(ref, view.record_id)
        index = {}
        for ref in view.protected_artifacts:
            if ref["aad"]["domain"] == "ohpipe:p4c:protected":
                continue
            if ref not in view.protected_refs:
                raise ProtectionError("Abgeschlossener Schutzverweis ohne Speicherbeleg")
            index[(ref["role"], ref["sha256"])] = ref
        if protected - set(index):
            raise ProtectionError("Authentifizierter Schutzverweis fehlt")
    except ProtectionConfig as exc:
        findings.append(ProtectionConfigurationFinding(str(exc)))
    except (ProtectionError, OSError):
        findings.append("P4b-Speicher-/Zugriffsprüfung fehlgeschlagen; Inhalt nicht entsiegelt")
    return findings
