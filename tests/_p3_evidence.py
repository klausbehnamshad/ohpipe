"""Ausgeschriebene Quellen für synthetische Evidenztests; keine Produktableitung."""

INPUTS = {
    "transcript.revision": (),
    "transcript.confirmed": ("transcript.revision",),
    "l1.suggestions": ("transcript.confirmed", "transcript.revision"),
    "l1.coverage": ("l1.suggestions", "transcript.confirmed", "transcript.revision"),
    "l1.adjudicated": ("l1.suggestions", "l1.coverage"),
    "metadata.draft": ("l1.adjudicated",),
    "metadata.confirmed": ("metadata.draft",),
    "abstract.draft": ("l1.adjudicated", "metadata.confirmed"),
    "abstract.confirmed": ("abstract.draft",),
    "analysis.draft": ("l1.adjudicated",),
    "analysis.confirmed": ("analysis.draft",),
    "release.preview": ("metadata.confirmed", "abstract.confirmed", "l1.adjudicated"),
    "release.approved": ("release.preview",),
    "export.bundle": ("release.approved",),
    "analysis.approved": ("analysis.confirmed",),
    "analysis.bundle": ("analysis.approved",),
}


def bindings(artifact, sha):
    if artifact == "transcript.confirmed":
        return {"input_refs": {"transcript": sha}}
    if not INPUTS[artifact]:
        return {}
    return {
        "input_refs": {role: sha for role in INPUTS[artifact]},
        "input_refs_version": 3,
        "profile_id": "sandbox",
        "graph_sha256": "bcc5a96b8625c90e6ef73bdf505eda151109e16b804cf84a99c7f942b25463be",
    }


def ancestors(artifact):
    result = set()
    pending = list(INPUTS[artifact])
    while pending:
        role = pending.pop()
        if role not in result:
            result.add(role)
            pending.extend(INPUTS[role])
    return result
