"""Parse the two historical model-probe log records used by regression tests.

Extracted unchanged from the internal pilot runner. Parsing a record does not
authenticate it or establish model quality. No model service is called here.
"""

import json


def local_model_proofs(log):
    prefix = "WALZ_LOCAL_MODEL_PROOF "
    proof_lines = []
    for line in log.splitlines():
        candidate = line.lstrip(".")
        if candidate.startswith(prefix):
            proof_lines.append(candidate.removeprefix(prefix))
    assert len(proof_lines) == 2
    return sorted((json.loads(line) for line in proof_lines), key=lambda item: item["probe"])
