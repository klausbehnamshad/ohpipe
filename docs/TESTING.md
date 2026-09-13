# Testing and limitations

This preview distinguishes a working synthetic demonstration from a fully passing test suite. **The complete historical suite is not green.** GitHub's full-suite job runs the failures as well and does not mask its exit code. A passing package or lint job is not a substitute for that result.

## Reproduce the checks

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]' build
.venv/bin/python -m pytest --ignore=tests/test_ollama_live.py
bash examples/synthetic/durchstich.sh
.venv/bin/python -m build
```

Exclude the live-model module before test collection; it otherwise probes a local service. Adapter tests use fixtures and test servers. No model-quality conclusion follows from them.

The source correction was measured on macOS/arm64 with Python 3.13.9 and pytest 9.1.1. The public checkout was measured separately; see [VALIDATION.json](../VALIDATION.json). The GitHub workflow is configured for Linux/Python 3.11; configuration alone does not establish a successful hosted run.

## Measured local results — 13 September 2026

| Check | Passed | Failed | Expected failures |
|---|---:|---:|---:|
| Corrected source | 2,374 | 533 | 26 |
| Curated public checkout, before confirmation-window correction | 2,371 | 533 | 26 |
| Reviewed alpha candidate | 2,403 | 533 | 26 |

All shared test nodes have the same outcome. Eleven GitLab-specific CI cases were replaced by eight GitHub CI cases, explaining the count difference. The designated 493-test protection selection passes in both trees; it does not cover every security-relevant test.

Two dependencies exposed by curation were corrected before the final public run: the technical reference again states its limited scope, and the unchanged log parser is available without the internal pilot runner. Synthetic fixture labels were also clarified. All 271 tests in the affected modules passed separately.

The 48-stage synthetic workflow passes from source and from an installed wheel outside the checkout. Metadata resources load there with all 13 fields. These are workflow and packaging checks, not model-quality measurements.

The reviewed alpha adds 20 confirmation-window and 12 storage-placement checks. All pass. Shared test outcomes remain unchanged; the historical matrix still fails. Seven existing relational-intent tests were ported to valid authenticated setup while retaining their mutation counterchecks. [Contract scope](CONTRACT-SCOPE.md) explains the actual exercised boundaries, the additional correction and the recovery-workflow limit.

## Three corrected replay defects

The preview makes three earlier expected failures into ordinary regression tests, with their valid-case counterexamples retained:

- A disposition event in a journal without authentication cannot confer exclusion.
- An anchor outcome without preceding artifact bytes cannot establish a source binding.
- A record exclusion must name an artifact in the profile graph before taking effect. A malformed decision still receives the appropriate decision diagnostic first.

These corrections do not establish completeness of the replay threat model.

## Historical failures retained

The B3b tests retain an older contract matrix: **520 failing contract cases**, **11 failing structure/binding checks**, and **two related matrix checks** in `test_release_blockers.py` were measured at the baseline. Differences include direct domain return values versus operator reports, invalid test record identifiers, and a fixed historical source fingerprint. These are not all treated as harmless, nor are expected values automatically replaced with current output.

The **25 remaining historical pseudonymisation expected failures** refer to earlier APIs, representations or test preconditions. [ATTACK-TEST-MAPPING.md](ATTACK-TEST-MAPPING.md) identifies related tests of the current manual workflow and the limits of that mapping. These cases remain visible. One further expected failure concerns recovery guidance in three operator messages.

The large `b3b-norm-coverage.json` file is retained as the synthetic contract fixture required by these tests. It is not an evaluation corpus or a certification. The German serialization reference preserves technical contracts and vectors required by regression tests; private decision records are not distributed.

## What is not established

- Model accuracy, recall of identifying information or validity of research interpretations.
- Exhaustive protection against malicious operators, all file-system attacks or all forms of data leakage.
- Equivalence of every historical attack case with a current test.
- General operational suitability, a completed deployment review or export readiness for real projects.

The standard demo uses the sandbox profile without mandatory pseudonymisation. The separate manual tests use invented material, temporary keys and external stores. A successful test only establishes its stated condition within that setup.
