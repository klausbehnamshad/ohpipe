# Historical contract matrix and preview scope

The historical B3b matrix is retained as an unresolved compatibility specification. A failed comparison is neither automatically a product vulnerability nor automatically a harmless test defect. The preview does not claim conformance to the complete matrix.

The 520 failing matrix cases were reviewed by their actual entry point and captured observations:

| Exercised boundary | Cases | What the comparison establishes |
|---|---:|---|
| Domain APIs | 275 | Typed returns or exceptions are often compared with operator-report fields. Several fixtures call a parser instead of exercising the workflow named by the requirement. |
| CLI | 99 | Includes changed report contracts and incomplete or invalid setup arguments. `LNG-81` calls `init`; its workspace-initialization event is an intended effect. |
| Replay | 5 | A single unauthenticated decision returns a record mapping containing `STOP`. These fixtures do not establish the actor chronology named in their requirements. |
| Confirmation writer | 7 | Constructed plans exposed missing checks before effects. The actual CLI confirmation window was reproduced and corrected; see below. |
| Recovery classification | 134 | Compares a report for a supplied recovery trace. These calls do not execute recovery writes. |

Thirteen further failures concern nine fixed historical source fingerprints, two static matrix checks and two older checks of the matrix representation. They remain visible. No test was deleted or marked as expected-failing merely to make CI green.

## Confirmation window correction

Before correction, retiring the selected human during the confirmation prompt still allowed a confirmation to be written. An automatically selected group could also change and return to its earlier membership unnoticed. Tests now cover those cases, a changed or reasserted transcript revision, and competing confirmation plans.

The writer rechecks the relevant state under the common writer lock before persisting an intent, marker or decision. Stale plans return `ACTION_B3B_CONFIRMATION_STALE` without confirmation effects. Tests retain valid explicit selection despite an unrelated human registration, an unrelated machine registration, exact retry and a fresh preview. One case uses another actual process during the prompt. These 20 tests use invented material and a newly generated journal key.

Seven existing relational-intent checks now prepare an authenticated transcript and registered human instead of inventing state references. Their deterministic comparison and mutation counterchecks are retained. The seven original matrix cases remain unchanged and still fail the historical contract comparison.

## Operational limits

The demonstrated entry point is the synthetic catalog workflow. The manual pseudonymisation path has separate synthetic tests and closed profile identities. This is an experimental software preview, not an assertion of general operational readiness.

The complete historical recovery contract and an end-to-end `--retry-intent` recovery workflow are not delivered by this preview. Normal-command idempotence and specific repair paths are tested separately. Do not infer general crash recovery from those results.

The historical pseudonymisation cases have a separate [mapping](ATTACK-TEST-MAPPING.md). The current checks do not establish model accuracy, exhaustive identifier detection, every old attack scenario or project authorization. See [Testing](TESTING.md) for measured results and [Governance](GOVERNANCE.md) for project responsibility.
