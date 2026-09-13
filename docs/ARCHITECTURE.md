# Architecture

OHPIPE separates immutable material, recorded events and computed workflow state.

```mermaid
flowchart LR
    A[Transcript material] --> B[Version and source binding]
    B --> C[Descriptive proposals]
    C --> D[Human review]
    D --> E[Reviewed catalog draft]
    E --> F[Release decision]
    F --> G[JSON bundle]
```

This is the synthetic catalog path. Profiles requiring manual pseudonymisation insert marking, case review, entity resolution, deterministic replacement and full-text review before descriptive processing. Their protected material is held in configured external stores. The sandbox path does not provide that protection.

The journal records proposals, receipts and decisions as distinct events. State is computed by replaying them against the profile's graph. An output can become stale when relevant inputs or decisions change. Recorded evidence is checked against the material it references.

Hashing identifies bytes. Journal authentication establishes that a writer held the configured key; it does not establish a person's identity or validate a claimed project approval.

The metadata model is package data under `src/ohpipe/schemas/metadata/`. Its DCTAP supplies field definitions and the JSON schema is checked for drift. The model does not decide whether data may be processed or published.

OHPIPE and DINOH Evaluation are separate components. Evaluation data and results are not automatically transferred into a pipeline workspace. Installing this repository does not provision a reviewed operational deployment. See [Testing](TESTING.md) and [Profiles](PROFILES.md).
