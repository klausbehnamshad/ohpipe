# OHPIPE

**A research workflow for oral-history transcripts, descriptive proposals and human review.**

OHPIPE is the pipeline component of **DINOH**, an infrastructure for working with oral-history material. The wider project brings together OHPIPE, the separate [DINOH Evaluation](https://github.com/klausbehnamshad/DINOH) laboratory, the IMM metadata model and shared methodological documentation.

This repository is an **experimental public preview**. Its entry point is a reproducible demonstration with invented transcripts and recorded model responses. The code also contains a manual pseudonymisation workflow and model-adapter interfaces. The full test suite still contains known failures, documented in [Testing and limitations](docs/TESTING.md).

## Try the synthetic workflow

Use Python 3.11+ and a POSIX environment with Bash. Development checks have run locally on macOS/arm64 with Python 3.13.9; the accompanying GitHub workflow is configured for Linux/Python 3.11. Windows is not a supported target for this preview.

```bash
git clone https://github.com/klausbehnamshad/ohpipe.git
cd ohpipe
python3 -m venv .venv
.venv/bin/python -m pip install -e .
bash examples/synthetic/durchstich.sh
```

No model download or inference service is needed. The script creates a temporary workspace outside the checkout and removes it when finished. Some steps deliberately stop for review or reject an incomplete response; the script checks each expected exit code. The final `STALE` state demonstrates that changing a release decision invalidates the old bundle.

See the [demo guide](examples/synthetic/README.md) and [quickstart](docs/QUICKSTART.md).

## What the preview demonstrates

- Versioned transcript material with explicit language assignments and source bindings.
- Descriptive proposals kept distinct from human acceptance decisions.
- Review gates and checks for changed inputs, decisions and derived artifacts.
- A synthetic catalog workflow using IMM metadata fields and a JSON bundle output.

The manual workflow supports marking, case review, explicit entity resolution, deterministic replacement and review of the resulting text. It currently uses a closed set of named profiles and external protected stores. It has synthetic integration tests; the simple sandbox demo does **not** exercise it. See [Profiles and manual review](docs/PROFILES.md).

Recorded responses demonstrate workflow behavior, not model performance. Coverage figures describe the pipeline's defined coverage measure; they are not accuracy scores. Provenance can show which material and decisions an output depends on. It does not establish the scientific validity of an interpretation.

## Project responsibility

OHPIPE is intended for projects whose applicable data-protection, ethics and access requirements have been addressed before use. The controller or joint controllers remain responsible for project decisions. Software settings and review receipts do not confer legal authorization. Details are in [Governance](docs/GOVERNANCE.md).

The pilot completed on 13 September 2026 covered one transcript through reviewed descriptive proposals. That endpoint does not establish export readiness, general model quality or suitability for other projects.

## Documentation and development

- [Architecture](docs/ARCHITECTURE.md)
- [Testing and known limitations](docs/TESTING.md)
- [Historical attack-test mapping](docs/ATTACK-TEST-MAPPING.md)
- [Roadmap](docs/ROADMAP.md)
- [Contributing](CONTRIBUTING.md) and [security reports](SECURITY.md)
- [Changes](CHANGELOG.md) and [citation metadata](CITATION.cff)

Code is provided under the [MIT license](LICENSE). The bundled IMM-Core metadata files have separate attribution and CC-BY-4.0 terms; see [Third-party notices](THIRD_PARTY_NOTICES.md).
