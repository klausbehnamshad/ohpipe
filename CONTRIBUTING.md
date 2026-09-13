# Contributing

Use synthetic examples only. Do not contribute interview material, operational journals, keys or private approvals.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest --ignore=tests/test_ollama_live.py
.venv/bin/ruff check src tests tools
```

The full suite has known failures. State which tests you ran and compare relevant results with [Testing](docs/TESTING.md). Do not delete failures or add expected-failure markers merely to obtain green CI. Changes to review, exclusion, identity or data handling need a failing example and a valid-case counterexample.

Explain the observable behavior, scope and validation. Keep workflow evidence separate from scientific-validity claims. Historical reference fixtures preserve independent expected behavior; change them only alongside a documented change to that behavior.

Use [SECURITY.md](SECURITY.md) for security reports.
