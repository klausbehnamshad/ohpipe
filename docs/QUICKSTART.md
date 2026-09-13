# Synthetic quickstart

Use Python 3.11+, Bash and a POSIX system. From the checkout root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/ohpipe --help
bash examples/synthetic/durchstich.sh
```

The demonstration loads this checkout's code, creates a random journal key and a temporary data directory, and checks every expected result. It uses invented material. The key and data are removed when finished unless retention is requested:

```bash
OHPIPE_DURCHSTICH_BEHALTEN=1 bash examples/synthetic/durchstich.sh
```

The final message identifies the retained directory. It is not a release attachment.

To inspect an empty workspace outside the checkout:

```bash
demo_root=$(mktemp -d)
.venv/bin/ohpipe --profile sandbox --root "$demo_root/data" init
.venv/bin/ohpipe --profile sandbox --root "$demo_root/data" doctor
.venv/bin/ohpipe --profile sandbox --root "$demo_root/data" status
```

| Exit code | Meaning |
|---|---|
| 0 | Ready for the command's stated purpose |
| 1 | Stop: a blocking finding or failed operation |
| 2 | Configuration or usage problem |
| 3 | Human action or another workflow step is needed |

The full demonstration supplies the synthetic inputs, authentication and confirmations needed for its later stages. A `READY` label is not scientific validation or project authorization. Some diagnostics and technical reference documents remain in German.

For development checks:

```bash
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest --ignore=tests/test_ollama_live.py
```

The complete suite has known historical failures. See [TESTING.md](TESTING.md). Excluding the live-model module before collection prevents its availability probe from running.
