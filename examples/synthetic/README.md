# Synthetic demonstration

These transcripts are invented fixtures. They are not real interview material or a benchmark for model quality.

After creating `.venv` and installing the package, run from the checkout root:

```bash
bash examples/synthetic/durchstich.sh
```

The script checks 48 numbered stations with recorded model responses. It includes deliberate stops, human confirmations, rejection of an incomplete response, a synthetic catalog bundle, a transcript correction and invalidation of obsolete outputs. It ends by changing the release decision so the old bundle becomes `STALE`. Each command has an expected exit code; an unexpected result aborts the script.

The sandbox profile does not require pseudonymisation. This demo does not measure identification or removal of identifying information. The manual path has separate synthetic integration tests.

The fixtures contain German, Luxembourgish and French. One cue contains code-switching. The assignment format carries one language per segment: an explicit simplification, not a rewriting of the spoken text. Every cue has a speaker prefix, as required by the input contract.

The run creates and deletes its own temporary directory outside the checkout. Set `OHPIPE_DURCHSTICH_BEHALTEN=1` to retain it for inspection. The script loads the current checkout's source; installed-wheel behavior is checked separately.
