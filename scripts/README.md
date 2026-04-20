# Perf Scripts

Quick benchmark matrix run:

```bash
scripts/bench-key.sh
```

Run only finds_prepared benchmarks:

```bash
scripts/bench-key.sh --mode finds-prepared
```

Print a compact Criterion summary table:

```bash
scripts/bench-summary.sh --mode finds-prepared
```

Run local perf smoke check against a saved baseline:

```bash
scripts/perf-smoke.sh --baseline scanner-main --mode matches
```

Save a baseline (run on checkout A):

```bash
scripts/bench-ab.sh --name scanner-ab --phase save --runs 3
```

Compare against saved baseline (run on checkout B):

```bash
scripts/bench-ab.sh --name scanner-ab --phase compare --runs 3
```

Tune criterion settings:

```bash
scripts/bench-key.sh --sample-size 20 --measurement-time 5
```

## Reproducible Benchmarking Notes

To reduce ratio swings between runs, keep benchmark settings and machine state
as stable as possible.

- Prefer the default bench profile in `scripts/bench-key.sh` (`--sample-size 30 --measurement-time 8`).
- Compare branches with the same run shape via `scripts/bench-ab.sh --runs 3`.
- Close background CPU-heavy apps before runs.
- Keep power settings stable (plugged-in laptop, no battery saver mode).
- On Linux, pin to a fixed CPU core when practical, for example:

```bash
taskset -c 2 scripts/bench-key.sh --mode finds-prepared
```

- On Linux, prefer a fixed governor for perf work (for example `performance`).
- On macOS, there is no direct governor toggle; run with stable thermals and repeat A/B runs.

For interpreter-friendly output after each run, use:

```bash
scripts/bench-summary.sh --mode all
scripts/bench-pelite-summary.sh --group all
```

Run a scanner flamegraph with sigscan:

```bash
scripts/flamegraph-scan.sh -- fixtures/memflow_coredump.x86_64.dll "48 8B 0D ${'}"
```

Write flamegraph to a specific file:

```bash
scripts/flamegraph-scan.sh --output perf.svg -- fixtures/libmemflow_coredump.x86_64.so "55 41 57"
```

Run the goblin-sigscan vs pelite PE benchmark:

```bash
cargo bench -p goblin-sigscan --bench pelite_compare
```

Print goblin-sigscan vs pelite benchmark ratios:

```bash
scripts/bench-pelite-summary.sh
```

Show only first-match ratios:

```bash
scripts/bench-pelite-summary.sh --group first-match
```
