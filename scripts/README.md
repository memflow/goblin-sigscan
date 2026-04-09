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

Run a scanner flamegraph with sigscan:

```bash
scripts/flamegraph-scan.sh -- fixtures/memflow_coredump.x86_64.dll "48 8B 0D ${'}"
```

Write flamegraph to a specific file:

```bash
scripts/flamegraph-scan.sh --output perf.svg -- fixtures/libmemflow_coredump.x86_64.so "55 41 57"
```
