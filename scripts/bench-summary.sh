#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

usage() {
	cat <<'EOF'
Usage: scripts/bench-summary.sh [--mode MODE] [--metric median|mean]

Print a compact table from Criterion output in target/criterion.

Options:
  --mode MODE            matches, finds, finds-prepared, all (default: all)
  --metric NAME          median or mean (default: median)
  -h, --help             Show help

Examples:
  scripts/bench-summary.sh
  scripts/bench-summary.sh --mode finds-prepared
EOF
}

mode="all"
metric="median"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--mode)
		mode="$2"
		shift 2
		;;
	--metric)
		metric="$2"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "error: unknown argument: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

case "$metric" in
median | mean) ;;
*)
	echo "error: invalid --metric '$metric' (median|mean)" >&2
	exit 2
	;;
esac

case "$mode" in
matches)
	benches=(
		"scan_pe64/matches_code/jump4"
		"scan_pe64/matches_code/alternation"
		"scan_elf64/matches_code/push_pop"
		"scan_elf64/matches_code/jump1"
		"scan_pe64/matches_code/jump4_tiny"
		"scan_elf64/matches_code/jump4_tiny"
	)
	;;
finds)
	benches=(
		"scan_pe64/finds_code/jump4"
		"scan_pe64/finds_code/alternation"
		"scan_elf64/finds_code/push_pop"
		"scan_elf64/finds_code/jump1"
		"scan_pe64/finds_code/jump4_tiny"
		"scan_elf64/finds_code/jump4_tiny"
	)
	;;
finds-prepared)
	benches=(
		"scan_pe64/finds_prepared/jump4"
		"scan_pe64/finds_prepared/alternation"
		"scan_elf64/finds_prepared/push_pop"
		"scan_elf64/finds_prepared/jump1"
		"scan_pe64/finds_prepared/jump4_tiny"
		"scan_elf64/finds_prepared/jump4_tiny"
	)
	;;
all)
	benches=(
		"scan_pe64/matches_code/jump4"
		"scan_pe64/matches_code/alternation"
		"scan_elf64/matches_code/push_pop"
		"scan_elf64/matches_code/jump1"
		"scan_pe64/matches_code/jump4_tiny"
		"scan_elf64/matches_code/jump4_tiny"
		"scan_pe64/finds_code/jump4"
		"scan_pe64/finds_code/alternation"
		"scan_elf64/finds_code/push_pop"
		"scan_elf64/finds_code/jump1"
		"scan_pe64/finds_code/jump4_tiny"
		"scan_elf64/finds_code/jump4_tiny"
		"scan_pe64/finds_prepared/jump4"
		"scan_pe64/finds_prepared/alternation"
		"scan_elf64/finds_prepared/push_pop"
		"scan_elf64/finds_prepared/jump1"
		"scan_pe64/finds_prepared/jump4_tiny"
		"scan_elf64/finds_prepared/jump4_tiny"
	)
	;;
*)
	echo "error: invalid --mode '$mode' (matches|finds|finds-prepared|all)" >&2
	exit 2
	;;
esac

python3 - "$metric" "${benches[@]}" <<'PY'
import json
import pathlib
import sys

metric = sys.argv[1]
benches = sys.argv[2:]
root = pathlib.Path("target/criterion")


def fmt_ns(ns: float) -> str:
    if ns >= 1_000_000_000:
        return f"{ns / 1_000_000_000:.2f}s"
    if ns >= 1_000_000:
        return f"{ns / 1_000_000:.2f}ms"
    if ns >= 1_000:
        return f"{ns / 1_000:.2f}us"
    return f"{ns:.2f}ns"


print(f"{'benchmark':50} {'time':>12} {'delta':>10}")
print("-" * 75)

for bench in benches:
    bench_dir = root / bench
    est_path = bench_dir / "new" / "estimates.json"
    if not est_path.exists():
        print(f"{bench:50} {'(missing)':>12} {'-':>10}")
        continue

    data = json.loads(est_path.read_text())
    time_ns = float(data[metric]["point_estimate"])

    change_path = bench_dir / "change" / "estimates.json"
    if change_path.exists():
        change = json.loads(change_path.read_text())
        delta = float(change[metric]["point_estimate"]) * 100.0
        delta_str = f"{delta:+.2f}%"
    else:
        delta_str = "-"

    print(f"{bench:50} {fmt_ns(time_ns):>12} {delta_str:>10}")
PY
