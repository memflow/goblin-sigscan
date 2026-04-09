#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

usage() {
	cat <<'EOF'
Usage: scripts/bench-pelite-summary.sh [--group GROUP] [--metric median|mean]

Print a compact goblin-lite vs pelite ratio table from Criterion output.

Options:
  --group NAME           first-match, all-matches, all (default: all)
  --metric NAME          median or mean (default: median)
  -h, --help             Show help

Examples:
  scripts/bench-pelite-summary.sh
  scripts/bench-pelite-summary.sh --group first-match
  scripts/bench-pelite-summary.sh --metric mean
EOF
}

group="all"
metric="median"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--group)
		group="$2"
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

case "$group" in
first-match | all-matches | all) ;;
*)
	echo "error: invalid --group '$group' (first-match|all-matches|all)" >&2
	exit 2
	;;
esac

case "$metric" in
median | mean) ;;
*)
	echo "error: invalid --metric '$metric' (median|mean)" >&2
	exit 2
	;;
esac

python3 - "$group" "$metric" <<'PY'
import json
import pathlib
import sys

group = sys.argv[1]
metric = sys.argv[2]
root = pathlib.Path("target/criterion")
cases = ["jump4_tiny", "jump4", "alternation", "skip_range"]

groups = [
    ("first-match", "pe64_compare_first_match"),
    ("all-matches", "pe64_compare_all_matches"),
]
if group != "all":
    groups = [item for item in groups if item[0] == group]


def fmt_ns(ns: float) -> str:
    if ns >= 1_000_000_000:
        return f"{ns / 1_000_000_000:.2f}s"
    if ns >= 1_000_000:
        return f"{ns / 1_000_000:.2f}ms"
    if ns >= 1_000:
        return f"{ns / 1_000:.2f}us"
    return f"{ns:.2f}ns"


def point_estimate(path: pathlib.Path) -> float | None:
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    return float(data[metric]["point_estimate"])


print(f"{'group':12} {'pattern':12} {'goblin-lite':>12} {'pelite':>12} {'ratio':>8} {'delta':>9}")
print("-" * 74)

for group_name, dir_name in groups:
    for case in cases:
        goblin_path = root / dir_name / "goblin-lite" / case / "new" / "estimates.json"
        pelite_path = root / dir_name / "pelite" / case / "new" / "estimates.json"
        goblin = point_estimate(goblin_path)
        pelite = point_estimate(pelite_path)

        if goblin is None or pelite is None:
            print(f"{group_name:12} {case:12} {'(missing)':>12} {'(missing)':>12} {'-':>8} {'-':>9}")
            continue

        ratio = goblin / pelite
        delta = (ratio - 1.0) * 100.0
        print(
            f"{group_name:12} {case:12} {fmt_ns(goblin):>12} {fmt_ns(pelite):>12} {ratio:>8.2f}x {delta:>+8.1f}%"
        )
PY
