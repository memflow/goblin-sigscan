#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

usage() {
	cat <<'EOF'
Usage: scripts/perf-smoke.sh --baseline NAME [options]

Run a small local perf smoke check and warn on large regressions.

Options:
  --baseline NAME        Criterion baseline name to compare against (required)
  --mode NAME            matches, finds, finds-prepared, all (default: matches)
  --threshold PCT        Warn when median delta exceeds this percent (default: 5)
  --sample-size N        Criterion sample size (default: 10)
  --measurement-time S   Criterion measurement time seconds (default: 1)
  -h, --help             Show help

Example:
  scripts/perf-smoke.sh --baseline scanner-main --mode finds-prepared
EOF
}

baseline=""
mode="matches"
threshold="5"
sample_size="10"
measurement_time="1"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--baseline)
		baseline="$2"
		shift 2
		;;
	--mode)
		mode="$2"
		shift 2
		;;
	--threshold)
		threshold="$2"
		shift 2
		;;
	--sample-size)
		sample_size="$2"
		shift 2
		;;
	--measurement-time)
		measurement_time="$2"
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

if [[ -z "$baseline" ]]; then
	echo "error: --baseline is required" >&2
	usage >&2
	exit 2
fi

./scripts/bench-key.sh \
	--mode "$mode" \
	--baseline "$baseline" \
	--sample-size "$sample_size" \
	--measurement-time "$measurement_time"

./scripts/bench-summary.sh --mode "$mode" --metric median

python3 - "$mode" "$threshold" <<'PY'
import json
import pathlib
import sys

mode = sys.argv[1]
threshold = float(sys.argv[2])
root = pathlib.Path("target/criterion")

groups = {
    "matches": [
        "scan_pe64/matches_code/jump4",
        "scan_pe64/matches_code/alternation",
        "scan_elf64/matches_code/push_pop",
        "scan_elf64/matches_code/jump1",
        "scan_pe64/matches_code/jump4_tiny",
        "scan_elf64/matches_code/jump4_tiny",
    ],
    "finds": [
        "scan_pe64/finds_code/jump4",
        "scan_pe64/finds_code/alternation",
        "scan_elf64/finds_code/push_pop",
        "scan_elf64/finds_code/jump1",
        "scan_pe64/finds_code/jump4_tiny",
        "scan_elf64/finds_code/jump4_tiny",
    ],
    "finds-prepared": [
        "scan_pe64/finds_prepared/jump4",
        "scan_pe64/finds_prepared/alternation",
        "scan_elf64/finds_prepared/push_pop",
        "scan_elf64/finds_prepared/jump1",
        "scan_pe64/finds_prepared/jump4_tiny",
        "scan_elf64/finds_prepared/jump4_tiny",
    ],
    "all": [],
}

if mode == "all":
    benches = groups["matches"] + groups["finds"] + groups["finds-prepared"]
else:
    benches = groups.get(mode)
    if benches is None:
        print(f"error: invalid mode {mode}", file=sys.stderr)
        sys.exit(2)

regressions = []
for bench in benches:
    path = root / bench / "change" / "estimates.json"
    if not path.exists():
        continue
    data = json.loads(path.read_text())
    delta = float(data["median"]["point_estimate"]) * 100.0
    if delta > threshold:
        regressions.append((bench, delta))

if regressions:
    print("WARN: perf smoke regression(s) over threshold:")
    for bench, delta in regressions:
        print(f"  {bench}: +{delta:.2f}%")
    sys.exit(1)

print(f"OK: no median regressions above +{threshold:.2f}%")
PY
