#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

readonly DEFAULT_SAMPLE_SIZE=10
readonly DEFAULT_MEASUREMENT_TIME=3

usage() {
	cat <<'EOF'
Usage: scripts/bench-key.sh [options]

Run the scanner benchmark key matrix under nix.

Options:
  --sample-size N        Criterion sample size (default: 10)
  --measurement-time S   Criterion measurement time seconds (default: 3)
  --save-baseline NAME   Save baseline with this name
  --baseline NAME        Compare against baseline with this name
  --extra ARG            Extra argument forwarded to criterion (repeatable)
  -h, --help             Show help

Examples:
  scripts/bench-key.sh --save-baseline pre-anchor
  scripts/bench-key.sh --baseline pre-anchor
EOF
}

sample_size="$DEFAULT_SAMPLE_SIZE"
measurement_time="$DEFAULT_MEASUREMENT_TIME"
baseline_mode=""
baseline_name=""
extra_args=()

while [[ $# -gt 0 ]]; do
	case "$1" in
	--sample-size)
		sample_size="$2"
		shift 2
		;;
	--measurement-time)
		measurement_time="$2"
		shift 2
		;;
	--save-baseline)
		baseline_mode="--save-baseline"
		baseline_name="$2"
		shift 2
		;;
	--baseline)
		baseline_mode="--baseline"
		baseline_name="$2"
		shift 2
		;;
	--extra)
		extra_args+=("$2")
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

if [[ -n "$baseline_mode" && -z "$baseline_name" ]]; then
	echo "error: baseline mode requires a baseline name" >&2
	exit 2
fi

readonly BENCHES=(
	"scan_pe64/matches_code/jump4"
	"scan_pe64/matches_code/alternation"
	"scan_elf64/matches_code/push_pop"
	"scan_elf64/matches_code/jump1"
	"scan_pe64/matches_code/jump4_tiny"
	"scan_elf64/matches_code/jump4_tiny"
)

for bench in "${BENCHES[@]}"; do
	echo "==> $bench"
	cmd=(
		nix develop -c cargo bench -p goblin-lite --bench scan_perf -- "$bench"
		--sample-size "$sample_size"
		--measurement-time "$measurement_time"
	)
	if [[ -n "$baseline_mode" ]]; then
		cmd+=("$baseline_mode" "$baseline_name")
	fi
	if [[ ${#extra_args[@]} -gt 0 ]]; then
		cmd+=("${extra_args[@]}")
	fi
	"${cmd[@]}"
done
