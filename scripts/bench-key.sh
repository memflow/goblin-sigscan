#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

readonly DEFAULT_SAMPLE_SIZE=30
readonly DEFAULT_MEASUREMENT_TIME=8

usage() {
	cat <<'EOF'
Usage: scripts/bench-key.sh [options]

Run the scanner benchmark key matrix under nix.

Options:
  --mode NAME            Benchmark mode: matches, finds, finds-prepared, all (default: all)
  --sample-size N        Criterion sample size (default: 30)
  --measurement-time S   Criterion measurement time seconds (default: 8)
  --save-baseline NAME   Save baseline with this name
  --baseline NAME        Compare against baseline with this name
  --extra ARG            Extra argument forwarded to criterion (repeatable)
  -h, --help             Show help

Examples:
  scripts/bench-key.sh --save-baseline pre-anchor
  scripts/bench-key.sh --baseline pre-anchor
  scripts/bench-key.sh --mode finds-prepared
EOF
}

sample_size="$DEFAULT_SAMPLE_SIZE"
measurement_time="$DEFAULT_MEASUREMENT_TIME"
mode="all"
baseline_mode=""
baseline_name=""
extra_args=()

while [[ $# -gt 0 ]]; do
	case "$1" in
	--mode)
		mode="$2"
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

if [[ "$sample_size" -lt 10 ]]; then
	echo "error: --sample-size must be >= 10 for criterion" >&2
	exit 2
fi

case "$mode" in
matches)
	readonly BENCHES=(
		"scan_pe64/matches_code/jump4"
		"scan_pe64/matches_code/alternation"
		"scan_elf64/matches_code/push_pop"
		"scan_elf64/matches_code/jump1"
		"scan_pe64/matches_code/jump4_tiny"
		"scan_elf64/matches_code/jump4_tiny"
	)
	;;
finds)
	readonly BENCHES=(
		"scan_pe64/finds_code/jump4"
		"scan_pe64/finds_code/alternation"
		"scan_elf64/finds_code/push_pop"
		"scan_elf64/finds_code/jump1"
		"scan_pe64/finds_code/jump4_tiny"
		"scan_elf64/finds_code/jump4_tiny"
	)
	;;
finds-prepared)
	readonly BENCHES=(
		"scan_pe64/finds_prepared/jump4"
		"scan_pe64/finds_prepared/alternation"
		"scan_elf64/finds_prepared/push_pop"
		"scan_elf64/finds_prepared/jump1"
		"scan_pe64/finds_prepared/jump4_tiny"
		"scan_elf64/finds_prepared/jump4_tiny"
	)
	;;
all)
	readonly BENCHES=(
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
