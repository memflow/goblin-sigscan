#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

usage() {
	cat <<'EOF'
Usage: scripts/bench-ab.sh --name BASELINE [options]

Two-phase A/B helper for Criterion baselines.

Phase 1 (baseline save):
  scripts/bench-ab.sh --name my-change --phase save

Phase 2 (compare current checkout vs saved baseline):
  scripts/bench-ab.sh --name my-change --phase compare

Options:
  --name NAME            Baseline name (required)
  --phase save|compare   Which phase to run (default: save)
  --mode NAME            Benchmark mode passed to bench-key (default: all)
  --runs N               Repeat full key matrix N times (default: 1)
  --sample-size N        Criterion sample size (default: 10)
  --measurement-time S   Criterion measurement time seconds (default: 3)
  --extra ARG            Extra criterion argument (repeatable)
  -h, --help             Show help

Notes:
  - This script does not mutate git state.
  - Run "save" on checkout A, switch checkout, then run "compare".
EOF
}

baseline_name=""
phase="save"
mode="all"
runs=1
sample_size=10
measurement_time=3
extra_args=()

while [[ $# -gt 0 ]]; do
	case "$1" in
	--name)
		baseline_name="$2"
		shift 2
		;;
	--phase)
		phase="$2"
		shift 2
		;;
	--mode)
		mode="$2"
		shift 2
		;;
	--runs)
		runs="$2"
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

if [[ -z "$baseline_name" ]]; then
	echo "error: --name is required" >&2
	usage >&2
	exit 2
fi

case "$phase" in
save)
	baseline_flag=(--save-baseline "$baseline_name")
	;;
compare)
	baseline_flag=(--baseline "$baseline_name")
	;;
*)
	echo "error: invalid phase '$phase' (expected save or compare)" >&2
	exit 2
	;;
esac

for run in $(seq 1 "$runs"); do
	echo "==> phase=$phase run=$run baseline=$baseline_name"
	cmd=(
		scripts/bench-key.sh
		--mode "$mode"
		--sample-size "$sample_size"
		--measurement-time "$measurement_time"
		"${baseline_flag[@]}"
	)
	for extra in "${extra_args[@]}"; do
		cmd+=(--extra "$extra")
	done
	"${cmd[@]}"
done
