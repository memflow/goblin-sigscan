#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

usage() {
	cat <<'EOF'
Usage: scripts/flamegraph-scan.sh [--output FILE] -- <sigscan args>

Run a scanner flamegraph under nix using the `sigscan` crate.

Examples:
  scripts/flamegraph-scan.sh -- fixtures/memflow_coredump.x86_64.dll "48 8B 0D ${'}"
  scripts/flamegraph-scan.sh --output perf.svg -- fixtures/libmemflow_coredump.x86_64.so "55 41 57"
EOF
}

output_file=""

while [[ $# -gt 0 ]]; do
	case "$1" in
	--output)
		output_file="$2"
		shift 2
		;;
	--)
		shift
		break
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

if [[ $# -eq 0 ]]; then
	echo "error: missing sigscan arguments" >&2
	usage >&2
	exit 2
fi

cmd=(nix develop -c cargo flamegraph -p sigscan --root)
if [[ -n "$output_file" ]]; then
	cmd+=(--output "$output_file")
fi
cmd+=(--)
cmd+=("$@")

"${cmd[@]}"
