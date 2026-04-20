#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

usage() {
	cat <<'EOF'
Usage: scripts/flamegraph-scan.sh [--output FILE] -- <sigscan args>

Run a scanner flamegraph under nix using the `sigscan` crate.

Options:
  --root               Pass --root to cargo flamegraph (may require sudo)
  --output FILE        Output SVG path
  -h, --help           Show help

Examples:
  scripts/flamegraph-scan.sh -- fixtures/memflow_coredump.x86_64.dll "48 8B 0D ${'}"
  scripts/flamegraph-scan.sh --output perf.svg -- fixtures/libmemflow_coredump.x86_64.so "55 41 57"
EOF
}

output_file=""
use_root="false"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--root)
		use_root="true"
		shift
		;;
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

if [[ "$(uname -s)" == "Darwin" ]] && ! command -v xctrace >/dev/null 2>&1; then
	echo "error: xctrace is required on macOS for cargo flamegraph" >&2
	echo "hint: install Xcode Command Line Tools and open Instruments once" >&2
	exit 1
fi

cmd=(nix develop -c cargo flamegraph -p goblin-sigscan-cli)
if [[ "$use_root" == "true" ]]; then
	cmd+=(--root)
fi
if [[ -n "$output_file" ]]; then
	cmd+=(--output "$output_file")
fi
cmd+=(--)
cmd+=("$@")

"${cmd[@]}"
