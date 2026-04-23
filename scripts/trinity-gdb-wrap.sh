#!/bin/bash
#
# trinity-gdb-wrap.sh — launch trinity under `gdb --batch` so we always
# capture post-mortem state on abort, regardless of whether the kernel
# coredumper rate-limited the dump.
#
# Coredumper has a per-process rate limit (see core_pipe_limit) and will
# silently drop dumps under load.  When trinity aborts during a long
# soak, that means the operator is left with no register state, no
# backtrace, and no idea which shared region was being chewed on.  This
# wrapper sidesteps coredumper entirely: gdb stays attached for the
# whole run, and the canned hook list runs at exit/abort to dump the
# interesting bits to stderr.
#
# Hooks injected (run after the inferior stops — normal exit OR signal):
#   p nr_shared_regions          — current count of mmap'd shared regions
#   p global_objects_protected   — alloc_shared() global-pool guard
#   info proc mappings           — full /proc/<pid>/maps view
#   thread apply all bt full     — every thread's stack, locals included
#
# Usage:
#   ./scripts/trinity-gdb-wrap.sh -- -c iouring_flood -N 1
#   ./scripts/trinity-gdb-wrap.sh -- --max-runtime 5m
#
# Everything after `--` is forwarded verbatim to the trinity binary.
#
# Trinity binary is located at:
#   1. ./trinity (relative to this script's repo root), if present
#   2. $TRINITY_BIN, if set
#   3. otherwise: error out
#

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_trinity="${script_dir}/../trinity"

if [[ -x "${repo_trinity}" ]]; then
    trinity_bin="${repo_trinity}"
elif [[ -n "${TRINITY_BIN:-}" && -x "${TRINITY_BIN}" ]]; then
    trinity_bin="${TRINITY_BIN}"
else
    echo "ERROR: trinity binary not found." >&2
    echo "  Tried: ${repo_trinity}" >&2
    echo "  TRINITY_BIN env var: ${TRINITY_BIN:-<unset>}" >&2
    echo "  Build trinity first, or set TRINITY_BIN to an executable path." >&2
    exit 1
fi

# Strip the optional `--` separator so the remainder is purely
# trinity's argv.  Without `--`, treat all positional args as
# trinity's.
trinity_args=()
if [[ $# -gt 0 && "$1" == "--" ]]; then
    shift
fi
trinity_args=("$@")

tmp_cmds=$(mktemp -t trinity-gdb-wrap.XXXXXX)
trap 'rm -f "${tmp_cmds}"' EXIT

# Build the gdb command file.  `run` is issued first; the hooks below
# fire after the inferior stops (exit, signal, or breakpoint).  In
# --batch mode gdb then quits and propagates the inferior's exit
# status.  Errors in individual hooks are tolerated so one missing
# symbol (e.g. an older trinity build without global_objects_protected)
# does not skip the rest of the dump.
{
    echo "set pagination off"
    echo "set print pretty on"
    echo "set print elements 0"
    echo "set confirm off"
    # `run` takes the inferior arguments inline.  Quote each one so
    # spaces/globs survive the trip through gdb's parser.
    printf "run"
    for a in "${trinity_args[@]+"${trinity_args[@]}"}"; do
        # Single-quote and escape any embedded single quotes.
        esc=${a//\'/\'\\\'\'}
        printf " '%s'" "${esc}"
    done
    printf "\n"
    echo "echo \\n===== nr_shared_regions =====\\n"
    echo "p nr_shared_regions"
    echo "echo \\n===== global_objects_protected =====\\n"
    echo "p global_objects_protected"
    echo "echo \\n===== info proc mappings =====\\n"
    echo "info proc mappings"
    echo "echo \\n===== thread apply all bt full =====\\n"
    echo "thread apply all bt full"
} > "${tmp_cmds}"

exec gdb --batch -x "${tmp_cmds}" "${trinity_bin}"
