#!/bin/bash
set -euo pipefail

ulimit -c unlimited

core_pattern=$(cat /proc/sys/kernel/core_pattern)
echo "core_pattern: ${core_pattern}"

if [[ -z "${core_pattern}" || "${core_pattern}" == "core" ]]; then
    echo "WARNING: core_pattern is '${core_pattern}' — cores may land in cwd with no PID suffix." >&2
    echo "  To get predictable cores: echo 'core.%p' | sudo tee /proc/sys/kernel/core_pattern" >&2
elif [[ "${core_pattern}" == '|'* ]]; then
    pipe_target="${core_pattern#|}"
    # Split on any whitespace (tab as well as space) — some site-local
    # core handlers use TABs rather than spaces to delimit their arg list.
    read -r pipe_binary _ <<< "${pipe_target}"
    if [[ ! -x "${pipe_binary}" ]]; then
        echo "WARNING: core_pattern pipes to '${pipe_binary}' which doesn't exist or isn't executable." >&2
        echo "  Cores will be silently dropped. To get cores in cwd: echo 'core.%p' | sudo tee /proc/sys/kernel/core_pattern" >&2
    fi
fi

# Trinity uses KCOV whenever /sys/kernel/debug/kcov is exposed; bad perms
# silently disable coverage with no useful diagnostic from trinity itself.
if [[ -e /sys/kernel/debug/kcov ]]; then
    if [[ ! -r /sys/kernel/debug/kcov ]] || [[ ! -w /sys/kernel/debug/kcov ]]; then
        echo "WARNING: /sys/kernel/debug/kcov is not world-readable/writable — KCOV will fail." >&2
        echo "  Fix: sudo chmod 777 /sys/kernel/debug && sudo chmod 666 /sys/kernel/debug/kcov" >&2
    fi
fi

# When running under valgrind, recommend the suppressions file so the
# known KCOV_INIT_TRACE false positive doesn't drown the real output.
if [[ -n "${RUNNING_ON_VALGRIND:-}" ]]; then
    script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
    supp_file="${script_dir}/../valgrind.supp"
    if [[ -r "${supp_file}" ]] && [[ "${VALGRIND_OPTS:-}" != *"${supp_file}"* ]]; then
        echo "NOTE: running under valgrind without trinity's suppressions file." >&2
        echo "  For cleaner output add: --suppressions=${supp_file}" >&2
    fi
fi

# Outer-scope memory containment via transient systemd scope, layered on
# top of trinity's own self_cgroup (--memory-max etc., see self_cgroup.c).
# The outer scope protects the brief startup window before trinity creates
# its sub-cgroups, and is a safety net if self_cgroup setup itself fails
# or is disabled with --no-cgroup.
#
# Defaults below MIRROR self_cgroup.c's defaults (60/50/20 of MemTotal);
# if you change one, change the other.  Override per-run with
# TRINITY_MEM_MAX / TRINITY_MEM_HIGH / TRINITY_MEM_SWAP_MAX (any unit
# systemd accepts, e.g. "8G", "512M").  Set TRINITY_NO_CGROUP=1 to skip
# the outer scope entirely; trinity's self_cgroup is unaffected.
cmd=(./trinity "$@")

if [[ -z "${TRINITY_NO_CGROUP:-}" ]]; then
    if ! command -v systemd-run >/dev/null 2>&1; then
        echo "NOTE: systemd-run not found; skipping outer scope (trinity's self_cgroup is still active unless --no-cgroup was passed)." >&2
    else
        # Don't double-wrap if already inside a scoped cgroup with a cap.
        cg_path=$(awk -F: '/^0::/ {print $3}' /proc/self/cgroup 2>/dev/null || true)
        wrap=1
        if [[ -n "${cg_path}" ]] && [[ -r "/sys/fs/cgroup${cg_path}/memory.max" ]]; then
            cur_max=$(cat "/sys/fs/cgroup${cg_path}/memory.max")
            if [[ "${cur_max}" != "max" ]]; then
                echo "trinity: already in capped cgroup ${cg_path} (memory.max=${cur_max}); skipping outer scope (self_cgroup still active)." >&2
                wrap=
            fi
        fi

        if [[ -n "${wrap}" ]]; then
            mem_total_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
            mem_max=${TRINITY_MEM_MAX:-$((mem_total_kb * 60 / 100))K}
            mem_high=${TRINITY_MEM_HIGH:-$((mem_total_kb * 50 / 100))K}
            mem_swap_max=${TRINITY_MEM_SWAP_MAX:-$((mem_total_kb * 20 / 100))K}

            echo "trinity: wrapping in systemd scope (MemoryMax=${mem_max}, MemoryHigh=${mem_high}, MemorySwapMax=${mem_swap_max})"
            cmd=(systemd-run --user --scope --quiet
                -p MemoryMax="${mem_max}"
                -p MemoryHigh="${mem_high}"
                -p MemorySwapMax="${mem_swap_max}"
                -- "${cmd[@]}")
        fi
    fi
fi

exec "${cmd[@]}"
