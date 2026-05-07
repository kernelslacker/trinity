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
    pipe_binary="${pipe_target%% *}"
    if [[ ! -x "${pipe_binary}" ]]; then
        echo "WARNING: core_pattern pipes to '${pipe_binary}' which doesn't exist or isn't executable." >&2
        echo "  Cores will be silently dropped. To get cores in cwd: echo 'core.%p' | sudo tee /proc/sys/kernel/core_pattern" >&2
    fi
fi

if [[ -e /sys/kernel/debug/kcov ]]; then
    for arg in "$@"; do
        if [[ "${arg}" == "--kcov" ]]; then
            if [[ ! -r /sys/kernel/debug/kcov ]] || [[ ! -w /sys/kernel/debug/kcov ]]; then
                echo "WARNING: /sys/kernel/debug/kcov is not world-readable/writable — KCOV will fail." >&2
                echo "  Fix: sudo chmod 777 /sys/kernel/debug && sudo chmod 666 /sys/kernel/debug/kcov" >&2
            fi
            break
        fi
    done
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

# Memory containment via transient systemd scope.  Stopgap until trinity
# learns to create its own cgroup at startup.  Wraps the launch in a scope
# with MemoryMax/MemoryHigh/MemorySwapMax so OOM under load stays scoped
# to trinity instead of taking down the host's tmux/ssh/shell.
#
# Defaults: 60% of MemTotal hard cap, 50% high-water, 20% swap cap.
# Override with TRINITY_MEM_MAX / TRINITY_MEM_HIGH / TRINITY_MEM_SWAP_MAX
# (any unit systemd accepts, e.g. "8G", "512M").  Set TRINITY_NO_CGROUP=1
# to disable wrapping entirely.
if [[ -z "${TRINITY_NO_CGROUP:-}" ]] && command -v systemd-run >/dev/null 2>&1; then
    # Don't double-wrap if already inside a scoped cgroup with a cap.
    cg_path=$(awk -F: '/^0::/ {print $3}' /proc/self/cgroup 2>/dev/null || true)
    if [[ -n "${cg_path}" ]] && [[ -r "/sys/fs/cgroup${cg_path}/memory.max" ]]; then
        cur_max=$(cat "/sys/fs/cgroup${cg_path}/memory.max")
        if [[ "${cur_max}" != "max" ]]; then
            echo "trinity: already in cgroup ${cg_path} with memory.max=${cur_max}, skipping wrap"
            exec ./trinity "$@"
        fi
    fi

    mem_total_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
    mem_max=${TRINITY_MEM_MAX:-$((mem_total_kb * 60 / 100))K}
    mem_high=${TRINITY_MEM_HIGH:-$((mem_total_kb * 50 / 100))K}
    mem_swap_max=${TRINITY_MEM_SWAP_MAX:-$((mem_total_kb * 20 / 100))K}

    echo "trinity: wrapping in systemd scope (MemoryMax=${mem_max}, MemoryHigh=${mem_high}, MemorySwapMax=${mem_swap_max})"
    exec systemd-run --user --scope --quiet \
        -p MemoryMax="${mem_max}" \
        -p MemoryHigh="${mem_high}" \
        -p MemorySwapMax="${mem_swap_max}" \
        -- ./trinity "$@"
fi

exec ./trinity "$@"
