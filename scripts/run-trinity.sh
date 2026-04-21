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

exec ./trinity "$@"
