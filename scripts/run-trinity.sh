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

# --- per-run kernel-log capture --------------------------------------------
# Stream the ring buffer for the whole run into dmesg.log.  Continuous, not
# an end-of-run dump: the ring is finite and a long noisy run overflows it.
# --follow-new skips the pre-run buffer (log is THIS run only); stdbuf -oL
# line-buffers so a splat just before teardown isn't lost in a stdio buffer.
# Own transient scope mirrors the trinity scope -> reaped by cleanup() below.
# Needs CAP_SYSLOG (root or kernel.dmesg_restrict=0), same as kcov access.
# TRINITY_NO_DMESG=1 skips it; TRINITY_DMESG_LOG overrides the path;
# TRINITY_DMESG_MAX caps the captured size (default 1G) so a long or
# crash-looping run on a noisy debug kernel can't fill the disk. The cap
# is enforced on the consumer side via `head -c` in a process substitution
# so dmesg_pid still refers to the dmesg launcher and cleanup() can reap
# it through either the scope-stop or the plain-kill teardown path.
dmesg_log="${TRINITY_DMESG_LOG:-dmesg.log}"
dmesg_scope=""
dmesg_pid=""
if [[ -z "${TRINITY_NO_DMESG:-}" ]]; then
    dmesg_cmd=(stdbuf -oL dmesg --follow-new --time-format=iso)
    if command -v systemd-run >/dev/null 2>&1; then
        dmesg_scope="trinity-dmesg-$$.scope"
        dmesg_cmd=(systemd-run --user --scope --quiet --unit="${dmesg_scope}" -- "${dmesg_cmd[@]}")
    fi
    "${dmesg_cmd[@]}" > >(head -c "${TRINITY_DMESG_MAX:-1G}" > "${dmesg_log}") &
    dmesg_pid=$!
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

# Lift RLIMIT_NOFILE before exec.  Trinity's 16-child fan-out plus per-child
# netlink/kcov/fileindex/iommufd/landlock pressure exhausts the default 1024
# soft limit at startup (observed: genetlink nl_open EMFILE during init,
# get_random_fd outer retry budget exhausted).  Done here rather than via
# systemd-run -p because scope units reject LimitNOFILE — it's a service-
# unit-only property.  Best-effort: silently no-op if the hard limit is
# already below 65536, leaving the previous soft limit in place.
ulimit -n 65536 2>/dev/null || true

cmd=(./trinity "$@")

scope_name=""
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

            # Named scope so the EXIT/INT/TERM trap below can reap the
            # whole trinity process tree by stopping the scope's cgroup.
            scope_name="trinity-run-$$.scope"

            echo "trinity: wrapping in systemd scope ${scope_name} (MemoryMax=${mem_max}, MemoryHigh=${mem_high}, MemorySwapMax=${mem_swap_max})"
            # Delegate=yes hands the scope's cgroup subtree to trinity so
            # self_cgroup can enable +memory on it and nest its
            # parent/children OOM split under this cap.
            cmd=(systemd-run --user --scope --quiet
                --unit="${scope_name}"
                -p Delegate=yes
                -p MemoryMax="${mem_max}"
                -p MemoryHigh="${mem_high}"
                -p MemorySwapMax="${mem_swap_max}"
                -- "${cmd[@]}")
        fi
    fi
fi

# Reap the entire trinity process tree on wrapper exit. Without this,
# the parent, children, and any zombies/D-state stragglers out-live the
# wrapper and accumulate over repeated runs (a relaunch loop on a fuzz
# host was observed leaving 35+ orphaned -C16 parents pinning memory and
# wedging subsequent runs).
#
# Scoping is per-invocation: stop only this run's named scope, or signal
# only this run's process group -- never a broad pkill that would also
# kill concurrent trinity runs on the same host.
#
# D-state children can't be force-killed until their in-flight syscall
# returns; scope-stop / pgid-kill sends SIGKILL to every task in the
# group, reaps everything killable immediately, and the kernel releases
# the rest as their syscalls complete.
child=""
cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if [[ -n "${scope_name}" ]]; then
        systemctl --user stop "${scope_name}" >/dev/null 2>&1 || true
    elif [[ -n "${child}" ]]; then
        kill -KILL -- "-${child}" 2>/dev/null || true
    fi
    # Stop the dmesg follower after trinity so it captures teardown splats;
    # line-buffered output means no extra flush is needed.
    if [[ -n "${dmesg_scope}" ]]; then
        systemctl --user stop "${dmesg_scope}" >/dev/null 2>&1 || true
    elif [[ -n "${dmesg_pid}" ]]; then
        kill "${dmesg_pid}" 2>/dev/null || true
    fi
    exit "${rc}"
}
trap cleanup EXIT INT TERM

if [[ -n "${scope_name}" ]]; then
    # systemd-run places the command in the named scope's cgroup;
    # cleanup reaps the tree via `systemctl --user stop <scope>`.
    "${cmd[@]}" &
else
    # No scope (TRINITY_NO_CGROUP / systemd-run absent / already capped):
    # enable job control so bash puts the backgrounded command in its own
    # process group, then $! == PGID and `kill -- -PGID` reaps the tree.
    set -m
    "${cmd[@]}" &
    set +m
fi
child=$!
wait "${child}"
