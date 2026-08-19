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

# Privileged pre-run setup scripts: must be run manually as root.
# This script does NOT invoke them automatically — each requires
# elevated privilege and is a deliberate per-boot decision.
#
#   scripts/setup-fault-injectors.sh
#       Arm debugfs fault injectors.
#       (CAP_SYS_RESOURCE, CAP_DAC_OVERRIDE)
#
#   scripts/setup-privileged-preconditions.sh
#       Mount tracefs and relax 0640 file modes (TRACE_MODE_WRITE,
#       kernel/trace/trace.h:34) so the unprivileged runner can
#       exercise tracefs-fuzzer.
#       (CAP_SYS_ADMIN, CAP_DAC_OVERRIDE)
#
# Fault-injector state: read the world-readable file written by
# scripts/setup-fault-injectors.sh (run once as root before this script).
# The debugfs attrs are 0600 root-owned, so the runner cannot probe them
# directly; the setup script is the authoritative source of truth.
# Absent state file → unknown (no privileged setup was done this boot).
_fi_state_file="/run/trinity/fault-injectors.state"
_fi_injectors_armed=0
_fi_lockdep_stats_readable=0
_fi_make_it_fail_pid=""
if [[ -r "${_fi_state_file}" ]]; then
    # Source key=value lines; skip comment lines.
    while IFS='=' read -r _k _v; do
        [[ "${_k}" == '#'* ]] && continue
        [[ -z "${_k}" ]]      && continue
        case "${_k}" in
            injectors_armed)         _fi_injectors_armed="${_v}"         ;;
            lockdep_stats_readable)  _fi_lockdep_stats_readable="${_v}"  ;;
            make_it_fail_pid)        _fi_make_it_fail_pid="${_v}"        ;;
        esac
    done < "${_fi_state_file}"
fi

if [[ "${_fi_injectors_armed}" == "1" ]]; then
    # Determine whether the task-filtered injectors are actually scoped to
    # this run.  fail_task() in lib/fault-inject.c:81 gates five of the six
    # injectors on current->make_it_fail, which is only set via the
    # /proc/<pid>/make-it-fail procfs knob and inherited by dup_task_struct().
    # If setup-fault-injectors.sh ran without --pid, make_it_fail_pid is
    # empty and those five injectors inject nothing for any task in this run.
    _fi_task_filtered_inert=0
    if [[ -z "${_fi_make_it_fail_pid}" ]]; then
        _fi_task_filtered_inert=1
    else
        # Walk the PPid chain upward from this process to see whether
        # make_it_fail_pid is an ancestor of $$ (and therefore whether
        # current->make_it_fail is set for tasks spawned from this shell).
        _fi_pid_is_ancestor=0
        _fi_walk="$$"
        while [[ -n "${_fi_walk}" ]] && [[ "${_fi_walk}" != "0" ]]; do
            if [[ "${_fi_walk}" == "${_fi_make_it_fail_pid}" ]]; then
                _fi_pid_is_ancestor=1
                break
            fi
            _fi_walk=$(awk '/^PPid:/ {print $2}' "/proc/${_fi_walk}/status" 2>/dev/null) || break
        done
        if [[ "${_fi_pid_is_ancestor}" != "1" ]]; then
            _fi_task_filtered_inert=1
        fi
    fi
    if [[ "${_fi_task_filtered_inert}" == "1" ]]; then
        echo "WARNING: fault injectors armed but make_it_fail_pid is absent or targets a different task tree (see ${_fi_state_file})." >&2
        echo "  Five task-filtered injectors (failslab, fail_page_alloc, fail_usercopy, fail_futex, fail_sunrpc)" >&2
        echo "  are inert for this run: fail_task() (lib/fault-inject.c:81) gates them on current->make_it_fail," >&2
        echo "  which is only inherited by dup_task_struct() descendants of the --pid target." >&2
        echo "  Only fail_skb_realloc is not task-filtered and will fire." >&2
        echo "  Fix: sudo scripts/setup-fault-injectors.sh --pid \$\$ then re-run." >&2
    else
        echo "trinity: fault injectors armed by setup-fault-injectors.sh (see ${_fi_state_file})"
    fi
else
    # No state file or injectors not armed: advise the operator.
    # The debugfs attrs are 0600 so we cannot read or write them here;
    # warn once and direct to the setup script.
    if [[ -d /sys/kernel/debug/failslab || -d /sys/kernel/debug/fail_page_alloc ]]; then
            echo "WARNING: fault injectors appear compiled in but setup-fault-injectors.sh has not run or died on invalid args (check stderr)." >&2
            echo "  Six compiled-in injectors (failslab, fail_page_alloc, fail_usercopy, fail_futex," >&2
            echo "  fail_sunrpc, fail_skb_realloc) default probability=0 and will not fire." >&2
            echo "  Fix: sudo scripts/setup-fault-injectors.sh [--pid \$\$] then re-run this script." >&2
    fi
fi

# Tracefs state: read the world-readable file written by
# scripts/setup-privileged-preconditions.sh (run once as root before this
# script).  The tracefs control files are 0640 root:root by default so the
# runner cannot probe them directly; the setup script is the authoritative
# source of truth.  Absent state file → unknown (setup has not run this boot).
_tf_state_file="/run/trinity/tracefs.state"
_tf_tracefs_ready=0
if [[ -r "${_tf_state_file}" ]]; then
    while IFS='=' read -r _k _v; do
        [[ "${_k}" == '#'* ]] && continue
        [[ -z "${_k}" ]]      && continue
        case "${_k}" in
            tracefs_ready)  _tf_tracefs_ready="${_v}"  ;;
        esac
    done < "${_tf_state_file}"
fi

if [[ "${_tf_tracefs_ready}" != "1" ]]; then
    # Absent state file or tracefs_ready != 1: tracefs-fuzzer will probe
    # access(W_OK) on tracing_on at runtime and set tracefs_runtime_dead
    # (childops/fs/tracefs-fuzzer.c:1579-1594) if it gets EACCES, silently
    # skipping all tracefs operations.  Warn so the operator knows coverage
    # may be degraded without failing the run.
    if [[ ! -r "${_tf_state_file}" ]]; then
        echo "WARNING: ${_tf_state_file} absent — setup-privileged-preconditions.sh has not run this boot." >&2
        echo "  tracefs-fuzzer may get EACCES on tracing_on (TRACE_MODE_WRITE 0640 root:root)" >&2
        echo "  and set tracefs_runtime_dead, silently skipping all tracefs coverage." >&2
        echo "  Fix: sudo scripts/setup-privileged-preconditions.sh [--user \$USER] then re-run." >&2
    else
        echo "WARNING: ${_tf_state_file} present but tracefs_ready != 1 (got '${_tf_tracefs_ready}')." >&2
        echo "  Tracefs coverage may be disabled for this run (see ${_tf_state_file})." >&2
        echo "  Fix: sudo scripts/setup-privileged-preconditions.sh [--user \$USER] then re-run." >&2
    fi
fi

# lockdep self-disables on the FIRST splat — debug_locks_off() sets
# debug_locks=0 and lockdep never reports again until reboot — so "no
# deadlock found" and "lockdep died hours ago" are the same output.
# /proc/lockdep_stats exposes the live/dead bit as ' debug_locks:'
# (1=live, 0=self-disabled).  Record it now so cleanup() can flag a mid-run
# 1->0 transition, and warn loudly if it is already dead before we start.
# The single number is the whole signal; parsing dmesg for splat text is
# dmesg-scan's job, not the runner's.  Guarded so a non-lockdep kernel is a
# silent no-op.
# Tri-state: "alive" (readable, debug_locks=1), "dead" (readable but
# debug_locks=0, or exists but not readable), "unknown" (absent — non-lockdep
# kernel).  cleanup() gates on != unknown so the mid-run liveness check fires
# whenever startup could determine a state, not only when it found lockdep live.
# /proc/lockdep_stats is 0400 (root-read-only) by default; setup-fault-injectors.sh
# runs chmod o+r on it and records lockdep_stats_readable=1 in the state file.
# Use that hint: if the setup script relaxed the mode, read it directly;
# if not, we know it's unreadable and say so without a misleading access probe.
lockdep_state="unknown"
if [[ -e /proc/lockdep_stats ]]; then
    if [[ "${_fi_lockdep_stats_readable}" == "1" ]] || [[ -r /proc/lockdep_stats ]]; then
        lockdep_at_start=$(awk '/^ debug_locks:/ {print $2}' /proc/lockdep_stats 2>/dev/null || echo "")
        if [[ "${lockdep_at_start}" == "0" ]]; then
            lockdep_state="dead"
            echo "WARNING: lockdep is already self-disabled (debug_locks=0 in /proc/lockdep_stats) — lock-order coverage is DEAD for this run." >&2
            echo "  A prior splat killed it; nothing re-enables lockdep short of a reboot, so 'no deadlock found' this run means nothing." >&2
        elif [[ -n "${lockdep_at_start}" ]]; then
            lockdep_state="alive"
        else
            lockdep_state="dead"
            echo "WARNING: lockdep liveness UNKNOWN — /proc/lockdep_stats not readable (try: sudo scripts/setup-fault-injectors.sh)" >&2
        fi
    else
        lockdep_state="dead"
        echo "WARNING: lockdep liveness UNKNOWN — /proc/lockdep_stats is 0400 root-only; run setup-fault-injectors.sh as root to relax readability" >&2
        echo "  Fix: sudo scripts/setup-fault-injectors.sh" >&2
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

# Reap the entire trinity process tree AND the dmesg follower on wrapper
# exit. The trap is installed HERE -- right after the dmesg follower is
# launched and BEFORE the ~100 lines of cgroup setup below -- because the
# follower runs in a systemd-owned transient scope that OUTLIVES this
# wrapper. If the trap were installed only just before trinity launches (as
# it was), a `set -e` failure or a signal during cgroup setup would exit
# without reaping it, orphaning a `dmesg --follow-new | head -c 1G` pair per
# run. scope_name/child are empty at this point, so an early fire reaps only
# the dmesg scope; both are filled in below before they are used.
#
# Scoping is per-invocation: stop only this run's named scope, or kill only
# this run's processes directly -- never a broad pkill that would also kill
# concurrent trinity runs on the same host. D-state children can't be
# force-killed until their in-flight syscall returns; the kernel releases
# them as their syscalls complete.  Only the cgroup path (scope-stop) reaches
# every task: workers call setsid() in child/child-init-isolate.c and
# permanently leave the parent's process group, so a pgid-kill cannot reach
# them; the fallback must kill them individually by PID.
scope_name=""
child=""
cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if [[ -n "${scope_name}" ]]; then
        systemctl --user stop "${scope_name}" >/dev/null 2>&1 || true
    elif [[ -n "${child}" ]]; then
        # Workers call setsid() in child/child-init-isolate.c and leave the
        # parent's process group permanently; a pgid-kill cannot reach them.
        # Capture their PIDs from the trinity parent's task/*/children BEFORE
        # killing the parent (workers reparent to init on parent death), then
        # SIGKILL each directly.  This is per-invocation; never pkill -x trinity.
        _worker_pids=()
        for _f in /proc/"${child}"/task/*/children; do
            [[ -r "${_f}" ]] || continue
            _kids=()
            read -r -a _kids < "${_f}" || true
            (( ${#_kids[@]} )) && _worker_pids+=("${_kids[@]}")
        done
        if [[ ${#_worker_pids[@]} -eq 0 ]] && kill -0 "${child}" 2>/dev/null; then
            echo "WARNING: cleanup(): worker sweep found no PIDs (CONFIG_PROC_CHILDREN?); workers may be leaked" >&2
        fi
        kill -KILL "${child}" 2>/dev/null || true
        for _wpid in "${_worker_pids[@]}"; do
            kill -KILL "${_wpid}" 2>/dev/null || true
        done
    fi
    # lockdep self-disables on the first splat; report a mid-run 1->0
    # transition so a run that went blind after minute 3 isn't mistaken for a
    # clean one.  Runs on EXIT/INT/TERM, so this fires on crash and interrupt
    # paths too, not only on clean exit.
    if [[ "${lockdep_state:-unknown}" != "unknown" ]] && [[ -e /proc/lockdep_stats ]]; then
        if [[ "${_fi_lockdep_stats_readable:-0}" == "1" ]] || [[ -r /proc/lockdep_stats ]]; then
            _lds_end=$(awk '/^ debug_locks:/ {print $2}' /proc/lockdep_stats 2>/dev/null || echo "")
            if [[ "${_lds_end}" == "0" ]]; then
                echo "WARNING: lockdep self-disabled during this run (debug_locks ${lockdep_state} -> dead) — lock-order coverage stopped at the first splat (see dmesg.log); everything after that point was uncovered." >&2
            fi
        else
            echo "WARNING: lockdep liveness UNKNOWN at cleanup — /proc/lockdep_stats is 0400 root-only (was ${lockdep_state} at start); run setup-fault-injectors.sh to relax readability" >&2
        fi
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

if [[ -n "${scope_name}" ]]; then
    # systemd-run places the command in the named scope's cgroup;
    # cleanup reaps the tree via `systemctl --user stop <scope>`.
    "${cmd[@]}" &
else
    # No scope (TRINITY_NO_CGROUP / systemd-run absent / already capped):
    # enable job control so bash puts the backgrounded command in its own
    # process group.  Note: workers setsid() out of this group; cleanup()
    # reaps them individually by PID rather than via a pgid-kill.
    set -m
    "${cmd[@]}" &
    set +m
fi
child=$!
wait "${child}"
