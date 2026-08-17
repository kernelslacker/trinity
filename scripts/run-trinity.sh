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

# The 2026-08-14 debug-kernel rebuild compiles in six fault injectors
# (failslab, fail_page_alloc, fail_futex, fail_sunrpc, fail_skb_realloc,
# fail_usercopy).  Compiled in is not the same as armed, and the difference
# is invisible from the Kconfig: failslab and fail_page_alloc default to
# ignore-gfp-wait=1 (they skip every GFP_KERNEL allocation, i.e. nearly all
# of them) so they inject essentially nothing, and fail_skb_realloc defaults
# filtered=false so any non-zero probability faults reallocs on EVERY netdev
# on the box.  A run can therefore look fully fault-injecting while injecting
# nothing, or arm host-wide against the real management interface by accident.
# As with the kcov check above we only diagnose and print the fix: the
# debugfs files are root-owned (0600), trinity runs unprivileged, and the
# runner must never write them itself.  Each check gates on [[ -r ]] before
# reading — synthesising a worst-case default from an unreadable attr and
# then warning about it produces unfalsifiable noise that trains operators
# to ignore the output.  The right end-state is a privileged setup script
# that writes a world-readable state file the runner can consume, but that
# spec is separate future work.  Silent no-op when /sys/kernel/debug is
# absent or unreadable (non-debug kernels, unprivileged hosts).
if [[ -r /sys/kernel/debug ]]; then
    # failslab / fail_page_alloc: clear ignore-gfp-wait or they inject almost
    # nothing.  These two are the only compiled-in injectors that need it
    # (fail_futex/fail_sunrpc/fail_usercopy have no gfp filter and are live).
    for _inj in failslab fail_page_alloc; do
        _gfp="/sys/kernel/debug/${_inj}/ignore-gfp-wait"
        if [[ -e "${_gfp}" ]]; then
            if [[ ! -r "${_gfp}" ]]; then
                echo "WARNING: ${_inj} state UNKNOWN — debugfs attrs are 0600 root-only; run as root or via a privileged setup script to verify injector state." >&2
            elif [[ "$(cat "${_gfp}")" != "0" ]]; then
                echo "WARNING: ${_inj} has ignore-gfp-wait=1 — it skips every GFP_KERNEL allocation and injects almost nothing as configured." >&2
                echo "  Fix: echo 0 | sudo tee ${_gfp}" >&2
            fi
        fi
    done

    # All six compiled-in injectors: warn if probability=0 (disarmed) or
    # times=0 (budget exhausted).  Each attr is checked for readability
    # independently before use — see rationale in the block comment above.
    for _inj in failslab fail_page_alloc fail_futex fail_sunrpc fail_usercopy; do
        _prob_f="/sys/kernel/debug/${_inj}/probability"
        _times_f="/sys/kernel/debug/${_inj}/times"
        if [[ -e "${_prob_f}" ]]; then
            if [[ ! -r "${_prob_f}" ]]; then
                echo "WARNING: ${_inj} state UNKNOWN — debugfs attrs are 0600 root-only; run as root or via a privileged setup script to verify injector state." >&2
            else
                if [[ "$(cat "${_prob_f}")" == "0" ]]; then
                    echo "WARNING: ${_inj} probability=0 — this fault injector is disarmed." >&2
                    echo "  Fix: echo <N> | sudo tee ${_prob_f}" >&2
                fi
                if [[ -r "${_times_f}" ]] && [[ "$(cat "${_times_f}")" == "0" ]]; then
                    echo "WARNING: ${_inj} times=0 — fault budget exhausted; the injector will not fire until reset." >&2
                    echo "  Fix: echo -1 | sudo tee ${_times_f}" >&2
                fi
            fi
        fi
    done

    # fail_skb_realloc: the device filter is load-bearing, not stylistic.
    # should_fail_net_realloc_skb() only consults skb->dev->name when
    # 'filtered' is set, and it defaults false — so 'devname' MUST be written
    # before 'probability', or the injector arms against every netdev on the
    # host including its real management interface.
    _skb=/sys/kernel/debug/fail_skb_realloc
    if [[ -d "${_skb}" ]]; then
        _prob_f="${_skb}/probability"
        _times_f="${_skb}/times"
        _filt_f="${_skb}/filtered"
        if [[ ! -r "${_prob_f}" ]]; then
            echo "WARNING: fail_skb_realloc state UNKNOWN — debugfs attrs are 0600 root-only; run as root or via a privileged setup script to verify injector state." >&2
        else
            _prob="$(cat "${_prob_f}")"
            if [[ "${_prob}" == "0" ]]; then
                echo "WARNING: fail_skb_realloc probability=0 — the RX-path skb-realloc injector is disarmed." >&2
                echo "  Fix (device filter FIRST, then probability — the order is load-bearing):" >&2
                echo "    echo <ifname> | sudo tee ${_skb}/devname" >&2
                echo "    echo 1        | sudo tee ${_skb}/filtered" >&2
                echo "    echo <N>      | sudo tee ${_skb}/probability" >&2
            elif [[ -r "${_filt_f}" ]] && [[ "$(cat "${_filt_f}")" == "0" ]]; then
                echo "WARNING: fail_skb_realloc is armed (probability=${_prob}) but UNSCOPED (filtered=0) — it faults reallocs on EVERY netdev, including this host's management interface." >&2
                echo "  Fix: set a device filter — echo <ifname> | sudo tee ${_skb}/devname && echo 1 | sudo tee ${_skb}/filtered" >&2
            fi
            if [[ -r "${_times_f}" ]] && [[ "$(cat "${_times_f}")" == "0" ]]; then
                echo "WARNING: fail_skb_realloc times=0 — fault budget exhausted; the injector will not fire until reset." >&2
                echo "  Fix: echo -1 | sudo tee ${_times_f}" >&2
            fi
        fi
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
lockdep_alive_at_start=""
if [[ -e /proc/lockdep_stats ]]; then
    if [[ -r /proc/lockdep_stats ]]; then
        lockdep_alive_at_start=$(awk '/^ debug_locks:/ {print $2}' /proc/lockdep_stats)
        if [[ "${lockdep_alive_at_start}" == "0" ]]; then
            echo "WARNING: lockdep is already self-disabled (debug_locks=0 in /proc/lockdep_stats) — lock-order coverage is DEAD for this run." >&2
            echo "  A prior splat killed it; nothing re-enables lockdep short of a reboot, so 'no deadlock found' this run means nothing." >&2
        fi
    else
        echo "WARNING: lockdep liveness UNKNOWN — /proc/lockdep_stats exists but is not readable as $(id -un)" >&2
        echo "  Running with CONFIG_LOCKDEP=y but without privilege to verify lock-order coverage." >&2
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
# Scoping is per-invocation: stop only this run's named scope, or signal
# only this run's process group -- never a broad pkill that would also kill
# concurrent trinity runs on the same host. D-state children can't be
# force-killed until their in-flight syscall returns; scope-stop / pgid-kill
# sends SIGKILL to every task, reaps everything killable immediately, and
# the kernel releases the rest as their syscalls complete.
scope_name=""
child=""
cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if [[ -n "${scope_name}" ]]; then
        systemctl --user stop "${scope_name}" >/dev/null 2>&1 || true
    elif [[ -n "${child}" ]]; then
        kill -KILL -- "-${child}" 2>/dev/null || true
    fi
    # lockdep self-disables on the first splat; report a mid-run 1->0
    # transition so a run that went blind after minute 3 isn't mistaken for a
    # clean one.  Runs on EXIT/INT/TERM, so this fires on crash and interrupt
    # paths too, not only on clean exit.
    if [[ "${lockdep_alive_at_start:-}" == "1" ]] && [[ -e /proc/lockdep_stats ]]; then
        if [[ -r /proc/lockdep_stats ]]; then
            if [[ "$(awk '/^ debug_locks:/ {print $2}' /proc/lockdep_stats)" == "0" ]]; then
                echo "WARNING: lockdep self-disabled during this run (debug_locks 1 -> 0) — lock-order coverage stopped at the first splat (see dmesg.log); everything after that point was uncovered." >&2
            fi
        else
            echo "WARNING: lockdep liveness UNKNOWN — /proc/lockdep_stats exists but is not readable as $(id -un)" >&2
            echo "  Running with CONFIG_LOCKDEP=y but without privilege to verify lock-order coverage." >&2
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
    # process group, then $! == PGID and `kill -- -PGID` reaps the tree.
    set -m
    "${cmd[@]}" &
    set +m
fi
child=$!
wait "${child}"
