#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# setup-fault-injectors.sh — privileged pre-run helper for trinity fault injection
#
# Must be run as root (CAP_SYS_RESOURCE required for proc_fault_inject_write(),
# CAP_DAC_OVERRIDE required for chmod on /proc/lockdep_stats).
#
# Arms the six compiled-in fault injectors with correct per-context
# scoping, relaxes /proc/lockdep_stats readability, and emits a world-readable
# machine-readable state file that run-trinity.sh can consume without privilege.
#
# USAGE:
#   sudo scripts/setup-fault-injectors.sh [OPTIONS]
#
# OPTIONS:
#   --pid PID       Write make-it-fail=1 to /proc/PID/make-it-fail so all
#                   tasks forked from PID inherit it (scopes injection to the
#                   trinity process tree only).  Typically called again with
#                   the PID of the run-trinity.sh process after it starts.
#   --prob N        Fault probability 1-100 (default: ${TRINITY_FAULT_PROB:-2})
#   --netdev IFACE  Network interface for fail_skb_realloc devname filter
#                   (default: $TRINITY_NETDEV or first non-loopback interface)
#   --state FILE    State file path (default: /run/trinity/fault-injectors.state)
#   --dry-run       Print what would be written; do not write anything
#   -h, --help      Show this message
#
# SCOPING:
#   failslab:                    task-filter=1 + ignore-gfp-wait=0
#   fail_page_alloc:             task-filter=1 + ignore-gfp-wait=0 + ignore-gfp-highmem=0
#   fail_usercopy, fail_futex:  task-filter=1
#   fail_sunrpc:                task-filter=1 (kthreads satisfy in_task())
#   fail_skb_realloc:           devname=IFACE   (task-filter FATAL:
#                               softirq/NAPI has in_task()=false, applying
#                               task-filter=1 silently disarms this injector;
#                               kernel sets filtered internally via devname_write)
#
# INHERITANCE:
#   task->make_it_fail is copied through dup_task_struct() so writing 1 to the
#   trinity parent's /proc/<pid>/make-it-fail scopes injection to its entire
#   process tree without touching any other task on the host.

set -euo pipefail

STATE_FILE="/run/trinity/fault-injectors.state"
PROB="${TRINITY_FAULT_PROB:-2}"
TARGET_PID=""
NETDEV="${TRINITY_NETDEV:-}"
DRY_RUN=

usage() {
    sed -n '/^# USAGE:/,/^[^#]/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

die() { echo "setup-fault-injectors: ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pid)       TARGET_PID="$2"; shift 2 ;;
        --prob)      PROB="$2";       shift 2 ;;
        --netdev)    NETDEV="$2";     shift 2 ;;
        --state)     STATE_FILE="$2"; shift 2 ;;
        --dry-run)   DRY_RUN=1;       shift   ;;
        -h|--help)   usage 0 ;;
        *)           die "Unknown argument: $1 (try --help)" ;;
    esac
done

# ---------------------------------------------------------------------------
# Validate PROB
# ---------------------------------------------------------------------------
# Accept only integers in 1..100; reject non-numeric and out-of-range values.
# Both TRINITY_FAULT_PROB (env) and --prob N go through PROB; validate once
# after argument parsing so the same check covers both sources.
if ! [[ "${PROB}" =~ ^[1-9][0-9]*$ ]] || [[ 10#${PROB} -lt 1 ]] || [[ 10#${PROB} -gt 100 ]]; then # ^[1-9][0-9]*$ rejects leading zeros (08/007); 10# forces decimal in arithmetic
    die "invalid probability '${PROB}': must be an integer in 1..100 (set via --prob or TRINITY_FAULT_PROB)" # fast-fail: no state file written on invalid input; runner will report "has not run"
fi

# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------
if [[ "${EUID:-$(id -u)}" -ne 0 ]] && [[ -z "${DRY_RUN}" ]]; then
    die "must be run as root (CAP_SYS_RESOURCE required for fault-inject attrs)"
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
DEBUGFS=""
for _mnt in /sys/kernel/debug /debug; do
    if [[ -d "${_mnt}" ]] && mountpoint -q "${_mnt}" 2>/dev/null; then
        DEBUGFS="${_mnt}"
        break
    fi
done
# If not a mountpoint but the directory exists and is populated, use it anyway.
if [[ -z "${DEBUGFS}" ]] && [[ -d /sys/kernel/debug/failslab ]]; then
    DEBUGFS=/sys/kernel/debug
fi
[[ -n "${DEBUGFS}" ]] || die "debugfs not found or not mounted — cannot arm fault injectors"

write_attr() {
    local file="$1" value="$2"
    if [[ -n "${DRY_RUN}" ]]; then
        echo "[dry-run] echo ${value} > ${file}"
        return
    fi
    if [[ ! -e "${file}" ]]; then
        echo "  SKIP (absent): ${file}" >&2
        return
    fi
    echo "${value}" > "${file}" || { echo "  WARN: failed to write ${value} to ${file}" >&2; return; }
}

# Resolve the network interface for fail_skb_realloc devname filter.
# The filter is load-bearing: without it the injector arms against every netdev
# on the host, including the real management interface.
# Returns the first non-loopback virtual/dummy interface (no physical
# device/driver backing), or empty string if none found.  Set TRINITY_NETDEV
# or --netdev to force a specific interface.
resolve_netdev() {
    if [[ -n "${NETDEV}" ]]; then
        echo "${NETDEV}"; return
    fi
    local iface
    for iface in $(ls /sys/class/net/ 2>/dev/null); do
        [[ "${iface}" == "lo" ]] && continue
        # Prefer dummy/veth interfaces (lower blast radius on the host).
        if [[ -e /sys/class/net/${iface}/type ]]; then
            local iftype
            iftype=$(cat /sys/class/net/${iface}/type 2>/dev/null || echo 0)
            # ARPHRD_ETHER=1; dummy/veth are also 1 but report driver in uevent.
            if [[ -e /sys/class/net/${iface}/device/driver ]]; then
                : # real hardware — skip
            else
                # No physical device backing → virtual (dummy/veth/macvlan/etc.)
                echo "${iface}"; return
            fi
        fi
    done
    echo ""
}

# ---------------------------------------------------------------------------
# Arm fault injectors
# ---------------------------------------------------------------------------
# Tracking: per-injector armed flags and aggregate count.  An injector is
# considered "armed" only when its debugfs directory exists AND a non-zero
# probability was successfully written (confirmed by read-back for failslab;
# analogous check applied to the remaining injectors).  Mere directory
# presence means "compiled in", not "armed" — the two are not the same.
_arm_count=0
_failslab_armed=0
_fail_page_alloc_armed=0
_fail_usercopy_armed=0
_fail_futex_armed=0
_fail_sunrpc_armed=0
_fail_skb_realloc_armed=0
_netdev_armed=""

echo "setup-fault-injectors: arming fault injectors (debugfs=${DEBUGFS}, prob=${PROB})"

# Read probability back from an injector directory and confirm it is non-zero.
# In --dry-run mode no writes occur; returns 0 (success) if the directory
# exists — indicating the injector is compiled in, not that it is armed.
# Returns 0 (success/present or armed) or 1 (absent/not armed).
confirm_prob_armed() {
    local dir="$1"
    if [[ -n "${DRY_RUN}" ]]; then
        [[ -d "${dir}" ]]
        return
    fi
    local val
    val=$(cat "${dir}/probability" 2>/dev/null || echo 0)
    [[ "${val}" -gt 0 ]] 2>/dev/null
}

# Common attributes applied to every injector before injector-specific ones.
# Order matters for fail_skb_realloc: devname BEFORE probability so
# the injector is never briefly armed without a device filter.
arm_common() {
    local inj="$1"
    local d="${DEBUGFS}/${inj}"
    write_attr "${d}/interval"  1
    write_attr "${d}/times"    -1
    write_attr "${d}/space"     0
    write_attr "${d}/verbose"   2
}

# --- failslab ---------------------------------------------------------------
# GFP context: task.  Must clear ignore-gfp-wait (defaults 1 on most kernels,
# which skips every GFP_KERNEL alloc → near-zero effective injection rate).
_inj=failslab
if [[ -d "${DEBUGFS}/${_inj}" ]]; then
    echo "  ${_inj}: task-filter=1 ignore-gfp-wait=0 prob=${PROB}"
    arm_common "${_inj}"
    write_attr "${DEBUGFS}/${_inj}/task-filter"      1
    write_attr "${DEBUGFS}/${_inj}/ignore-gfp-wait"  0
    write_attr "${DEBUGFS}/${_inj}/probability"      "${PROB}"
    # Confirm write succeeded by reading probability back.
    if confirm_prob_armed "${DEBUGFS}/${_inj}"; then
        _failslab_armed=1
        _arm_count=$(( _arm_count + 1 ))
    fi
else
    echo "  ${_inj}: not present — skipping" >&2
fi

# --- fail_page_alloc ---------------------------------------------------------
_inj=fail_page_alloc
if [[ -d "${DEBUGFS}/${_inj}" ]]; then
    echo "  ${_inj}: task-filter=1 ignore-gfp-wait=0 ignore-gfp-highmem=0 prob=${PROB}"
    arm_common "${_inj}"
    write_attr "${DEBUGFS}/${_inj}/task-filter"       1
    # Disarm all four should_fail_alloc_page() short-circuits
    # (mm/fail_page_alloc.c:30-38):
    #   min-order=0        : kernel default 1 exempts order-0 allocs (line 30)
    #   ignore-gfp-wait=0  : maps to ignore_gfp_reclaim; default 1 exempts
    #                        GFP_RECLAIM/GFP_WAIT callers (line 38)
    #   ignore-gfp-highmem=0: default true exempts __GFP_HIGHMEM allocs
    #                        (line 35), silently dropping anonymous page-faults
    #                        and page-cache fills on x86_64
    #   __GFP_NOFAIL       : no trinity allocation path sets NOFAIL, so
    #                        that check (line 32) needs no knob adjustment
    write_attr "${DEBUGFS}/${_inj}/min-order"         0
    write_attr "${DEBUGFS}/${_inj}/ignore-gfp-wait"   0
    write_attr "${DEBUGFS}/${_inj}/ignore-gfp-highmem" 0
    write_attr "${DEBUGFS}/${_inj}/probability"       "${PROB}"
    if confirm_prob_armed "${DEBUGFS}/${_inj}"; then
        _fail_page_alloc_armed=1
        _arm_count=$(( _arm_count + 1 ))
    fi
else
    echo "  ${_inj}: not present — skipping" >&2
fi

# --- fail_usercopy -----------------------------------------------------------
_inj=fail_usercopy
if [[ -d "${DEBUGFS}/${_inj}" ]]; then
    echo "  ${_inj}: task-filter=1 prob=${PROB}"
    arm_common "${_inj}"
    write_attr "${DEBUGFS}/${_inj}/task-filter"  1
    write_attr "${DEBUGFS}/${_inj}/probability"  "${PROB}"
    if confirm_prob_armed "${DEBUGFS}/${_inj}"; then
        _fail_usercopy_armed=1
        _arm_count=$(( _arm_count + 1 ))
    fi
else
    echo "  ${_inj}: not present — skipping" >&2
fi

# --- fail_futex --------------------------------------------------------------
_inj=fail_futex
if [[ -d "${DEBUGFS}/${_inj}" ]]; then
    echo "  ${_inj}: task-filter=1 prob=${PROB}"
    arm_common "${_inj}"
    write_attr "${DEBUGFS}/${_inj}/task-filter"  1
    write_attr "${DEBUGFS}/${_inj}/probability"  "${PROB}"
    if confirm_prob_armed "${DEBUGFS}/${_inj}"; then
        _fail_futex_armed=1
        _arm_count=$(( _arm_count + 1 ))
    fi
else
    echo "  ${_inj}: not present — skipping" >&2
fi

# --- fail_sunrpc -------------------------------------------------------------
# Runs in kthread context; kthreads satisfy in_task() so task-filter=1 is safe.
_inj=fail_sunrpc
if [[ -d "${DEBUGFS}/${_inj}" ]]; then
    echo "  ${_inj}: task-filter=1 prob=${PROB}"
    arm_common "${_inj}"
    write_attr "${DEBUGFS}/${_inj}/task-filter"  1
    write_attr "${DEBUGFS}/${_inj}/probability"  "${PROB}"
    if confirm_prob_armed "${DEBUGFS}/${_inj}"; then
        _fail_sunrpc_armed=1
        _arm_count=$(( _arm_count + 1 ))
    fi
else
    echo "  ${_inj}: not present — skipping" >&2
fi

# --- fail_skb_realloc --------------------------------------------------------
# Runs in softirq/NAPI context: in_task()=false.  Applying task-filter=1
# would silently disarm the injector (lib/fault-inject.c:149 short-circuits on
# task_filter when !in_task()).  Use devname scoping ONLY.
# devname MUST be written BEFORE probability or the injector
# arms briefly against every netdev on the host.
# The kernel sets filtered internally via devname_write(); there is no
# userspace-writable filtered file in debugfs.
_inj=fail_skb_realloc
if [[ -d "${DEBUGFS}/${_inj}" ]]; then
    _netdev=$(resolve_netdev)
    if [[ -z "${_netdev}" ]]; then
        echo "  ${_inj}: WARN: no suitable network interface found — skipping (set TRINITY_NETDEV or --netdev)" >&2
    else
        _netdev_armed=${_netdev}
        echo "  ${_inj}: devname=${_netdev} prob=${PROB}  [NO task-filter: softirq context; filtered set by kernel via devname]"
        arm_common "${_inj}"
        # Device filter BEFORE probability — order is load-bearing.
        write_attr "${DEBUGFS}/${_inj}/devname"     "${_netdev}"
        # Confirm devname was accepted before arming probability.
        # Under --dry-run write_attr is a no-op; the readback will be empty
        # even when the injector is compiled in.  Short-circuit to directory
        # presence (same policy as confirm_prob_armed()).
        if [[ -n "${DRY_RUN}" ]] || { _dn_read=$(cat "${DEBUGFS}/${_inj}/devname" 2>/dev/null || true); [[ -n "${_dn_read}" ]]; }; then
            write_attr "${DEBUGFS}/${_inj}/probability" "${PROB}"
            if confirm_prob_armed "${DEBUGFS}/${_inj}"; then
                _fail_skb_realloc_armed=1
                _arm_count=$(( _arm_count + 1 ))
            fi
        else
            echo "  ${_inj}: WARN: devname write did not take — skipping" >&2
        fi  # devname readback guard
    fi
else
    echo "  ${_inj}: not present — skipping" >&2
fi

# ---------------------------------------------------------------------------
# make-it-fail: scope injection to the trinity process tree
# ---------------------------------------------------------------------------
# task->make_it_fail is copied through dup_task_struct(); writing 1 here
# and then forking run-trinity.sh (or having run-trinity.sh call this with
# its own PID) scopes all task-filtered injectors to the trinity subtree only.
make_it_fail_pid=""
if [[ -n "${TARGET_PID}" ]]; then
    _mif="/proc/${TARGET_PID}/make-it-fail"
    if [[ -e "${_mif}" ]]; then
        echo "setup-fault-injectors: arming make-it-fail for PID ${TARGET_PID}"
        write_attr "${_mif}" 1
        make_it_fail_pid="${TARGET_PID}"
    else
        echo "  WARN: /proc/${TARGET_PID}/make-it-fail not found (PID gone?)" >&2
    fi
fi

# ---------------------------------------------------------------------------
# /proc/lockdep_stats: relax readability
# ---------------------------------------------------------------------------
# /proc/lockdep_stats is created with mode 0400 (root-read-only) by
# kernel/lockdep_proc.c.  The unprivileged runner needs to read it to
# determine whether lockdep is live or self-disabled (debug_locks=0).
# chmod o+r is safe: the file is read-only even for root; there is no
# write path and no security-sensitive data beyond lock statistics.
lockdep_stats_readable=0
if [[ -e /proc/lockdep_stats ]]; then
    if [[ -n "${DRY_RUN}" ]]; then
        echo "[dry-run] chmod o+r /proc/lockdep_stats"
        lockdep_stats_readable=1
    else
        if chmod o+r /proc/lockdep_stats 2>/dev/null; then
            echo "setup-fault-injectors: /proc/lockdep_stats chmod o+r OK"
            lockdep_stats_readable=1
        else
            echo "  WARN: chmod o+r /proc/lockdep_stats failed" >&2
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Write state file
# ---------------------------------------------------------------------------
STATE_DIR=$(dirname "${STATE_FILE}")
if [[ -n "${DRY_RUN}" ]]; then
    echo "[dry-run] mkdir -p ${STATE_DIR} && write ${STATE_FILE}"
else
    mkdir -p "${STATE_DIR}"
fi

emit_state() {
    if [[ -n "${DRY_RUN}" ]]; then
        cat <<EOF
# Generated by setup-fault-injectors.sh at $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Consumed by run-trinity.sh; key=value, world-readable.
# DRY-RUN: no writes occurred; *_present keys reflect compiled-in status only.
# Arm state is unknown without a privileged run.
injectors_armed=unknown
injectors_armed_reason=dry_run
fault_probability=${PROB}
lockdep_stats_readable=${lockdep_stats_readable}
make_it_fail_pid=${make_it_fail_pid}
failslab_present=${_failslab_armed}
fail_page_alloc_present=${_fail_page_alloc_armed}
fail_usercopy_present=${_fail_usercopy_armed}
fail_futex_present=${_fail_futex_armed}
fail_sunrpc_present=${_fail_sunrpc_armed}
fail_skb_realloc_present=${_fail_skb_realloc_armed}
fail_skb_realloc_devname=${_netdev_armed}
debugfs_path=${DEBUGFS}
EOF
    else
        cat <<EOF
# Generated by setup-fault-injectors.sh at $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Consumed by run-trinity.sh; key=value, world-readable.
# injectors_armed=1 only when at least one injector has a confirmed non-zero
# probability — directory existence (compiled in) is not sufficient.
injectors_armed=$(( _arm_count > 0 ? 1 : 0 ))
injectors_armed_reason=ok
fault_probability=${PROB}
lockdep_stats_readable=${lockdep_stats_readable}
make_it_fail_pid=${make_it_fail_pid}
failslab_armed=${_failslab_armed}
fail_page_alloc_armed=${_fail_page_alloc_armed}
fail_usercopy_armed=${_fail_usercopy_armed}
fail_futex_armed=${_fail_futex_armed}
fail_sunrpc_armed=${_fail_sunrpc_armed}
fail_skb_realloc_armed=${_fail_skb_realloc_armed}
fail_skb_realloc_devname=${_netdev_armed}
debugfs_path=${DEBUGFS}
EOF
    fi
}

if [[ -n "${DRY_RUN}" ]]; then
    echo "--- state file (dry-run) ---"
    emit_state
    echo "---"
else
    emit_state > "${STATE_FILE}"
    chmod 0644 "${STATE_FILE}"
    echo "setup-fault-injectors: state written to ${STATE_FILE}"
fi

echo "setup-fault-injectors: done."
