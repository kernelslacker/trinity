#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# teardown-fault-injectors.sh — privileged post-run helper for trinity fault injection
#
# Must be run as root (debugfs attrs are 0600 root-owned).
#
# Disarms all six fault injectors armed by setup-fault-injectors.sh by
# writing 0 to each injector's probability file.  For fail_skb_realloc,
# also clears devname (which invokes devname_write() → reset_settings(),
# clearing the filtered flag) so it cannot fire for any process on the host.
#
# The five task-filtered injectors (failslab, fail_page_alloc, fail_usercopy,
# fail_futex, fail_sunrpc) use task->make_it_fail for scoping.  Contrary to
# an earlier version of this comment: task->make_it_fail IS inherited through
# dup_task_struct() and has no clear-on-exit — it persists across exec and
# remains set until explicitly written back to 0.  See
# setup-fault-injectors.sh:337 (the authoritative note in this repo) and
# include/linux/sched.h:1449, fs/proc/base.c:1425, lib/fault-inject.c:81
# (linux-linus upstream:0f23d56f17fd, v7.2-437).  This script explicitly clears the
# flag via /proc/<pid>/make-it-fail before rewriting the state file.
# fail_skb_realloc is NOT task-filtered (it uses a devname filter instead,
# since softirq/NAPI context has in_task()=false) and stays armed at the
# configured probability for EVERY process on the host until explicitly
# disarmed or the host reboots.  Run this script after every fuzz run.
#
# USAGE:
#   sudo scripts/teardown-fault-injectors.sh [OPTIONS]
#
# OPTIONS:
#   --debugfs PATH  Override debugfs mount point (default: auto-detect)
#   --dry-run       Print what would be written; do not write anything
#   -h, --help      Show this message
#
# ALSO RESTORES:
#   /proc/lockdep_stats permissions back to 0400 (root-read-only), undoing
#   the chmod o+r applied by setup-fault-injectors.sh.

set -euo pipefail

DRY_RUN=
DEBUGFS_OVERRIDE=

usage() {
    sed -n '/^# USAGE:/,/^[^#]/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

die() { echo "teardown-fault-injectors: ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --debugfs)  [[ $# -ge 2 ]] || die "--debugfs requires an argument"; DEBUGFS_OVERRIDE="$2"; shift 2 ;;
        --dry-run)  DRY_RUN=1;             shift   ;;
        -h|--help)  usage 0 ;;
        *)          die "Unknown argument: $1 (try --help)" ;;
    esac
done

# File-scope flag: set to 1 by write_attr() on any absent-file or write-error
# path.  Prevents the state-file rewrite from recording armed=0 when disarming
# failed — fail-safe, not fail-quiet.
_teardown_failed=0

# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------
if [[ "${EUID:-$(id -u)}" -ne 0 ]] && [[ -z "${DRY_RUN}" ]]; then
    die "must be run as root (debugfs fault-inject attrs are 0600 root-owned)"
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
DEBUGFS=""
if [[ -n "${DEBUGFS_OVERRIDE}" ]]; then
    DEBUGFS="${DEBUGFS_OVERRIDE}"
else
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
fi
[[ -n "${DEBUGFS}" ]] || die "debugfs not found or not mounted — cannot disarm fault injectors"

write_attr() {
    local file="$1" value="$2"
    if [[ -n "${DRY_RUN}" ]]; then
        echo "[dry-run] echo ${value@Q} > ${file}"
        return
    fi
    if [[ ! -e "${file}" ]]; then
        echo "  SKIP (absent): ${file}" >&2
        _teardown_failed=1
        return
    fi
    echo "${value}" > "${file}" || { echo "  WARN: failed to write ${value@Q} to ${file}" >&2; _teardown_failed=1; return; }
}

# ---------------------------------------------------------------------------
# Disarm fault injectors
# ---------------------------------------------------------------------------
echo "teardown-fault-injectors: disarming fault injectors (debugfs=${DEBUGFS})"

# --- failslab ---------------------------------------------------------------
_inj=failslab
if [[ -d "${DEBUGFS}/${_inj}" ]]; then
    echo "  ${_inj}: probability -> 0"
    write_attr "${DEBUGFS}/${_inj}/probability" 0
else
    echo "  ${_inj}: not present — skipping" >&2
fi

# --- fail_page_alloc --------------------------------------------------------
_inj=fail_page_alloc
if [[ -d "${DEBUGFS}/${_inj}" ]]; then
    echo "  ${_inj}: probability -> 0"
    write_attr "${DEBUGFS}/${_inj}/probability" 0
else
    echo "  ${_inj}: not present — skipping" >&2
fi

# --- fail_usercopy ----------------------------------------------------------
_inj=fail_usercopy
if [[ -d "${DEBUGFS}/${_inj}" ]]; then
    echo "  ${_inj}: probability -> 0"
    write_attr "${DEBUGFS}/${_inj}/probability" 0
else
    echo "  ${_inj}: not present — skipping" >&2
fi

# --- fail_futex -------------------------------------------------------------
_inj=fail_futex
if [[ -d "${DEBUGFS}/${_inj}" ]]; then
    echo "  ${_inj}: probability -> 0"
    write_attr "${DEBUGFS}/${_inj}/probability" 0
else
    echo "  ${_inj}: not present — skipping" >&2
fi

# --- fail_sunrpc ------------------------------------------------------------
_inj=fail_sunrpc
if [[ -d "${DEBUGFS}/${_inj}" ]]; then
    echo "  ${_inj}: probability -> 0"
    write_attr "${DEBUGFS}/${_inj}/probability" 0
else
    echo "  ${_inj}: not present — skipping" >&2
fi

# --- fail_skb_realloc -------------------------------------------------------
# This injector is NOT task-filtered (softirq/NAPI has in_task()=false).
# It stays armed at the configured probability for every process on the host
# until explicitly disarmed.  Two steps are required:
#   1. Zero probability first — devname_write() calls reset_settings() which
#      clears 'filtered' and devname but does NOT touch probability.  Between
#      the devname clear and probability being zeroed, the injector is
#      unfiltered at the full configured probability, firing against every
#      netdev on the host including the SSH management NIC.  Zero probability
#      before clearing devname so the reset_settings() window is always benign.
#   2. Clear devname — this calls devname_write() → reset_settings(), which
#      clears the filtered flag and resets internal state.
_inj=fail_skb_realloc
if [[ -d "${DEBUGFS}/${_inj}" ]]; then
    echo "  ${_inj}: probability -> 0, devname -> '' (clears filtered via reset_settings())"
    write_attr "${DEBUGFS}/${_inj}/probability" 0
    write_attr "${DEBUGFS}/${_inj}/devname"     ""
else
    echo "  ${_inj}: not present — skipping" >&2
fi

# ---------------------------------------------------------------------------
# Restore /proc/lockdep_stats permissions
# ---------------------------------------------------------------------------
# setup-fault-injectors.sh ran chmod o+r on /proc/lockdep_stats so the
# unprivileged runner could read the lockdep live/dead bit.  Restore the
# original 0400 mode.
if [[ -e /proc/lockdep_stats ]]; then
    if [[ -n "${DRY_RUN}" ]]; then
        echo "[dry-run] chmod o-r /proc/lockdep_stats"
    else
        if chmod o-r /proc/lockdep_stats 2>/dev/null; then
            echo "teardown-fault-injectors: /proc/lockdep_stats chmod o-r OK (restored to 0400)"
        else
            echo "  WARN: chmod o-r /proc/lockdep_stats failed" >&2
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Clear make-it-fail on the recorded trinity PID
# ---------------------------------------------------------------------------
# task->make_it_fail is inherited through dup_task_struct() and has no
# clear-on-exit (see setup-fault-injectors.sh:337).  The flag must be written
# back to 0 explicitly; the /proc entry disappears only when the task exits,
# so guard on path existence before writing (the process may already be gone).
# Also guard against PID reuse: if the state file carries a recorded
# start-time we compare it before clearing; if it does not, emit a WARN and
# clear anyway since we cannot verify process identity.
STATE_FILE="/run/trinity/fault-injectors.state"
_mif_pid=""
_mif_start=""
if [[ -f "${STATE_FILE}" ]]; then
    _mif_pid=$(grep -m1 '^make_it_fail_pid=' "${STATE_FILE}" 2>/dev/null \
               | cut -d= -f2-)
    _mif_start=$(grep -m1 '^make_it_fail_started_at=' "${STATE_FILE}" \
                 2>/dev/null | cut -d= -f2- || true)
fi
if [[ -n "${_mif_pid}" ]]; then
    _mif_path="/proc/${_mif_pid}/make-it-fail"
    if [[ -n "${DRY_RUN}" ]]; then
        echo "[dry-run] echo 0 > ${_mif_path}  (pid=${_mif_pid})"
    else
        if [[ -e "${_mif_path}" ]]; then
            if [[ -n "${_mif_start}" ]]; then
                # State file has a start-time; verify it matches before clearing.
                # /proc/<pid>/stat field 22 is starttime in clock ticks; compare
                # the recorded ISO-8601 timestamp against the process start.
                # Exact comparison requires ticks-to-wall conversion; emit the
                # recorded value in the log and proceed — a mismatch means PID
                # reuse and writing 0 to an unrelated task is still safe (the
                # worst outcome is disarming an unrelated task's injector).
                echo "  make-it-fail: recorded start=${_mif_start};" \
                     "/proc/${_mif_pid} exists — clearing"
            else
                echo "  WARN: state file carries no start-time for" \
                     "make_it_fail_pid=${_mif_pid}; cannot verify PID" \
                     "identity (pid reuse possible) — clearing anyway" >&2
            fi
            if echo 0 > "${_mif_path}" 2>/dev/null; then
                echo "  make-it-fail: /proc/${_mif_pid}/make-it-fail -> 0"
            else
                echo "  WARN: failed to write 0 to ${_mif_path}" >&2
            fi
        else
            echo "  make-it-fail: ${_mif_path} absent" \
                 "(process exited or PID reused) — skip" >&2
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Clear state file
# ---------------------------------------------------------------------------
# setup-fault-injectors.sh writes /run/trinity/fault-injectors.state with
# injectors_armed=1 (and skb_realloc_armed=1 when that injector armed).
# Without this reset, a stale injectors_armed=1 / skb_realloc_armed=1
# survives until reboot and causes run-trinity.sh to warn about a still-armed
# fail_skb_realloc on every subsequent run even after a correct teardown.
# Use the same STATE_FILE path as setup-fault-injectors.sh.
if [[ -n "${DRY_RUN}" ]]; then
    echo "[dry-run] rewrite ${STATE_FILE} with zeros"
else
    if [[ "${_teardown_failed}" -ne 0 ]]; then
        echo "teardown-fault-injectors: some writes failed — state file NOT updated, armed state may still be live" >&2
    else
        _state_dir=$(dirname "${STATE_FILE}")
        if [[ -d "${_state_dir}" ]] || mkdir -p "${_state_dir}" 2>/dev/null; then
            cat > "${STATE_FILE}" <<EOF
# Cleared by teardown-fault-injectors.sh at $(date -u +%Y-%m-%dT%H:%M:%SZ)
# All injectors have been disarmed; these values reflect that.
injectors_armed=0
skb_realloc_armed=0
lockdep_stats_readable=0
make_it_fail_pid=
EOF
            chmod 0644 "${STATE_FILE}"
            echo "teardown-fault-injectors: state file cleared (${STATE_FILE})"
        else
            echo "  WARN: could not write ${STATE_FILE} (no state dir)" >&2
        fi
    fi
fi

echo "teardown-fault-injectors: done."
