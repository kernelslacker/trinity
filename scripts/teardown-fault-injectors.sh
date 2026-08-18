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
# fail_futex, fail_sunrpc) go inert automatically when the trinity process
# tree exits because task->make_it_fail is not inherited across exec and is
# cleared on task exit.  fail_skb_realloc is NOT task-filtered (it uses a
# devname filter instead, since softirq/NAPI context has in_task()=false) and
# stays armed at the configured probability for EVERY process on the host
# until explicitly disarmed or the host reboots.  Run this script after every
# fuzz run.
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
        --debugfs)  DEBUGFS_OVERRIDE="$2"; shift 2 ;;
        --dry-run)  DRY_RUN=1;             shift   ;;
        -h|--help)  usage 0 ;;
        *)          die "Unknown argument: $1 (try --help)" ;;
    esac
done

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
        return
    fi
    echo "${value}" > "${file}" || { echo "  WARN: failed to write ${value@Q} to ${file}" >&2; return; }
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
#   1. Write "" to devname — this calls devname_write() → reset_settings(),
#      which clears the filtered flag and resets internal state.
#   2. Write 0 to probability — belt-and-suspenders; reset_settings() already
#      zeros probability, but an explicit write is clearer and idempotent.
_inj=fail_skb_realloc
if [[ -d "${DEBUGFS}/${_inj}" ]]; then
    echo "  ${_inj}: devname -> '' (clears filtered via reset_settings()), probability -> 0"
    write_attr "${DEBUGFS}/${_inj}/devname"     ""
    write_attr "${DEBUGFS}/${_inj}/probability" 0
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

echo "teardown-fault-injectors: done."
