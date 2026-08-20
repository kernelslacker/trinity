#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# setup-privileged-preconditions.sh — privileged pre-run helper for tracefs coverage
#
# Must be run as root (CAP_SYS_ADMIN required to mount tracefs;
# CAP_DAC_OVERRIDE required to relax permissions on 0640 tracefs files).
#
# Ensures tracefs is mounted at a stable path and that the tracefs control
# files are writable by the unprivileged trinity runner.  Without this:
#
#   (1) tracefs_fuzzer_init() (childops/fs/tracefs-fuzzer.c:1503-1516) probes
#       <root>/tracing_on with access(F_OK); if neither candidate root exists
#       the childop latches CHILDOP_LATCH_UNSUPPORTED and exits immediately.
#
#   (2) Even with the mount present, all tracefs control files are mode 0640
#       root:root (kernel/trace/trace.h:34 TRACE_MODE_WRITE 0640).  After the
#       child process drops privileges the runtime probe at
#       childops/fs/tracefs-fuzzer.c:1579-1594 calls access(W_OK) on
#       tracing_on, gets EACCES, sets tracefs_runtime_dead, and every
#       subsequent call returns immediately without exercising anything.
#
# This script is idempotent: if the mount already exists and the permissions
# are already relaxed it exits 0 without making any changes.
#
# USAGE:
#   sudo scripts/setup-privileged-preconditions.sh [OPTIONS]
#
# OPTIONS:
#   --mount-point PATH   Tracefs mount point (default: /sys/kernel/tracing)
#   --group GROUP        Group to own the tracefs tree (default: current user's
#                        primary group, or "nogroup" if run as root without a
#                        target user set via TRINITY_USER)
#   --user USER          Unprivileged user that will run trinity
#                        (overrides --group: uses that user's primary group)
#   --mode MODE          Permission bits for tracefs files (default: 0664)
#   --dry-run            Print what would be done; do not change anything
#   -h, --help           Show this message
#
# ENVIRONMENT:
#   TRINITY_USER         Unprivileged user that will run trinity (same as --user)
#
# EXAMPLES:
#   # Mount tracefs and grant access to the current user (running under sudo):
#   sudo scripts/setup-privileged-preconditions.sh --user "$SUDO_USER"
#
#   # Mount tracefs; world-writable (broadest access, development only):
#   sudo scripts/setup-privileged-preconditions.sh --mode 0666
#
#   # Preview without writing:
#   sudo scripts/setup-privileged-preconditions.sh --dry-run

set -Eeuo pipefail

MOUNT_POINT="/sys/kernel/tracing"
TARGET_USER="${TRINITY_USER:-${SUDO_USER:-}}"
TARGET_GROUP=""
FILE_MODE="0664"
DRY_RUN=

usage() {
    sed -n '/^# USAGE:/,/^[^#]/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

die()  { echo "setup-privileged-preconditions: ERROR: $*" >&2; exit 1; }
info() { echo "setup-privileged-preconditions: $*"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mount-point) MOUNT_POINT="$2"; shift 2 ;;
        --group)       TARGET_GROUP="$2"; shift 2 ;;
        --user)        TARGET_USER="$2"; shift 2 ;;
        --mode)        FILE_MODE="$2"; shift 2 ;;
        --dry-run)     DRY_RUN=1; shift ;;
        -h|--help)     usage 0 ;;
        *)             die "Unknown argument: $1 (try --help)" ;;
    esac
done

# ---------------------------------------------------------------------------
# Resolve target group
# ---------------------------------------------------------------------------
# If --user or TRINITY_USER was given, look up their primary group.
# Fall back to the invoking user's group (common when run via sudo --user).
if [[ -n "${TARGET_USER}" ]]; then
    TARGET_GROUP=$(id -gn "${TARGET_USER}" 2>/dev/null) \
        || die "cannot resolve primary group for user '${TARGET_USER}'"
elif [[ -z "${TARGET_GROUP}" ]]; then
    # No user or group specified; use the real UID's group if not root,
    # otherwise leave TARGET_GROUP empty and apply world-writable mode bits.
    _real_uid="${SUDO_UID:-${UID:-$(id -u)}}"
    if [[ "${_real_uid}" -ne 0 ]]; then
        TARGET_GROUP=$(id -gn "${_real_uid}" 2>/dev/null || true)
    fi
fi

# Validate FILE_MODE: must be a valid octal string (3 or 4 digits, all 0-7).
if ! [[ "${FILE_MODE}" =~ ^0[0-7]{3}$ ]]; then
    die "invalid mode '${FILE_MODE}': must be an octal permission string (e.g. 0664, 0666)"
fi

# Derive DIR_MODE from FILE_MODE: OR the execute/search bit into every
# non-zero rwx triad.  Example: 0664 (rw-rw-r--) -> 0775 (rwxrwxr-x).
# Derived here (after FILE_MODE is validated) so both the idempotency latch
# predicate below and the enforcement chmod step can share one derivation.
_fm_val=$(( 8#${FILE_MODE#0} ))
_o=$(( (_fm_val >> 6) & 7 )); [[ $_o -ne 0 ]] && _o=$(( _o | 1 ))
_g=$(( (_fm_val >> 3) & 7 )); [[ $_g -ne 0 ]] && _g=$(( _g | 1 ))
_w=$(( _fm_val & 7 ));        [[ $_w -ne 0 ]] && _w=$(( _w | 1 ))
DIR_MODE=$(printf "0%o" $(( (_o << 6) | (_g << 3) | _w )))

# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------
if [[ "${EUID:-$(id -u)}" -ne 0 ]] && [[ -z "${DRY_RUN}" ]]; then
    die "must be run as root (CAP_SYS_ADMIN required for mount, CAP_DAC_OVERRIDE for chmod)"
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# dry_run_or_exec CMD [ARGS...]: in dry-run mode print the command; otherwise
# execute it.  Use for all privileged mutating operations.
dry_run_or_exec() {
    if [[ -n "${DRY_RUN}" ]]; then
        echo "[dry-run] $*"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# State file: variables, emit_state, and EXIT trap
# ---------------------------------------------------------------------------
# _tracefs_ready_val starts as 'unknown'; Step 3 promotes it to '1' on
# success.  By defining emit_state and _spp_write_state here, and registering
# an EXIT trap, tracefs.state is written on every code path — including any
# early exit triggered by set -e before the normal write point at the bottom.
_tracefs_ready_val=unknown
_spp_state_file="/run/trinity/tracefs.state"
_spp_state_dir=$(dirname "${_spp_state_file}")

emit_state() {
    if [[ -n "${DRY_RUN}" ]]; then
        cat <<EOF
# Generated by setup-privileged-preconditions.sh at $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Consumed by run-trinity.sh; key=value, world-readable.
# DRY-RUN: no writes occurred; tracefs_ready state is unknown without a privileged run.
tracefs_ready=unknown
mount_point=${MOUNT_POINT}
file_mode=${FILE_MODE}
EOF
    else
        cat <<EOF
# Generated by setup-privileged-preconditions.sh at $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Consumed by run-trinity.sh; key=value, world-readable.
tracefs_ready=${_tracefs_ready_val}
mount_point=${MOUNT_POINT}
file_mode=${FILE_MODE}
EOF
    fi
}

_spp_write_state() {
    if [[ -n "${DRY_RUN}" ]]; then
        echo "[dry-run] mkdir -p ${_spp_state_dir} && write ${_spp_state_file}"
        echo "--- state file (dry-run) ---"
        emit_state
        echo "---"
    else
        mkdir -p "${_spp_state_dir}"
        chmod 0755 "${_spp_state_dir}"
        # Write atomically via a temp file so a partial write (full /run,
        # permission error) never leaves a truncated state file visible to
        # run-trinity.sh.  grep verifies the last key file_mode= is present
        # before the mv; a truncation after any earlier key still fails the
        # check and the partial file is discarded.  If mv fails, remove
        # the temp and warn; run-trinity.sh will fall back to the "state file
        # absent" branch which is accurate.
        local _spp_tmp
        _spp_tmp=$(mktemp "${_spp_state_file}.XXXXXX")             || { echo "setup-privileged-preconditions: WARNING: mktemp failed; state file not written" >&2; return; }
        if emit_state > "${_spp_tmp}" && grep -q ^file_mode= "${_spp_tmp}"; then
            if ! mv "${_spp_tmp}" "${_spp_state_file}"; then
                rm -f "${_spp_tmp}"
                echo "setup-privileged-preconditions: WARNING: mv ${_spp_tmp} -> ${_spp_state_file} failed; state file not written" >&2
                return
            fi
        else
            rm -f "${_spp_tmp}"
            echo "setup-privileged-preconditions: WARNING: emit_state failed; state file not written" >&2
            return
        fi
        chmod 0644 "${_spp_state_file}"
        info "state written to ${_spp_state_file}"
    fi
}
trap '_spp_write_state' EXIT
# Guard: MOUNT_POINT, TARGET_USER, TARGET_GROUP, FILE_MODE are all assigned
# unconditionally at lines 55-59 (before argument parsing may override them)
# and cannot be unset at this point.  Under set -u any reference to an unset
# variable in emit_state() would abort the EXIT trap body, so it is important
# that no path between here and the trap registration can unset them.  The
# only mutation below is TARGET_GROUP (resolved from TARGET_USER or SUDO_UID)
# which is always assigned an explicit value (possibly empty string) before
# the Steps begin.

# ---------------------------------------------------------------------------
# ERR trap: Steps 1-3
# ---------------------------------------------------------------------------
# set -e aborts on any unhandled command failure.  Without this trap,
# a failing dry_run_or_exec mount (or any other non-die failure path) exits
# with _tracefs_ready_val still 'unknown', and run-trinity.sh emits the soft
# "tracefs_ready != 1 ... coverage may be disabled" warning instead of the
# hard failure message.  Trap ERR across Steps 1-3 so that any set -e abort
# sets the failed marker; cleared with 'trap - ERR' after Step 3.
trap '_tracefs_ready_val=failed' ERR

# ---------------------------------------------------------------------------
# Step 1: Ensure tracefs is mounted
# ---------------------------------------------------------------------------
#
# tracefs_fuzzer_init() (childops/fs/tracefs-fuzzer.c:1503-1516) probes the
# first candidate root whose <root>/tracing_on exists via access(F_OK).  The
# candidate list (childops/fs/tracefs-fuzzer.c:66-68) is, in order:
#   /sys/kernel/tracing   -- dedicated tracefs mount (kernels >= 4.1)
#   /sys/kernel/debug/tracing -- tracefs mounted under debugfs (older kernels)
#
# We prefer the dedicated mount at /sys/kernel/tracing.  If tracefs is already
# mounted there (or the tracing_on file is otherwise accessible) we skip the
# mount step entirely.

TRACEFS_ALREADY_MOUNTED=
if mountpoint -q "${MOUNT_POINT}" 2>/dev/null; then
    TRACEFS_ALREADY_MOUNTED=1
elif [[ -e "${MOUNT_POINT}/tracing_on" ]]; then
    # Directory exists and has the sentinel file; probably already mounted
    # (mountpoint(1) can give false negatives inside containers).
    TRACEFS_ALREADY_MOUNTED=1
fi

if [[ -n "${TRACEFS_ALREADY_MOUNTED}" ]]; then
    info "tracefs already mounted at ${MOUNT_POINT} — skipping mount step"
else
    # Create the mount point directory if it does not exist.
    if [[ ! -d "${MOUNT_POINT}" ]]; then
        dry_run_or_exec mkdir -p "${MOUNT_POINT}"
    fi

    # Mount tracefs.  The filesystem name is "tracefs"; it is registered by
    # the kernel in kernel/trace/trace.c via register_filesystem(&trace_fs_type).
    # CAP_SYS_ADMIN is required.
    dry_run_or_exec mount -t tracefs tracefs "${MOUNT_POINT}"

    if [[ -z "${DRY_RUN}" ]]; then
        info "tracefs mounted at ${MOUNT_POINT}"
    fi
fi

# Verify that the tracing_on sentinel exists (confirms the mount worked and
# that CONFIG_TRACING is enabled in this kernel).
if [[ -z "${DRY_RUN}" ]]; then
    if [[ ! -e "${MOUNT_POINT}/tracing_on" ]]; then
        _tracefs_ready_val=failed
        die "${MOUNT_POINT}/tracing_on not found after mount — is CONFIG_TRACING enabled in this kernel?"
    fi
fi

# ---------------------------------------------------------------------------
# Step 2: Relax tracefs file permissions
# ---------------------------------------------------------------------------
#
# All tracefs control files are created with mode 0640 root:root.  The
# specific mode constant is TRACE_MODE_WRITE in kernel/trace/trace.h:34.
# Individual files also use TRACE_MODE_READ (0440) for read-only files and
# combinations thereof; the fuzzer needs write access to the control files it
# targets (tracing_on, kprobe_events, uprobe_events, set_ftrace_filter, etc.).
#
# Strategy: chgrp the entire tree to the target group, then chmod to the
# requested mode.  We use find(1) to touch only regular files and directories,
# skipping symlinks and device nodes (tracefs exposes no devices, but being
# explicit avoids surprises on non-standard kernel builds).
#
# This is idempotent: running a second time with the same group and mode is a
# no-op in effect (the chmod/chgrp calls succeed silently even if nothing
# changes).

# Check whether permissions already satisfy the requirements to avoid
# spurious output on re-runs.
_tracing_on="${MOUNT_POINT}/tracing_on"
_perms_ok=

if [[ -z "${DRY_RUN}" ]] && [[ -e "${_tracing_on}" ]]; then
    # Use -e rather than -w: root can always write so the -w test carried
    # no information about whether the *unprivileged runner* can write.
    _perms_ok=1
    info "${_tracing_on} exists — scanning tree for wrong group or mode"
    if [[ -n "${TARGET_GROUP}" ]]; then
        # Scan the whole tree; stop at the first entry that needs attention.
        # Test files against FILE_MODE and directories against DIR_MODE so that
        # a correctly-configured tree (dirs at DIR_MODE, files at FILE_MODE)
        # satisfies the predicate and the latch fires.
        if ! _need_work=$(find "${MOUNT_POINT}" \( -type f -o -type d \) \
                \( ! -group "${TARGET_GROUP}" \
                   -o \( -type f ! -perm "${FILE_MODE#0}" \) \
                   -o \( -type d ! -perm "${DIR_MODE#0}" \) \
                \) -print -quit 2>&1); then
            _need_work=1  # find failed -- cannot verify; must enforce
        fi
        if [[ -z "${_need_work}" ]]; then
            info "all entries in ${MOUNT_POINT} already have group '${TARGET_GROUP}' and correct modes — skipping chgrp/chmod"
            _perms_ok=2  # 2 = fully done, skip both steps
        else
            _perms_ok=1  # at least one entry needs chgrp/chmod
        fi
    fi
fi

# Part 2: if no group is set and the world-write bit is absent the
# unprivileged runner cannot write tracefs regardless of what chmod does:
# chgrp is skipped, the group bits are inaccessible, and world-write is
# also absent.  Die loudly rather than silently writing tracefs_ready=unknown
# every boot and leaving the operator puzzled about missing coverage.
if [[ -z "${DRY_RUN}" ]] && [[ -z "${TARGET_GROUP}" ]] && [[ $(( FILE_MODE & 2 )) -eq 0 ]]; then
    _tracefs_ready_val=failed
    die "cannot grant unprivileged write access to tracefs: TARGET_GROUP is empty (root invoked without --user / TRINITY_USER / SUDO_USER) and FILE_MODE '${FILE_MODE}' has no world-write bit — chgrp is skipped so group-write bits are inaccessible; re-run with --user USER or --mode 0666"
fi

if [[ "${_perms_ok}" != "2" ]]; then
    if [[ -n "${TARGET_GROUP}" ]]; then
        # chgrp: assign the target group to every regular file and directory
        # under MOUNT_POINT (symlinks and non-regular entries are skipped, to
        # match the predicate used by the latch scan above).
        # kernel/trace/trace.h:34 TRACE_MODE_WRITE 0640 means without this
        # chgrp the group bits (0040 r-- for the group) are irrelevant to any
        # group other than root.
        if ! dry_run_or_exec find "${MOUNT_POINT}" \( -type f -o -type d \) -exec chgrp "${TARGET_GROUP}" {} +; then
            _enforcement_failed="${_enforcement_failed:-}chgrp "
            info "WARNING: chgrp ${TARGET_GROUP} encountered errors under ${MOUNT_POINT} — continuing"
        elif [[ -z "${DRY_RUN}" ]]; then
            info "chgrp ${TARGET_GROUP} (files+dirs) under ${MOUNT_POINT}"
        fi
    fi

    # chmod: relax the write bit for the group (or world if no group given).
    # Regular files receive FILE_MODE; directories receive DIR_MODE, which
    # ORs the execute/search bit into every non-zero rwx triad of FILE_MODE
    # so the runner can traverse the tree.
    #
    # Two separate find(1) invocations are used — one for -type f and one for
    # -type d — rather than chmod -R so that symlinks and device nodes are left
    # untouched (tracefs does not create such entries, but defensive coding is
    # warranted when touching a kernel filesystem via CAP_DAC_OVERRIDE).

    if ! dry_run_or_exec find "${MOUNT_POINT}" -type f -exec chmod "${FILE_MODE}" {} +; then
        _enforcement_failed="${_enforcement_failed:-}chmod-files "
        info "WARNING: chmod ${FILE_MODE} (files) encountered errors under ${MOUNT_POINT} — continuing"
    fi
    if ! dry_run_or_exec find "${MOUNT_POINT}" -type d -exec chmod "${DIR_MODE}"  {} +; then
        _enforcement_failed="${_enforcement_failed:-}chmod-dirs "
        info "WARNING: chmod ${DIR_MODE} (dirs) encountered errors under ${MOUNT_POINT} — continuing"
    fi

    if [[ -z "${DRY_RUN}" ]] && [[ -z "${_enforcement_failed:-}" ]]; then
        info "chmod ${FILE_MODE} (files) / ${DIR_MODE} (dirs) under ${MOUNT_POINT}"
    fi
fi

# ---------------------------------------------------------------------------
# Step 3: Verify unprivileged write access
# ---------------------------------------------------------------------------
#
# Confirm that the target user can actually write tracing_on after the chmod
# above.  This catches gaps such as a read-only bind-mount or an LSM denial
# that would cause tracefs_fuzzer_init() to set tracefs_runtime_dead anyway.
#
# _tracefs_ready_val is the measured result written to the state file.
# It is initialised to 'unknown' early in the script and promoted to '1'
# only when this step runs and passes.  When TARGET_USER is empty (root
# login / systemd unit / cron / su -) the guard below means verification
# never runs, so we cannot claim ready=1; leave it 'unknown'.
if [[ -z "${DRY_RUN}" ]] && [[ -n "${TARGET_USER}" ]]; then
    if ! runuser -u "${TARGET_USER}" -- test -w "${MOUNT_POINT}/tracing_on" 2>/dev/null; then
        _tracefs_ready_val=failed
        die "post-condition failed: ${TARGET_USER} cannot write ${MOUNT_POINT}/tracing_on"
    fi
    info "verified: ${TARGET_USER} can write ${MOUNT_POINT}/tracing_on"
    _tracefs_ready_val=1
fi

# Steps 1-3 complete; clear ERR trap so subsequent non-fatal operations
# (summary output, state-file writes) don't accidentally set failed.
trap - ERR

# ---------------------------------------------------------------------------
# Summary  (tracefs.state is written by the EXIT trap registered above)
# ---------------------------------------------------------------------------
if [[ -n "${DRY_RUN}" ]]; then
    echo "setup-privileged-preconditions: dry-run complete — no changes made"
else
    info "done: tracefs at ${MOUNT_POINT} is ready for the unprivileged runner"
    if [[ -n "${TARGET_GROUP}" ]]; then
        info "  group=${TARGET_GROUP}  mode=${FILE_MODE}"
    else
        info "  mode=${FILE_MODE} (no group specified; world-writable bits applied)"
    fi
fi
