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

set -euo pipefail

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
if ! [[ "${FILE_MODE}" =~ ^0?[0-7]{3}$ ]]; then
    die "invalid mode '${FILE_MODE}': must be an octal permission string (e.g. 0664, 0666)"
fi

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
    # Check writability directly.
    if [[ -w "${_tracing_on}" ]]; then
        _perms_ok=1
        info "${_tracing_on} is already writable — checking group owner"
        # Even if the root-user itself can write (it always can), we still
        # want to relax for the unprivileged runner; proceed unless the file
        # is already in the correct group.
        if [[ -n "${TARGET_GROUP}" ]]; then
            _cur_grp=$(stat -c '%G' "${_tracing_on}" 2>/dev/null || true)
            if [[ "${_cur_grp}" == "${TARGET_GROUP}" ]]; then
                info "group already '${TARGET_GROUP}' on ${_tracing_on} — skipping chgrp/chmod"
                _perms_ok=2  # 2 = fully done, skip both steps
            else
                _perms_ok=1  # needs chgrp/chmod
            fi
        fi
    fi
fi

if [[ "${_perms_ok}" != "2" ]]; then
    if [[ -n "${TARGET_GROUP}" ]]; then
        # chgrp -R: assign the target group to every file and directory.
        # kernel/trace/trace.h:34 TRACE_MODE_WRITE 0640 means without this
        # chgrp the group bits (0040 r-- for the group) are irrelevant to any
        # group other than root.
        dry_run_or_exec chgrp -R "${TARGET_GROUP}" "${MOUNT_POINT}"
        if [[ -z "${DRY_RUN}" ]]; then
            info "chgrp -R ${TARGET_GROUP} ${MOUNT_POINT}"
        fi
    fi

    # chmod: relax the write bit for the group (or world if no group given).
    # We use find to apply the mode only to regular files; directories get
    # +x as well so the runner can traverse the tree.
    #
    # We do NOT use chmod -R directly on the mount point because that would
    # also affect special files (which tracefs does not create, but defensive
    # coding is warranted when touching a kernel filesystem via CAP_DAC_OVERRIDE).
    dry_run_or_exec find "${MOUNT_POINT}" \
        \( -type f -o -type d \) \
        -exec chmod "${FILE_MODE}" {} +

    if [[ -z "${DRY_RUN}" ]]; then
        info "chmod ${FILE_MODE} on files/dirs under ${MOUNT_POINT}"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
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
