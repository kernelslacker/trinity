#pragma once

/*
 * Root-gated parent-side startup isolation: in the parent's brief
 * root window (after do_uid0_check, before fork_children) we
 * unshare(CLONE_NEWNET|CLONE_NEWNS) and remount / as
 * MS_REC|MS_PRIVATE.  Successful steps latch shm->isolation.*_ready
 * so children skip the matching per-child unshare and inherit the
 * provisioned ns via fork().
 *
 * Stage 1 of the netns/mountns childop-coverage track -- pure spine.
 * No network or mount provisioning yet (later stages add lo-up and
 * the scratch block pool).  Any failure (non-root, EPERM, ENOSYS,
 * --no-startup-isolation) leaves both latches false and the children
 * take the existing per-child unshare path -- behaviour is
 * byte-for-byte unchanged from a non-root run.
 */
void setup_startup_isolation(void);
