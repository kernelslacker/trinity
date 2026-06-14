#pragma once

/*
 * Root-gated parent-side startup isolation: in the parent's brief
 * root window (after do_uid0_check, before fork_children) we
 * unshare(CLONE_NEWNET|CLONE_NEWNS), remount / as MS_REC|MS_PRIVATE,
 * bring lo UP inside the new netns and assign the loopback addresses
 * (127.0.0.1/8 + ::1/128).  Successful steps latch
 * shm->isolation.*_ready so children skip the matching per-child
 * unshare and inherit the provisioned ns via fork().  net_ready and
 * mnt_ready latch independently -- a failure on one half does not
 * block the other.
 *
 * netns_fd in shm->isolation is published as a freebie once net_ready
 * latches: BPF link API attach types whose target_fd is a netns
 * handle (sk_lookup, flow_dissector, sk_reuseport) draw from it
 * instead of re-opening /proc/self/ns/net per call.  Sentinel -1 means
 * "not published" -- either net_ready is false, or net_ready latched
 * but the procfs open failed.
 *
 * Any failure (non-root, EPERM, ENOSYS, --no-startup-isolation) leaves
 * the affected latch false and the children take the existing per-
 * child unshare path -- behaviour is byte-for-byte unchanged from a
 * non-root run.  Veth pair + spawned peer responder for real two-
 * endpoint datapaths and the scratch block pool for the mount-ns side
 * are follow-up stages.
 */
void setup_startup_isolation(void);
