#include <errno.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <sys/mount.h>
#include <unistd.h>

#include "isolation.h"
#include "params.h"
#include "shm.h"
#include "trinity.h"
#include "uid.h"

/*
 * Parent-side setup-then-drop spine.  Runs from init_pre_fork() after
 * do_uid0_check() and before any fork; the parent is still root here
 * by construction (auto-drop is per-child, in init_child_setup_sandbox).
 *
 * Two latches publish to children via shm:
 *
 *   isolation.net_ready -- unshare(CLONE_NEWNET) succeeded; children
 *     skip per-child unshare(CLONE_NEWNET) and inherit the parent's
 *     (empty-but-ours) netns.
 *
 *   isolation.mnt_ready -- unshare(CLONE_NEWNS) plus the MS_REC|
 *     MS_PRIVATE remount of '/' both succeeded; children skip the
 *     per-child unshare(CLONE_NEWNS) + private-remount dance and
 *     inherit the parent's private mount ns.
 *
 * Degrade-to-host on any failure: leave latches at the zero value
 * create_shm() memset, log once, return.  Children then take the
 * existing per-child unshare path -- behaviour matches today's
 * non-root run.
 *
 * Default: MS_REC|MS_PRIVATE only -- a writable scratch subtree
 * arrives with the scratch block pool; '/'-read-only is a
 * follow-up hardening pass, not day-1.
 */
void setup_startup_isolation(void)
{
	/*
	 * Non-root: never even attempt the syscalls.  The whole point of
	 * the gate is that every dev / claw build runs unprivileged and
	 * must see byte-for-byte today's behaviour -- same per-child
	 * unshare path in init_child_setup_sandbox, no new syscalls
	 * attempted from the parent.
	 */
	if (orig_uid != 0)
		return;

	/* Operator opt-out: forces today's behaviour even when launched
	 * as root.  Useful for debugging the per-child unshare path or
	 * running on a host where parent-side ns provisioning misbehaves. */
	if (no_startup_isolation)
		return;

	/*
	 * Enter a private net + mount ns in one shot.  If the kernel
	 * lacks CONFIG_NET_NS / CONFIG_NAMESPACES (ENOSYS) or a container
	 * sandbox blocks the unshare (EPERM), degrade silently.  The
	 * parent is the only caller, runs exactly once, and the failure
	 * envelope is "behave as today" -- no retry, no panic.
	 */
	if (unshare(CLONE_NEWNET | CLONE_NEWNS) != 0) {
		output(0, "startup isolation: unshare(CLONE_NEWNET|CLONE_NEWNS) failed (errno=%d) -- degrading to per-child unshare path\n",
			errno);
		return;
	}

	/*
	 * Without an explicit MS_REC|MS_PRIVATE remount the new mount ns
	 * inherits the host's propagation mode (MS_SHARED on most distros),
	 * so any later mount() the children issue would propagate back
	 * into the host's mount tree -- defeating the whole containment
	 * story.  If the remount itself is refused we cannot safely
	 * advertise the mount ns to children (they'd skip the per-child
	 * MS_PRIVATE dance and let mount churn escape), so leave mnt_ready
	 * false and log.  The unshare cannot be undone; the parent stays
	 * in a private (but propagating) mount ns for the rest of the run,
	 * which is harmless because the parent never issues fuzzed mounts.
	 */
	if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
		output(0, "startup isolation: MS_REC|MS_PRIVATE remount of '/' failed (errno=%d) -- degrading to per-child unshare path\n",
			errno);
		return;
	}

	/*
	 * Publish.  RELAXED matches the no_private_ns / no_pidns latch
	 * convention already used for sibling state in init_child_setup_
	 * sandbox; the cross-process happens-before edge to the child
	 * readers is provided by fork() itself, which is sequenced strictly
	 * after init_pre_fork() returns.
	 */
	__atomic_store_n(&shm->isolation.net_ready, true, __ATOMIC_RELAXED);
	__atomic_store_n(&shm->isolation.mnt_ready, true, __ATOMIC_RELAXED);

	output(0, "startup isolation: parent-provisioned net+mount ns ready (children will inherit, per-child unshare skipped)\n");
}
