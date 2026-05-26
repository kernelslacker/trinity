/*
 * Cross-arg lengths-match validator.
 *
 * Some syscalls express a buffer with a (pointer, count) pair where
 * the kernel rejects the call at its earliest validation step if the
 * pair is internally inconsistent (count > 0 but pointer NULL, etc).
 * Trinity's per-argument generators do not coordinate across slots,
 * so the random walk produces these inconsistent shapes routinely.
 *
 * Calling the kernel anyway wastes a syscall round-trip and a kcov
 * enable/disable pair to discover only the same early-EINVAL path
 * over and over.  This file's single entry point runs after .sanitise
 * but before dispatch and short-circuits a call whose argument shape
 * is provably DOA, freeing the slot for a call the kernel will
 * actually walk.
 *
 * Scope is deliberately narrow today: one concrete rule for
 * epoll_wait / epoll_pwait / epoll_pwait2 to land the framework.
 * Additional coupled-pair rules (readv/writev iovec slots, sendmsg
 * msghdr fields, recvmmsg vlen, etc.) belong in follow-up commits so
 * each rule can be reasoned about and reverted independently.
 */
#include "arg_coupling.h"
#include "syscall.h"
#include "trinity.h"

int validate_arg_coupling(struct syscallrecord *rec)
{
	const struct syscallentry *entry;

	if (rec == NULL)
		return 0;

	entry = rec->entry;
	if (entry == NULL || entry->name == NULL)
		return 0;

	/*
	 * epoll_wait / epoll_pwait / epoll_pwait2: the events output
	 * buffer (a2) must be non-NULL whenever maxevents (a3) is > 0.
	 * The kernel's ep_send_events() unconditionally dereferences the
	 * events pointer once maxevents is positive, so a NULL buffer
	 * with maxevents > 0 is rejected as EFAULT at copy_to_user time
	 * without exercising any interesting eventpoll path.  Skip the
	 * dispatch.  maxevents <= 0 is a legitimate sanitise bucket that
	 * exercises the early EINVAL reject; leave those alone.
	 *
	 * The family-membership test reads the cached is_epoll_wait_family
	 * byte stamped at table init; the original three strcmps fired on
	 * every dispatch even though only a tiny fraction of calls are in
	 * the family.
	 */
	if (entry->is_epoll_wait_family) {
		if ((long) rec->a3 > 0 && rec->a2 == 0) {
			outputerr("arg-coupling: %s rejected: maxevents=%ld but events=NULL\n",
				  entry->name, (long) rec->a3);
			return -1;
		}
	}

	return 0;
}
