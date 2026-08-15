/*
 * nat-t-churn-setup - one-time-per-grandchild scaffolding for the
 * nat_t_churn childop.  Carved out of childops/net/xfrm/nat-t-churn.c
 * so the tiny setup surface (lo bring-up, unsupported-latch bookkeeping)
 * compiles as its own TU and the shared file-scope state lives with
 * the code that owns it.
 *
 * Pure relocation: every function body and file-scope declaration is
 * byte-for-byte the same as the original.  The only linkage change is
 * widening warn_once_unsupported() / bring_lo_up() and the shared
 * latch/iteration state from file-static to external so the rest of
 * the pipeline can reach them across the TU boundary.
 */

#include "nat-t-churn-internal.h"
#include "childop-outcome.h"

/* Per-process master latch.  Set by two paths:
 *
 *   - the wrapper, on userns_run_in_ns() returning -EPERM (the
 *     grandchild's unshare(CLONE_NEWUSER) was refused by a hardened
 *     policy: user.max_user_namespaces=0 or
 *     kernel.unprivileged_userns_clone=0).  This write persists across
 *     invocations -- without a private netns we MUST NOT touch the
 *     host's xfrm SAD or NETLINK_XFRM state, so the op stays disabled
 *     for the remainder of this child's lifetime.
 *
 *   - the in-ns callback, on the first NETLINK_XFRM open or AF_INET
 *     socket structural rejection (EPROTONOSUPPORT / EAFNOSUPPORT)
 *     observed inside the grandchild -- CONFIG_XFRM / CONFIG_INET
 *     missing at runtime.  That write lives in the grandchild's
 *     address space and dies with the grandchild, so the rejection is
 *     re-discovered once per invocation; userns cannot manufacture an
 *     absent kernel CONFIG, so cross-invocation persistence of that
 *     path is not in scope.
 *
 * The transition false->true emits a single outputerr line via the
 * warn_once_unsupported helper. */
bool ns_unsupported_nat_t;

/* Sub-latch covering only the AF_INET6 / xfrm6 / UDPv6 branch.  Set on
 * the first AF_INET6 socket EAFNOSUPPORT, UDP_ENCAP setsockopt
 * EOPNOTSUPP, or NEWSA EAFNOSUPPORT/EOPNOTSUPP/EPROTONOSUPPORT, so a
 * kernel without ipv6 / xfrm6 stops burning syscalls on the v6 branch
 * while leaving the v4 path running. */
bool ns_unsupported_xfrm6;

__u32 g_iter;

/* RFC 3849 documentation prefix: 2001:db8::dead.  Used as both the
 * SA selector / template address and the unreachable sendto() target
 * for the xfrm6 dst-leak error path the upstream commit fixed. */
const __u8 nat_t_v6_addr[16] = {
	0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
	0,    0,    0,    0,    0, 0, 0xde, 0xad,
};

void warn_once_unsupported(const char *reason, int err)
{
	if (ns_unsupported_nat_t)
		return;
	ns_unsupported_nat_t = true;
	outputerr("nat_t_churn: %s failed (errno=%d), latching unsupported_nat_t\n",
		  reason, err);
}

/*
 * Bring lo up via SIOCSIFFLAGS on a temporary AF_INET DGRAM socket.
 * Called unconditionally at the start of each grandchild invocation --
 * userns_run_in_ns() gives every grandchild a fresh netns in which lo
 * is DOWN, so the round-trip is mandatory per call.  Failures are
 * counted via shm->lo_up_fail so the dead-arm oracle can distinguish
 * lo-up failure from no-route or arm-never-reached.
 */
void bring_lo_up(void)
{
	/* Snapshot the caller's op via this_child()->op_type (NULL guard
	 * for parent-context callers, NR_CHILD_OP_TYPES bounds check to
	 * match the surrounding valid_op gate in nat-t-churn) and
	 * publish the lo bring-up's raw kernel entries (socket + up to
	 * two ioctls + close) so the direct-syscall reporter moves under
	 * load. */
	{
		struct childdata *tc = this_child();
		const enum child_op_type op = tc ? tc->op_type :
			NR_CHILD_OP_TYPES;
		const bool valid_op = ((int) op >= 0 &&
				       op < NR_CHILD_OP_TYPES);

		if (valid_op)
			childop_direct_syscalls_add(op, 1);
	}
	struct ifreq ifr;
	int s;

	s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (s < 0) {
		__atomic_add_fetch(&shm->lo_up_fail, 1, __ATOMIC_RELAXED);
		return;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		(void)ioctl(s, SIOCSIFFLAGS, &ifr);
	} else {
		__atomic_add_fetch(&shm->lo_up_fail, 1, __ATOMIC_RELAXED);
	}
	close(s);
}
