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

/* Per-grandchild bookkeeping.  Inherited as false at grandchild fork
 * time (the persistent child never sets it -- the in-ns callback runs
 * exclusively in transient grandchildren), set to true after the
 * grandchild's first bring_lo_up() call in its own fresh netns.  Dies
 * with the grandchild on _exit(), so each subsequent grandchild
 * correctly re-runs bring_lo_up() once in its own netns.  The kernel
 * side of SIOCSIFFLAGS is idempotent if lo is already up. */
bool lo_brought_up;
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
 * Idempotent -- a second call after the interface is already up is a
 * no-op at the kernel level.  Failure is silent because the rest of
 * the sequence will surface a visible error if lo really is broken.
 */
void bring_lo_up(void)
{
	/* Snapshot the caller's op via this_child()->op_type (NULL guard
	 * for parent-context callers, NR_CHILD_OP_TYPES bounds check to
	 * match the surrounding valid_op gate in nat-t-churn) and
	 * publish this one-shot lo bring-up's raw kernel entries (socket
	 * + up to two ioctls + close) so the direct-syscall reporter
	 * moves under load.  bring_lo_up runs at most once per
	 * grandchild via the lo_brought_up latch, so a single per-call
	 * bump lines up with "a grandchild committed to running this
	 * op" without multi-counting per invocation. */
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
	if (s < 0)
		return;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		(void)ioctl(s, SIOCSIFFLAGS, &ifr);
	}
	close(s);
}
