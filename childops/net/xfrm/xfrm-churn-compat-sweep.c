/*
 * xfrm-churn-compat-sweep - defensive netlink_xfrm opcode-space sweep
 * for the xfrm_churn childop.  Carved out of
 * childops/net/xfrm/xfrm-churn.c so the compat-table off-end-read
 * driver compiles as its own TU alongside the netlink builders,
 * inner-traffic drivers, and the other alt-path sub-modes.
 *
 * Pure relocation: the function body is byte-for-byte the same as
 * the original.  xfrm_compat_msg_sweep widens from file-static to
 * external linkage so the xfrm-churn.c teardown phase can reach it
 * across the TU boundary; the shared ns_unsupported_xfrm latch it
 * consults keeps its definition in xfrm-churn.c and picks up an
 * extern declaration in xfrm-churn-internal.h.
 */

#include "xfrm-churn-internal.h"

/*
 * Defensive sweep of the netlink_xfrm opcode space, targeting off-end
 * indexing in net/xfrm/xfrm_compat.c::xfrm_msg_min[] and the broader
 * xfrm_user dispatch.  Pre-fix (upstream 28465227c80f) the compat
 * translation table was sized only through XFRM_MSG_GETAE while the
 * UAPI grew XFRM_MSG_MAPPING; a 32-bit task issuing MAPPING walked
 * off the end reading garbage.  A 64-bit-only fuzz binary doesn't
 * itself enter the compat translator, but iterating the full
 * XFRM_MSG_BASE..XFRM_MSG_MAX range exercises every kernel-side
 * dispatch slot, catching any later off-end index added since.
 *
 * Per-iteration: rebuild a minimal nlmsghdr with a fixed 64-byte
 * payload tail (small enough not to exceed any opcode's max, large
 * enough to satisfy the smaller of the 32-bit / 64-bit struct
 * minimums for most opcodes), sendto the bound NETLINK_XFRM fd
 * MSG_DONTWAIT, drain at most one reply per send.  Most opcodes
 * reject with EINVAL / E2BIG / EOPNOTSUPP — that's fine, the
 * dispatch slot lookup happens before the validation that emits the
 * rejection.  All I/O is non-blocking so the inner loop can't stall
 * past the SIGALRM(1s) cap.
 */
void xfrm_compat_msg_sweep(struct nl_ctx *ctx)
{
	struct sockaddr_nl dst;
	unsigned char buf[256];
	unsigned char rbuf[1024];
	struct nlmsghdr *nlh;
	unsigned int t;
	size_t off;
	ssize_t n;

	if (ns_unsupported_xfrm)
		return;

	__atomic_add_fetch(&shm->stats.xfrm_compat.sweep_runs,
			   1, __ATOMIC_RELAXED);

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;

	for (t = XFRM_MSG_NEWSA; t <= XFRM_COMPAT_SWEEP_MAX; t++) {
		memset(buf, 0, sizeof(buf));
		nlh = (struct nlmsghdr *)buf;
		nlh->nlmsg_type  = (__u16)t;
		nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
		nlh->nlmsg_seq   = nl_seq_next(ctx);
		off = NLMSG_HDRLEN + NLMSG_ALIGN(64);
		nlh->nlmsg_len   = (__u32)off;

		if (sendto(ctx->fd, buf, off, MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst)) < 0) {
			__atomic_add_fetch(&shm->stats.xfrm_compat.sends_failed,
					   1, __ATOMIC_RELAXED);
			continue;
		}
		__atomic_add_fetch(&shm->stats.xfrm_compat.sends_ok,
				   1, __ATOMIC_RELAXED);

		n = recv(ctx->fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
		if (n > 0)
			__atomic_add_fetch(&shm->stats.xfrm_compat.replies_seen,
					   1, __ATOMIC_RELAXED);
	}
}
