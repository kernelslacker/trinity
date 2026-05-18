/*
 * mpls_route_churn - rtnetlink walker for AF_MPLS label routes and
 * IPv4 MPLS_IPTUNNEL lwtunnel encap.
 *
 * Flat netlink fuzzing rarely assembles either MPLS routing path:
 *
 *   - net/mpls/af_mpls.c::mpls_rtm_newroute is reached via
 *     RTM_NEWROUTE / NETLINK_ROUTE with rtmsg.rtm_family = AF_MPLS,
 *     dst_len = 20, RTA_DST carrying an mpls_label-encoded inbound
 *     label, RTA_NEWDST carrying a 1..N entry outbound label stack
 *     with the bottom-of-stack bit on the last entry, and RTA_VIA
 *     pointing at an AF_INET nexthop.  AF_MPLS sockets cover the
 *     send/recv side of the LSR but never reach the FIB add path.
 *
 *   - net/mpls/mpls_iptunnel.c::mpls_build_state is reached via
 *     RTM_NEWROUTE / NETLINK_ROUTE on rtmsg.rtm_family = AF_INET (or
 *     AF_INET6) with RTA_ENCAP_TYPE = LWTUNNEL_ENCAP_MPLS and
 *     RTA_ENCAP nesting MPLS_IPTUNNEL_DST (label stack) plus
 *     MPLS_IPTUNNEL_TTL.  The encap parser builds an lwtunnel state
 *     with mpls_destroy_state as the rcu-deferred dtor; bug class is
 *     concurrent install/replace racing the rcu free.
 *
 * Sequence (per BUDGETED + JITTER iteration, 200 ms wall cap):
 *
 *   1.  unshare(CLONE_NEWNET) one-time per child; failure latches the
 *       op off when not EPERM (cap-gate handles EPERM the next way).
 *   2.  Open a NETLINK_ROUTE socket with SOCK_CLOEXEC + 1 s recvtimeo.
 *   3.  Pick arm A (AF_MPLS label install) or arm B (IPv4 lwtunnel
 *       MPLS encap install) 50/50 per iteration.
 *
 *   Arm A (AF_MPLS label install):
 *     RTM_NEWROUTE family=AF_MPLS, dst_len=20.
 *     RTA_DST  : mpls_label{entry = htonl((label << 12) | 0x100)}
 *                where label is in [16, 0xFFFFF] (well above the
 *                reserved 0..15 range, RFC 3032).
 *     RTA_NEWDST : 1..3 mpls_label out-stack, BoS bit set on last
 *                  entry only -- exercises the loop in
 *                  nla_get_labels().
 *     RTA_VIA  : struct rtvia { rtvia_family=AF_INET, rtvia_addr=
 *                127.0.0.{2..254} } -- the nexthop is reachable on
 *                lo so the route install doesn't bail on neighbour
 *                resolution.
 *     RTA_OIF  : if_nametoindex("lo") (best-effort; omitted when 0).
 *     RTA_TABLE: RT_TABLE_MAIN (254).
 *     RTM_DELROUTE rollback by in-label after the install.
 *
 *   Arm B (IPv4 lwtunnel MPLS encap):
 *     RTM_NEWROUTE family=AF_INET, dst_len=32.
 *     RTA_DST       : 192.0.2.{1..254} (TEST-NET-1, RFC 5737).
 *     RTA_GATEWAY   : 127.0.0.1.
 *     RTA_OIF       : if_nametoindex("lo").
 *     RTA_ENCAP_TYPE: LWTUNNEL_ENCAP_MPLS.
 *     RTA_ENCAP     : nested MPLS_IPTUNNEL_DST (1..3 label stack with
 *                     BoS bit on last) + MPLS_IPTUNNEL_TTL (rand%256).
 *     RTM_DELROUTE rollback by destination.
 *
 *   4.  Bounded inner retry: up to 8 retries per netlink operation
 *       on -EAGAIN / -ENOMEM.  Single retry per iteration to keep the
 *       wall budget bounded.
 *
 * Per-process latches:
 *
 *   - ns_unsupported_mpls         : set on first -EAFNOSUPPORT /
 *                                   -ENOPROTOOPT from arm A.  AF_MPLS
 *                                   is unreachable without
 *                                   CONFIG_MPLS_ROUTING and the
 *                                   mpls_router module loaded.
 *   - ns_unsupported_lwtunnel     : set on first -EOPNOTSUPP from arm
 *                                   B's RTA_ENCAP path (LWT not
 *                                   compiled or mpls_iptunnel module
 *                                   unloaded after registration).
 *   - modprobe_tried_mpls_router  : one-shot best-effort modprobe of
 *                                   "mpls_router" + "mpls_iptunnel"
 *                                   on first -ENETDOWN /
 *                                   -EPROTONOSUPPORT.  fork+execvp
 *                                   pattern from xfrm-churn -- failure
 *                                   (no /sbin/modprobe, lockdown,
 *                                   no module) is harmless, the latch
 *                                   prevents repeated attempts.
 *
 * Brick-safety:
 *   - All work happens inside CLONE_NEWNET; the host MPLS table is
 *     never touched.
 *   - Both arms install onto lo only -- no underlying physical
 *     device is involved; nexthops are 127/8 and 192.0.2/24 (TEST-
 *     NET-1, never routable on real networks).
 *   - BUDGETED outer loop with 200 ms wall cap; SO_RCVTIMEO on the
 *     rtnl socket caps any single recv at 1 s.
 *
 * Header gating: __has_include() on linux/mpls.h, linux/lwtunnel.h,
 * linux/mpls_iptunnel.h, linux/rtnetlink.h.  Build hosts without
 * the MPLS uapi silently drop the childop from the registry (the
 * fallback stub just bumps runs+ns_unsupported and returns).  Per-
 * symbol #ifndef shims at use site for RTA_VIA / RTA_NEWDST /
 * struct rtvia (4.5+) and MPLS_IPTUNNEL_* / LWTUNNEL_ENCAP_MPLS
 * (4.3+) so the file compiles even when the build host's headers
 * pre-date those additions.
 */

#if __has_include(<linux/mpls.h>) && __has_include(<linux/lwtunnel.h>) && \
	__has_include(<linux/mpls_iptunnel.h>) && __has_include(<linux/rtnetlink.h>)

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/lwtunnel.h>
#include <linux/mpls.h>
#include <linux/mpls_iptunnel.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "params.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/* AF_MPLS shipped in v4.1; older sysroots may omit it.  Stable UAPI int. */
#ifndef AF_MPLS
#define AF_MPLS				28
#endif

/* RTA_VIA / struct rtvia shipped in v4.5; supply stable values when
 * absent.  RTA_VIA is the IANA-assigned attribute number for the IPv4
 * nexthop carrier on AF_MPLS routes. */
#ifndef RTA_VIA
#define RTA_VIA				18
#endif
#ifndef RTA_NEWDST
#define RTA_NEWDST			19
#endif
#ifndef RTA_ENCAP_TYPE
#define RTA_ENCAP_TYPE			21
#endif
#ifndef RTA_ENCAP
#define RTA_ENCAP			22
#endif

#ifndef HAVE_STRUCT_RTVIA
struct rtvia_compat {
	__kernel_sa_family_t	rtvia_family;
	__u8			rtvia_addr[0];
};
#define mpls_rtvia			rtvia_compat
#else
#define mpls_rtvia			rtvia
#endif

/* mpls_iptunnel.h (4.3+) defines MPLS_IPTUNNEL_* enum.  Supply stable
 * values when the sysroot pre-dates the addition. */
#ifndef MPLS_IPTUNNEL_DST
#define MPLS_IPTUNNEL_DST		1
#endif
#ifndef MPLS_IPTUNNEL_TTL
#define MPLS_IPTUNNEL_TTL		2
#endif

/* lwtunnel.h (4.3+) defines LWTUNNEL_ENCAP_MPLS.  Supply stable value
 * when absent. */
#ifndef LWTUNNEL_ENCAP_MPLS
#define LWTUNNEL_ENCAP_MPLS		1
#endif

#define MPLS_RC_OUTER_BASE		4U
#define MPLS_RC_OUTER_FLOOR		8U
#define MPLS_RC_OUTER_CAP		16U
#define MPLS_RC_WALL_CAP_NS		(200ULL * 1000ULL * 1000ULL)
#define MPLS_RC_RTNL_BUF		2048
#define MPLS_RC_MAX_RETRIES		8
#define MPLS_RC_MAX_STACK		3U

#define MPLS_RC_LABEL_MIN		16U
#define MPLS_RC_LABEL_RANGE		(0x100000U - 16U)	/* [16, 0xFFFFF] */

/* Per-child latches.  All start cleared; transitions are one-way
 * within a child's lifetime. */
static bool ns_unsupported_mpls;
static bool ns_unsupported_lwtunnel;
static bool modprobe_tried_mpls_router;
static bool mpls_rc_unshared;

/*
 * Best-effort modprobe.  Same fork+execvp shape as xfrm-churn's
 * try_modprobe -- redirect stdio to /dev/null so module-load chatter
 * doesn't pollute trinity's output.  Failure (no module, no
 * /sbin/modprobe, no permission, lockdown=integrity) is exactly the
 * case the per-arm latch will catch on the subsequent NEWROUTE.
 */
static void try_modprobe(const char *mod)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return;
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (devnull >= 0) {
			(void)dup2(devnull, 0);
			(void)dup2(devnull, 1);
			(void)dup2(devnull, 2);
			close(devnull);
		}
		execlp("modprobe", "modprobe", "-q", mod, (char *)NULL);
		_exit(127);
	}
	(void)waitpid(pid, &status, 0);
}

static void maybe_modprobe_once(void)
{
	if (modprobe_tried_mpls_router)
		return;
	modprobe_tried_mpls_router = true;
	try_modprobe("mpls_router");
	try_modprobe("mpls_iptunnel");
	if (verbosity > 2)
		outputerr("[mpls_route_churn] latched modprobe_tried_mpls_router\n");
}

static void latch_ns_unsupported_mpls(int rc)
{
	if (ns_unsupported_mpls)
		return;
	ns_unsupported_mpls = true;
	__atomic_add_fetch(&shm->stats.mpls_route_churn_ns_unsupported,
			   1, __ATOMIC_RELAXED);
	if (verbosity > 2)
		outputerr("[mpls_route_churn] latched ns_unsupported_mpls (rc=%d)\n",
			  rc);
}

static void latch_ns_unsupported_lwtunnel(int rc)
{
	if (ns_unsupported_lwtunnel)
		return;
	ns_unsupported_lwtunnel = true;
	__atomic_add_fetch(&shm->stats.mpls_route_churn_ns_unsupported,
			   1, __ATOMIC_RELAXED);
	if (verbosity > 2)
		outputerr("[mpls_route_churn] latched ns_unsupported_lwtunnel (rc=%d)\n",
			  rc);
}

/*
 * Bounded retry wrapper for the mpls operations.  Retries -EAGAIN /
 * -ENOMEM up to MPLS_RC_MAX_RETRIES.  All other return codes (success
 * 0, -EAFNOSUPPORT, -EOPNOTSUPP, etc.) propagate immediately so the
 * caller can drive its latch.
 *
 * The shared nl_send_recv_retry covers -EAGAIN / -EBUSY only;
 * widening it to also cover -ENOMEM would change behaviour for every
 * existing ROUTE-plane consumer.  Keep this wrapper local so the
 * mpls-specific -ENOMEM retry stays an mpls concern.
 */
static int mpls_send_recv_retry(struct nl_ctx *ctx, void *msg, size_t len)
{
	int retries = 0;
	int rc;

	for (;;) {
		rc = nl_send_recv(ctx, msg, len);
		if (rc != -EAGAIN && rc != -ENOMEM)
			return rc;
		if (++retries >= MPLS_RC_MAX_RETRIES)
			return rc;
	}
}

/*
 * Encode an MPLS label-stack entry.  label is the 20-bit label value;
 * tc=0; bos=1 marks the bottom of the stack; ttl=64 (default-ish).
 * Returns network-byte-order __be32 ready for memcpy into an
 * mpls_label.entry field.
 */
static __be32 mpls_label_encode(__u32 label, bool bos)
{
	__u32 entry;

	entry = (label & 0xFFFFFU) << MPLS_LS_LABEL_SHIFT;
	if (bos)
		entry |= MPLS_LS_S_MASK;
	entry |= 64U & MPLS_LS_TTL_MASK;
	return htonl(entry);
}

/*
 * Build an out-label stack of `count` entries (1..MPLS_RC_MAX_STACK).
 * BoS bit is set on the last entry only.  Returns the byte length of
 * the stack (count * sizeof(struct mpls_label)).
 */
static size_t mpls_build_label_stack(struct mpls_label *stack,
				     unsigned int count)
{
	unsigned int i;

	if (count < 1)
		count = 1;
	if (count > MPLS_RC_MAX_STACK)
		count = MPLS_RC_MAX_STACK;

	for (i = 0; i < count; i++) {
		__u32 label = MPLS_RC_LABEL_MIN +
			      (rand32() % MPLS_RC_LABEL_RANGE);
		stack[i].entry = mpls_label_encode(label,
						   (i == count - 1));
	}
	return count * sizeof(struct mpls_label);
}

/*
 * Arm A: install one AF_MPLS label route.
 *
 *   RTM_NEWROUTE family=AF_MPLS dst_len=20
 *     RTA_DST    : 4-byte mpls_label encoding the in-label
 *     RTA_NEWDST : 1..3 mpls_label out-stack
 *     RTA_VIA    : struct rtvia AF_INET, addr 127.0.0.x
 *     RTA_OIF    : lo ifindex (omitted if 0)
 *     RTA_TABLE  : RT_TABLE_MAIN
 *
 * Returns 0 on accept, negated errno on rejection, -EIO on local
 * failure.  *out_in_label is set to the in-label so the caller can
 * issue the matching RTM_DELROUTE.
 */
static int build_mpls_label_install(struct nl_ctx *ctx, int lo_ifindex,
				    __u32 *out_in_label)
{
	unsigned char buf[MPLS_RC_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	struct mpls_label in_label_buf;
	struct mpls_label out_stack[MPLS_RC_MAX_STACK];
	unsigned char via_buf[sizeof(struct mpls_rtvia) + 4];
	struct mpls_rtvia *via = (struct mpls_rtvia *)via_buf;
	__u32 in_label;
	__u32 nexthop;
	unsigned int stack_n;
	size_t stack_len, off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	rtm = (struct rtmsg *)NLMSG_DATA(nlh);
	rtm->rtm_family   = AF_MPLS;
	rtm->rtm_dst_len  = 20;
	rtm->rtm_table    = RT_TABLE_MAIN;
	rtm->rtm_protocol = RTPROT_STATIC;
	rtm->rtm_scope    = RT_SCOPE_UNIVERSE;
	rtm->rtm_type     = RTN_UNICAST;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*rtm));

	in_label = MPLS_RC_LABEL_MIN + (rand32() % MPLS_RC_LABEL_RANGE);
	in_label_buf.entry = mpls_label_encode(in_label, true);
	off = nla_put(buf, off, sizeof(buf), RTA_DST,
		      &in_label_buf, sizeof(in_label_buf));
	if (!off)
		return -EIO;

	stack_n = 1U + (rand32() % MPLS_RC_MAX_STACK);
	stack_len = mpls_build_label_stack(out_stack, stack_n);
	off = nla_put(buf, off, sizeof(buf), RTA_NEWDST,
		      out_stack, stack_len);
	if (!off)
		return -EIO;

	memset(via_buf, 0, sizeof(via_buf));
	via->rtvia_family = AF_INET;
	nexthop = htonl(0x7f000002U + (rand32() % 253U)); /* 127.0.0.{2..254} */
	memcpy(via->rtvia_addr, &nexthop, sizeof(nexthop));
	off = nla_put(buf, off, sizeof(buf), RTA_VIA,
		      via_buf, sizeof(struct mpls_rtvia) + sizeof(nexthop));
	if (!off)
		return -EIO;

	if (lo_ifindex > 0) {
		off = nla_put_u32(buf, off, sizeof(buf), RTA_OIF,
				  (__u32)lo_ifindex);
		if (!off)
			return -EIO;
	}

	off = nla_put_u32(buf, off, sizeof(buf), RTA_TABLE, RT_TABLE_MAIN);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;

	*out_in_label = in_label;
	return mpls_send_recv_retry(ctx, buf, off);
}

/*
 * Arm A rollback: RTM_DELROUTE family=AF_MPLS keyed on in-label.
 */
static int build_mpls_label_delete(struct nl_ctx *ctx, __u32 in_label)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	struct mpls_label in_label_buf;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	rtm = (struct rtmsg *)NLMSG_DATA(nlh);
	rtm->rtm_family   = AF_MPLS;
	rtm->rtm_dst_len  = 20;
	rtm->rtm_table    = RT_TABLE_MAIN;
	rtm->rtm_scope    = RT_SCOPE_NOWHERE;
	rtm->rtm_type     = RTN_UNICAST;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*rtm));

	in_label_buf.entry = mpls_label_encode(in_label, true);
	off = nla_put(buf, off, sizeof(buf), RTA_DST,
		      &in_label_buf, sizeof(in_label_buf));
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf), RTA_TABLE, RT_TABLE_MAIN);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return mpls_send_recv_retry(ctx, buf, off);
}

/*
 * Arm B: install one IPv4 route with MPLS_IPTUNNEL lwtunnel encap.
 *
 *   RTM_NEWROUTE family=AF_INET dst_len=32
 *     RTA_DST       : 192.0.2.{1..254} (TEST-NET-1)
 *     RTA_GATEWAY   : 127.0.0.1
 *     RTA_OIF       : lo ifindex
 *     RTA_ENCAP_TYPE: LWTUNNEL_ENCAP_MPLS
 *     RTA_ENCAP     : nested MPLS_IPTUNNEL_DST + MPLS_IPTUNNEL_TTL
 *
 * Returns 0 on accept, negated errno on rejection, -EIO on local
 * failure.  *out_dst is set to the IPv4 destination so the caller can
 * issue the matching RTM_DELROUTE.
 */
static int build_iptunnel_install(struct nl_ctx *ctx, int lo_ifindex,
				  __be32 *out_dst)
{
	unsigned char buf[MPLS_RC_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	struct mpls_label out_stack[MPLS_RC_MAX_STACK];
	__be32 dst, gw;
	__u16 encap_type;
	__u8 ttl;
	unsigned int stack_n;
	size_t stack_len, off, encap_off;

	if (lo_ifindex <= 0)
		return -EIO;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	rtm = (struct rtmsg *)NLMSG_DATA(nlh);
	rtm->rtm_family   = AF_INET;
	rtm->rtm_dst_len  = 32;
	rtm->rtm_table    = RT_TABLE_MAIN;
	rtm->rtm_protocol = RTPROT_STATIC;
	rtm->rtm_scope    = RT_SCOPE_UNIVERSE;
	rtm->rtm_type     = RTN_UNICAST;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*rtm));

	dst = htonl(0xC0000201U + (rand32() % 254U)); /* 192.0.2.{1..254} */
	off = nla_put(buf, off, sizeof(buf), RTA_DST, &dst, sizeof(dst));
	if (!off)
		return -EIO;

	gw = htonl(0x7f000001U); /* 127.0.0.1 */
	off = nla_put(buf, off, sizeof(buf), RTA_GATEWAY, &gw, sizeof(gw));
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf), RTA_OIF,
			  (__u32)lo_ifindex);
	if (!off)
		return -EIO;

	encap_type = LWTUNNEL_ENCAP_MPLS;
	off = nla_put_u16(buf, off, sizeof(buf), RTA_ENCAP_TYPE, encap_type);
	if (!off)
		return -EIO;

	encap_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), RTA_ENCAP);
	if (!off)
		return -EIO;

	stack_n = 1U + (rand32() % MPLS_RC_MAX_STACK);
	stack_len = mpls_build_label_stack(out_stack, stack_n);
	off = nla_put(buf, off, sizeof(buf), MPLS_IPTUNNEL_DST,
		      out_stack, stack_len);
	if (!off)
		return -EIO;

	ttl = (__u8)(rand32() & 0xffU);
	off = nla_put_u8(buf, off, sizeof(buf), MPLS_IPTUNNEL_TTL, ttl);
	if (!off)
		return -EIO;

	nla_nest_end(buf, encap_off, off);

	nlh->nlmsg_len = (__u32)off;

	*out_dst = dst;
	return mpls_send_recv_retry(ctx, buf, off);
}

/*
 * Arm B rollback: RTM_DELROUTE family=AF_INET keyed on destination.
 */
static int build_iptunnel_delete(struct nl_ctx *ctx, __be32 dst, int lo_ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	rtm = (struct rtmsg *)NLMSG_DATA(nlh);
	rtm->rtm_family   = AF_INET;
	rtm->rtm_dst_len  = 32;
	rtm->rtm_table    = RT_TABLE_MAIN;
	rtm->rtm_scope    = RT_SCOPE_NOWHERE;
	rtm->rtm_type     = RTN_UNICAST;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*rtm));

	off = nla_put(buf, off, sizeof(buf), RTA_DST, &dst, sizeof(dst));
	if (!off)
		return -EIO;

	if (lo_ifindex > 0) {
		off = nla_put_u32(buf, off, sizeof(buf), RTA_OIF,
				  (__u32)lo_ifindex);
		if (!off)
			return -EIO;
	}

	nlh->nlmsg_len = (__u32)off;
	return mpls_send_recv_retry(ctx, buf, off);
}

/*
 * Map an rtnetlink errno to one of the latch actions:
 *   - EAFNOSUPPORT / ENOPROTOOPT  : no MPLS on this kernel.
 *   - EOPNOTSUPP / EPROTONOSUPPORT: structural unsupported (lwtunnel
 *                                   off, or arm-specific reject).
 *   - ENETDOWN / EPROTONOSUPPORT  : module not loaded -- worth one
 *                                   modprobe attempt.
 *
 * arm = 'A' (label install) or 'B' (iptunnel install).
 */
static void map_rc_to_latch(int rc, char arm)
{
	if (rc >= 0)
		return;

	if (rc == -EAFNOSUPPORT || rc == -ENOPROTOOPT) {
		if (arm == 'A')
			latch_ns_unsupported_mpls(rc);
		else
			latch_ns_unsupported_lwtunnel(rc);
		return;
	}

	if (rc == -EOPNOTSUPP) {
		if (arm == 'B')
			latch_ns_unsupported_lwtunnel(rc);
		return;
	}

	if (rc == -ENETDOWN || rc == -EPROTONOSUPPORT)
		maybe_modprobe_once();
}

bool mpls_route_churn(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;
	struct nl_ctx ctx = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	int lo_ifindex;

	(void)child;

	__atomic_add_fetch(&shm->stats.mpls_route_churn_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_mpls && ns_unsupported_lwtunnel)
		return true;

	if (!mpls_rc_unshared) {
		if (unshare(CLONE_NEWNET) < 0) {
			if (errno != EPERM) {
				latch_ns_unsupported_mpls(-errno);
				latch_ns_unsupported_lwtunnel(-errno);
				return true;
			}
			/* EPERM: stay in the host netns -- the per-arm
			 * cap-gates will catch the structural unsupported
			 * cases without scribbling on the main MPLS table
			 * (which on a build host without mpls_router loaded
			 * doesn't exist anyway). */
		}
		mpls_rc_unshared = true;
	}

	if (nl_open(&ctx, &opts) < 0)
		return true;

	lo_ifindex = (int)if_nametoindex("lo");

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_MPLS_ROUTE_CHURN,
			       JITTER_RANGE(MPLS_RC_OUTER_BASE));
	if (outer_iters < MPLS_RC_OUTER_FLOOR)
		outer_iters = MPLS_RC_OUTER_FLOOR;
	if (outer_iters > MPLS_RC_OUTER_CAP)
		outer_iters = MPLS_RC_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		bool pick_arm_a;

		if ((unsigned long long)ns_since(&t_outer) >=
		    MPLS_RC_WALL_CAP_NS)
			break;

		pick_arm_a = (rand32() & 1U) != 0;

		if (pick_arm_a && !ns_unsupported_mpls) {
			__u32 in_label = 0;
			int rc = build_mpls_label_install(&ctx, lo_ifindex,
							  &in_label);

			if (rc == 0) {
				__atomic_add_fetch(
					&shm->stats.mpls_route_churn_label_install_ok,
					1, __ATOMIC_RELAXED);
				if (build_mpls_label_delete(&ctx,
							    in_label) == 0)
					__atomic_add_fetch(
						&shm->stats.mpls_route_churn_delete_ok,
						1, __ATOMIC_RELAXED);
			} else {
				map_rc_to_latch(rc, 'A');
			}
		} else if (!pick_arm_a && !ns_unsupported_lwtunnel) {
			__be32 dst = 0;
			int rc = build_iptunnel_install(&ctx, lo_ifindex,
							&dst);

			if (rc == 0) {
				__atomic_add_fetch(
					&shm->stats.mpls_route_churn_iptunnel_install_ok,
					1, __ATOMIC_RELAXED);
				if (build_iptunnel_delete(&ctx, dst,
							  lo_ifindex) == 0)
					__atomic_add_fetch(
						&shm->stats.mpls_route_churn_delete_ok,
						1, __ATOMIC_RELAXED);
			} else {
				map_rc_to_latch(rc, 'B');
			}
		}

		if (ns_unsupported_mpls && ns_unsupported_lwtunnel)
			break;
	}

	nl_close(&ctx);
	return true;
}

#else  /* !__has_include(<linux/mpls.h>) etc. */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

bool mpls_route_churn(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.mpls_route_churn_runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.mpls_route_churn_ns_unsupported,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif
