/*
 * mpls_route_churn - rtnetlink walker for the MPLS FIB install paths
 * flat netlink fuzzing rarely assembles.  Targets
 * net/mpls/af_mpls.c:mpls_rtm_newroute (arm A: AF_MPLS in-label route,
 * 1..3 out-label stack with BoS on the last) and
 * net/mpls/mpls_iptunnel.c:mpls_build_state (arm B: IPv4 route with a
 * nested LWTUNNEL_ENCAP_MPLS encap).  Arm B's bug class is a concurrent
 * install/replace racing the rcu-deferred mpls_destroy_state.
 *
 * Each invocation runs a 200 ms budgeted loop inside a private user+net
 * namespace (userns_run_in_ns grandchild, _exit reaps the routes);
 * 50/50 per iter it installs arm A or arm B and RTM_DELROUTE rolls it
 * back, with up to 8 -EAGAIN/-ENOMEM retries per op.
 *
 * Brick-safety: all work is inside CLONE_NEWNET so the host MPLS/IPv4
 * tables are never touched; routes install onto lo only, nexthops in
 * 127/8 and 192.0.2/24 (TEST-NET-1, unroutable).
 *
 * Latches: userns -EPERM latches the op off for the child's life
 * (without a private netns we must not touch host routing).  The
 * per-arm -EAFNOSUPPORT/-EOPNOTSUPP latches and the one-shot
 * mpls_router/mpls_iptunnel modprobe are set inside the grandchild, so
 * the COW copy dies on _exit() and each invocation re-probes once
 * (userns cannot manufacture an absent CONFIG).
 *
 * Header-gated by __has_include() on the MPLS/lwtunnel/rtnetlink uapi
 * (absent headers drop the childop to a stub), with per-symbol #ifndef
 * shims at use site for RTA_VIA/RTA_NEWDST/rtvia and MPLS_IPTUNNEL_*.
 */

#if __has_include(<linux/mpls.h>) && __has_include(<linux/lwtunnel.h>) && \
	__has_include(<linux/mpls_iptunnel.h>) && __has_include(<linux/rtnetlink.h>)

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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
#include "childops-util.h"
#include "jitter.h"
#include "params.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

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
 * within a child's lifetime.  ns_unsupported_userns_mpls_route_churn
 * is the master latch set on userns_run_in_ns() -EPERM and gates the
 * outer dispatcher; the rest are set inside the grandchild and only
 * short-circuit the rest of one invocation's outer loop before the
 * COW copies die on _exit(). */
static bool ns_unsupported_userns_mpls_route_churn;
static bool ns_unsupported_mpls;
static bool ns_unsupported_lwtunnel;
static bool modprobe_tried_mpls_router;

/*
 * One-shot outputerr on the userns latch transition false->true.
 */
static void warn_once_unsupported_userns(const char *reason, int err)
{
	if (ns_unsupported_userns_mpls_route_churn)
		return;
	ns_unsupported_userns_mpls_route_churn = true;
	/* check-static: child-output-ok */
	outputerr("mpls_route_churn: %s failed (errno=%d), latching unsupported_userns\n",
		  reason, err);
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
	__atomic_add_fetch(&shm->stats.mpls_route_churn.ns_unsupported,
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
	__atomic_add_fetch(&shm->stats.mpls_route_churn.ns_unsupported,
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
			      rnd_modulo_u32(MPLS_RC_LABEL_RANGE);
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

	in_label = MPLS_RC_LABEL_MIN + rnd_modulo_u32(MPLS_RC_LABEL_RANGE);
	in_label_buf.entry = mpls_label_encode(in_label, true);
	off = nla_put(buf, off, sizeof(buf), RTA_DST,
		      &in_label_buf, sizeof(in_label_buf));
	if (!off)
		return -EIO;

	stack_n = 1U + rnd_modulo_u32(MPLS_RC_MAX_STACK);
	stack_len = mpls_build_label_stack(out_stack, stack_n);
	off = nla_put(buf, off, sizeof(buf), RTA_NEWDST,
		      out_stack, stack_len);
	if (!off)
		return -EIO;

	memset(via_buf, 0, sizeof(via_buf));
	via->rtvia_family = AF_INET;
	nexthop = htonl(0x7f000002U + rnd_modulo_u32(253U)); /* 127.0.0.{2..254} */
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

	dst = htonl(0xC0000201U + rnd_modulo_u32(254U)); /* 192.0.2.{1..254} */
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

	stack_n = 1U + rnd_modulo_u32(MPLS_RC_MAX_STACK);
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
static void map_rc_to_latch(int op_type, int rc, char arm)
{
	/* op_type is a snapshot of child->op_type from the caller; the
	 * field lives in shared memory and can be scribbled by a
	 * poisoned-arena write from a sibling, so bounds-check the
	 * snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
	 * array and skip the write when it is out of range. */
	const bool valid_op = (op_type >= 0 && op_type < NR_CHILD_OP_TYPES);

	if (rc >= 0)
		return;

	if (rc == -EAFNOSUPPORT || rc == -ENOPROTOOPT) {
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op_type],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		if (arm == 'A')
			latch_ns_unsupported_mpls(rc);
		else
			latch_ns_unsupported_lwtunnel(rc);
		return;
	}

	if (rc == -EOPNOTSUPP) {
		if (arm == 'B') {
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op_type],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
			latch_ns_unsupported_lwtunnel(rc);
		}
		return;
	}

	if (rc == -ENETDOWN || rc == -EPROTONOSUPPORT)
		maybe_modprobe_once();
}

/*
 * Per-invocation state handed to the in-ns callback so its stats
 * writes keep landing against the right childop slot.
 */
struct mpls_route_churn_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so the
 * NETLINK_ROUTE socket and any MPLS / IPv4 routes the BUDGETED outer
 * loop installs are reaped by the kernel along with the namespace.
 * Return value is ignored by the helper.
 */
static int mpls_route_churn_in_ns(void *arg)
{
	struct mpls_route_churn_ctx *cctx = (struct mpls_route_churn_ctx *)arg;
	struct childdata *child = cctx->child;
	struct timespec t_outer;
	unsigned int outer_iters, i;
	struct nl_ctx ctx = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	int lo_ifindex;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range, and pass the
	 * snapshot through to map_rc_to_latch() instead of re-reading
	 * child->op_type. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (nl_open(&ctx, &opts) < 0)
		return 0;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

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

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

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
					&shm->stats.mpls_route_churn.label_install_ok,
					1, __ATOMIC_RELAXED);
				if (build_mpls_label_delete(&ctx,
							    in_label) == 0)
					__atomic_add_fetch(
						&shm->stats.mpls_route_churn.delete_ok,
						1, __ATOMIC_RELAXED);
			} else {
				map_rc_to_latch(op, rc, 'A');
			}
		} else if (!pick_arm_a && !ns_unsupported_lwtunnel) {
			__be32 dst = 0;
			int rc = build_iptunnel_install(&ctx, lo_ifindex,
							&dst);

			if (rc == 0) {
				__atomic_add_fetch(
					&shm->stats.mpls_route_churn.iptunnel_install_ok,
					1, __ATOMIC_RELAXED);
				if (build_iptunnel_delete(&ctx, dst,
							  lo_ifindex) == 0)
					__atomic_add_fetch(
						&shm->stats.mpls_route_churn.delete_ok,
						1, __ATOMIC_RELAXED);
			} else {
				map_rc_to_latch(op, rc, 'B');
			}
		}

		if (ns_unsupported_mpls && ns_unsupported_lwtunnel)
			break;
	}

	nl_close(&ctx);
	return 0;
}

bool mpls_route_churn(struct childdata *child)
{
	struct mpls_route_churn_ctx cctx = { .child = child };
	int rc;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op latch_reason array.  The field lives in shared
	 * memory and can be scribbled by a poisoned-arena write from a
	 * sibling; skip the latch write entirely when the snapshot is
	 * out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.mpls_route_churn.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_userns_mpls_route_churn)
		return true;

	if (ns_unsupported_mpls && ns_unsupported_lwtunnel)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, mpls_route_churn_in_ns, &cctx);
	if (rc == -EPERM) {
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		warn_once_unsupported_userns("userns_run_in_ns(CLONE_NEWNET)",
					     EPERM);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without latching
		 * -- the failure is not policy and may not recur. */
		return true;
	}

	return true;
}

#else  /* !__has_include(<linux/mpls.h>) etc. */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

#include "kernel/socket.h"
bool mpls_route_churn(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.mpls_route_churn.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.mpls_route_churn.ns_unsupported,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif
