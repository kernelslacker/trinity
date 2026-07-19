/*
 * tc_qdisc_churn - TC qdisc tree mutation under live traffic.
 *
 * Targets "qdisc lifetime ends while an skb is still being classified" --
 * the sch_qfq UAF (CVE-2023-4623), sch_qfq OOB (CVE-2023-3611 /
 * -31436), cls_fw refcount (CVE-2023-3776), sch_netem (CVE-2024-36978)
 * lineage.  Random fuzz can't build a working TCM_HANDLE/TCM_PARENT chain
 * so RTM_NEWTCLASS/NEWTFILTER bounce off the lookup gates in
 * net/sched/sch_api.c and cls_api.c before commit-time work runs.
 *
 * Sequence per invocation inside a userns_run_in_ns grandchild (identity
 * userns + CLONE_NEWNET, _exit reaps): fresh RTM_NEWLINK dummy per iter
 * (clean qdisc target instead of stomping shared lo root), IFF_UP,
 * RTM_NEWQDISC root with TCA_KIND rotated across the qdisc-kind table
 * (major:0 handle, random major in [0x10, 0xfff0]).  Classful kinds
 * (htb/hfsc/qfq/prio/ets) get two RTM_NEWTCLASS children (defaults --
 * commit-time codepath runs regardless).  RTM_NEWTFILTER with cls kind
 * rotated {u32, basic, matchall, flower} at prio 1 / ETH_P_ALL wires to
 * root.  UDP burst via SO_BINDTODEVICE drives __dev_xmit_skb ->
 * qdisc_enqueue -> sch_direct_xmit through the freshly-installed tree.
 * Mid-flow RTM_NEWQDISC TCM_REPLACE swaps the root kind (qdisc_replace vs
 * in-flight classify), then RTM_DELTFILTER + RTM_DELQDISC race the
 * still-draining skbs.
 *
 * Sub-mode ONE_IN(4) builds a peek-x-peek stack: parent whose ->dequeue
 * calls .peek() on an inner qdisc whose .peek is qdisc_peek_dequeued
 * (dequeues + stashes in q->skb).  Parents: prio/tbf/sfb/red; children:
 * qfq/sfq/cake.  The bug class: parent believes peek returned a still-
 * queued skb and returns it unchanged, leaving q->skb pointing at an
 * already-dequeued skb.  Same UDP burst shape.
 *
 * Brick-safety: private netns only, dummy + loopback only, one full
 * create/destroy per invocation, burst BUDGETED+JITTER around base 5 with
 * STORM_BUDGET_NS 200 ms wall cap and 64-frame ceiling, all I/O
 * MSG_DONTWAIT + SO_RCVTIMEO=1s on the rtnl ack socket.
 *
 * Latches: userns -EPERM latches the op off for the child's life.  Inside
 * the grandchild: ns_unsupported_dummy on dummy NEWLINK failure;
 * ns_unsupported_kind[] per-kind on missing sch_* / cls_* module.  Per-kind
 * best-effort modprobe sch_<kind> fires once per kind, latched so a missing
 * /sbin/modprobe or lockdown=integrity pays the EFAIL once.
 */

#if __has_include(<linux/udp.h>)
#include <linux/udp.h>
#endif

#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "jitter.h"
#include "name-pool.h"
#include "random.h"
#include "shm.h"
#include "qdisc-churn-internal.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"
#include "kernel/udp.h"
/* Per-iteration packet burst base.  BUDGETED+JITTER scales it.
 * Sends are MSG_DONTWAIT; the inner loop also clamps to
 * STORM_BUDGET_NS wall-clock so even an unbounded burst can't stall
 * past the SIGALRM(1s) cap. */
#define TC_PACKET_BASE		5U
#define TC_PACKET_FLOOR		16U	/* always send at least this many */
#define TC_PACKET_CAP		64U	/* upper clamp on per-iter burst */
#define STORM_BUDGET_NS		200000000L	/* 200 ms */

/* UDP destination port for the loopback drive packet.  Loopback-
 * only inside a private netns — value is functionally arbitrary; a
 * fixed non-privileged port keeps any escaped packet trivially
 * identifiable in a tcpdump trace during triage. */
#define TC_INNER_PORT		34569

/*
 * Qdisc kind rotation.  Each entry is the kind name as the kernel
 * registers it (matches the sch_<kind> module name with the same
 * suffix used by request_module).  Mix of classless (cake, fq_pie,
 * fq_codel, pfifo_fast, netem, tbf) and classful (htb, hfsc, qfq,
 * prio, ets, taprio, sfb, red) so both per-iteration commit paths
 * get coverage.  sfb and red expose .graft via Qdisc_class_ops with
 * a single child slot at classid 1; treated as classful here so
 * they participate as parent qdiscs in the deliberate peek-stack
 * sub-mode (see peek_parents[] below).
 */
struct qdisc_kind {
	const char *name;
	bool classful;
};

static const struct qdisc_kind qdisc_kinds[] = {
	{ "qfq",         true  },
	{ "taprio",      true  },
	{ "netem",       false },
	{ "sfb",         true  },
	{ "red",         true  },
	{ "cake",        false },
	{ "tbf",         false },
	{ "htb",         true  },
	{ "hfsc",        true  },
	{ "prio",        true  },
	{ "ets",         true  },
	{ "fq_pie",      false },
	{ "fq_codel",    false },
	{ "pfifo_fast",  false },
};
#define NR_QDISC_KINDS	ARRAY_SIZE(qdisc_kinds)

/*
 * Filter (cls) kind rotation.  Same shape as qdisc_kinds: name +
 * "needs payload" flag.  matchall is the only one that classifies
 * with no extra options; u32 / basic / flower / bpf accept an empty
 * TCA_OPTIONS and still run the cls_*_init / cls_*_change commit
 * paths that the CVE-2023-3776 cls_fw lineage exercises.
 */
static const char * const cls_kinds[] = {
	"matchall", "u32", "basic", "flower", "bpf",
};
#define NR_CLS_KINDS	ARRAY_SIZE(cls_kinds)

/* Per-grandchild latched gates.  Inherited as false at grandchild
 * fork time (the persistent child never sets them -- the in-ns
 * callback runs exclusively in transient grandchildren) and flipped
 * on the first config-absent rejection from the corresponding
 * subsystem.  Die with the grandchild on _exit(); each subsequent
 * grandchild re-discovers the latch in its own fresh netns.  The
 * EOPNOTSUPP / EAFNOSUPPORT / EPROTONOSUPPORT detection arms are
 * preserved because a fresh user namespace cannot manufacture an
 * absent kernel CONFIG -- the gate still short-circuits the rest
 * of the grandchild's iteration once it fires. */
static bool ns_unsupported_rtnl;
static bool ns_unsupported_dummy;
static bool ns_unsupported_inet;
static bool ns_unsupported_bridge;

/* Per-kind latches: indexed by qdisc_kinds[] / cls_kinds[].  Set on
 * first NEWQDISC / NEWTFILTER rejection with EOPNOTSUPP /
 * EAFNOSUPPORT / ENOENT / ENOMODULE -- the rest of that grandchild's
 * rotation skips the kind. */
static bool ns_unsupported_qdisc_kind[NR_QDISC_KINDS];
static bool ns_unsupported_cls_kind[NR_CLS_KINDS];

/* Per-kind modprobe latch: prevents re-spawning modprobe every
 * iteration for the same kind inside one grandchild. */
static bool modprobe_tried_qdisc[NR_QDISC_KINDS];
static bool modprobe_tried_cls[NR_CLS_KINDS];

static bool lo_brought_up;

/* Master gate: persistent across iterations in the persistent
 * child.  Set when userns_run_in_ns returns -EPERM (hardened userns
 * policy refused CLONE_NEWUSER -- typically
 * user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  The per-grandchild gates
 * above die with the grandchild; helper-EPERM is the only signal
 * that survives long enough to short-circuit subsequent
 * invocations. */
static bool ns_unsupported_tc_qdisc;

static void warn_once_unsupported_tc_qdisc(const char *reason, int err)
{
	if (ns_unsupported_tc_qdisc)
		return;
	ns_unsupported_tc_qdisc = true;
	outputerr("tc_qdisc_churn: %s failed (errno=%d), latching unsupported_tc_qdisc\n",
		  reason, err);
}

static void modprobe_qdisc(unsigned int idx)
{
	char modname[32];

	if (modprobe_tried_qdisc[idx])
		return;
	modprobe_tried_qdisc[idx] = true;
	snprintf(modname, sizeof(modname), "sch_%s", qdisc_kinds[idx].name);
	try_modprobe(modname);
}

static void modprobe_cls(unsigned int idx)
{
	char modname[32];

	if (modprobe_tried_cls[idx])
		return;
	modprobe_tried_cls[idx] = true;
	snprintf(modname, sizeof(modname), "cls_%s", cls_kinds[idx]);
	try_modprobe(modname);
}

/*
 * Bring lo up inside the private netns.  Some classifier paths
 * short-circuit on lo not being up; flip it once-per-child.
 * Failures are ignored — the rest of the sequence will fail
 * visibly if rtnl is genuinely broken.
 */

/*
 * Pick a random qdisc kind index that isn't latched-off.  Returns
 * NR_QDISC_KINDS if every kind is latched (caller bails out).
 */
static unsigned int pick_qdisc_idx(void)
{
	unsigned int start = rnd_modulo_u32(NR_QDISC_KINDS);
	unsigned int i;

	for (i = 0; i < NR_QDISC_KINDS; i++) {
		unsigned int idx = (start + i) % NR_QDISC_KINDS;

		if (!ns_unsupported_qdisc_kind[idx])
			return idx;
	}
	return NR_QDISC_KINDS;
}

/*
 * Pick a different qdisc kind than `avoid`, for the mid-flow
 * REPLACE.  Returns NR_QDISC_KINDS if no alternative is available.
 */
static unsigned int pick_qdisc_idx_other(unsigned int avoid)
{
	unsigned int start = rnd_modulo_u32(NR_QDISC_KINDS);
	unsigned int i;

	for (i = 0; i < NR_QDISC_KINDS; i++) {
		unsigned int idx = (start + i) % NR_QDISC_KINDS;

		if (idx == avoid)
			continue;
		if (!ns_unsupported_qdisc_kind[idx])
			return idx;
	}
	return NR_QDISC_KINDS;
}

static unsigned int pick_cls_idx(void)
{
	unsigned int start = rnd_modulo_u32(NR_CLS_KINDS);
	unsigned int i;

	for (i = 0; i < NR_CLS_KINDS; i++) {
		unsigned int idx = (start + i) % NR_CLS_KINDS;

		if (!ns_unsupported_cls_kind[idx])
			return idx;
	}
	return NR_CLS_KINDS;
}

/*
 * Map a kernel error to a "module unsupported" verdict.  EOPNOTSUPP
 * / EAFNOSUPPORT / EPROTONOSUPPORT / ENOENT are the typical
 * rejections from the kernel for an unknown qdisc / cls module
 * after request_module fails.  EINVAL is excluded — most kinds
 * reject our empty TCA_OPTIONS with EINVAL as a parameter complaint,
 * not a module-missing signal.
 */
static bool is_unsupported_err(int rc)
{
	return rc == -EOPNOTSUPP || rc == -EAFNOSUPPORT ||
	       rc == -EPROTONOSUPPORT || rc == -ENOENT;
}

/*
 * Parents whose ->dequeue calls peek on their inner child qdisc.
 * sfb / red front a single inner queue at classid 1; prio walks
 * its bands (band 1 maps to classid 1 here); tbf gates by token
 * bucket and reads from its single inner queue.  child_classid is
 * the minor used when grafting the child as parent=major:classid.
 *
 * Each entry's opts encoder feeds the parent qdisc init: prio /
 * sfb take empty options; red / tbf demand parameter blobs.
 */
struct peek_parent {
	const char *name;
	peek_opts_encoder enc;
	unsigned short inner_type;
	__u32 child_classid;
};

static const struct peek_parent peek_parents[] = {
	{ "prio", NULL,             0,             1 },
	{ "sfb",  NULL,             0,             1 },
	{ "red",  encode_red_opts,  TCA_RED_PARMS, 1 },
	{ "tbf",  encode_tbf_opts,  TCA_TBF_PARMS, 1 },
};
#define NR_PEEK_PARENTS	ARRAY_SIZE(peek_parents)

/*
 * Children whose .peek is qdisc_peek_dequeued (or a stash-on-peek
 * equivalent for cake).  Empty options are accepted by all three
 * for the qdisc init itself; qfq additionally needs a class +
 * filter so the parent's enqueue path can land an skb in it
 * (handled inline in do_peek_stack).
 */
static const char * const peek_children[] = {
	"qfq", "sfq", "cake",
};
#define NR_PEEK_CHILDREN	ARRAY_SIZE(peek_children)

/*
 * Look up qdisc_kinds[] index for a peek-stack name so we can
 * share the per-kind ns_unsupported / modprobe latches with the
 * standard rotation.  Returns NR_QDISC_KINDS if not found.
 */
static unsigned int qdisc_kind_idx(const char *name)
{
	unsigned int i;

	for (i = 0; i < NR_QDISC_KINDS; i++) {
		if (strcmp(qdisc_kinds[i].name, name) == 0)
			return i;
	}
	return NR_QDISC_KINDS;
}

/*
 * Build the deliberate peek-x-peek stack and drive it with a UDP
 * burst.  Uses the same BUDGETED+JITTER pattern as the standard
 * path so the wall-clock cap is uniform across both sub-modes.
 * Caller falls through to the shared dellink cleanup at the
 * tc_qdisc_churn out: label so any installed qdisc tree gets
 * cascaded down via dev_qdisc_destroy when the dummy goes.
 */
static void do_peek_stack(struct nl_ctx *ctx, int ifindex, const char *dev_name)
{
	const struct peek_parent *p;
	const char *child_name;
	unsigned int p_idx, c_idx;
	unsigned int p_kind_idx, c_kind_idx;
	__u32 p_major, p_handle, c_major, c_handle, c_parent;
	int rc;

	__atomic_add_fetch(&shm->stats.tc_qdisc_churn.peek_stack_runs, 1,
			   __ATOMIC_RELAXED);

	p_idx = rnd_modulo_u32(NR_PEEK_PARENTS);
	c_idx = rnd_modulo_u32(NR_PEEK_CHILDREN);
	p = &peek_parents[p_idx];
	child_name = peek_children[c_idx];

	p_kind_idx = qdisc_kind_idx(p->name);
	c_kind_idx = qdisc_kind_idx(child_name);
	if (p_kind_idx >= NR_QDISC_KINDS || c_kind_idx >= NR_QDISC_KINDS)
		return;
	if (ns_unsupported_qdisc_kind[p_kind_idx] ||
	    ns_unsupported_qdisc_kind[c_kind_idx])
		return;

	modprobe_qdisc(p_kind_idx);
	modprobe_qdisc(c_kind_idx);

	p_major  = (__u32)((rand32() % 0xfee0U) + 0x10U);
	p_handle = p_major << 16;
	/* keep child major distinct from parent for clarity in any
	 * post-mortem dump — the kernel only requires uniqueness within
	 * the device but mixing them up makes triage harder. */
	do {
		c_major = (__u32)((rand32() % 0xfee0U) + 0x10U);
	} while (c_major == p_major);
	c_handle = c_major << 16;
	c_parent = p_handle | p->child_classid;

	rc = build_newqdisc_opts(ctx, ifindex, p_handle, TC_H_ROOT,
				 p->name, p->enc, p->inner_type,
				 NLM_F_CREATE | NLM_F_EXCL);
	if (rc != 0) {
		if (is_unsupported_err(rc))
			ns_unsupported_qdisc_kind[p_kind_idx] = true;
		__atomic_add_fetch(&shm->stats.tc_qdisc_churn.peek_stack_install_fail,
				   1, __ATOMIC_RELAXED);
		return;
	}

	rc = build_newqdisc(ctx, ifindex, c_handle, c_parent,
			    child_name, NLM_F_CREATE | NLM_F_EXCL);
	if (rc != 0) {
		if (is_unsupported_err(rc))
			ns_unsupported_qdisc_kind[c_kind_idx] = true;
		__atomic_add_fetch(&shm->stats.tc_qdisc_churn.peek_stack_install_fail,
				   1, __ATOMIC_RELAXED);
		(void)build_delqdisc(ctx, ifindex, p_handle, TC_H_ROOT);
		return;
	}

	__atomic_add_fetch(&shm->stats.tc_qdisc_churn.peek_stack_install_ok,
			   1, __ATOMIC_RELAXED);

	/*
	 * qfq has no internal classifier — without a class + filter
	 * any enqueue lands nowhere and the parent's peek-on-inner
	 * never sees an skb.  Build a single qfq class and a matchall
	 * filter on the qfq qdisc that pins everything to it.  Errors
	 * here are non-fatal: the install_ok counter already fired
	 * and the burst still exercises some part of the path.
	 */
	if (strcmp(child_name, "qfq") == 0) {
		__u32 qfq_class = c_handle | 1U;

		(void)build_qfq_class(ctx, ifindex, qfq_class, c_handle);
		(void)build_newtfilter(ctx, ifindex, c_handle, "matchall");
	}

	if (!ns_unsupported_inet) {
		struct sockaddr_in dst;
		struct timespec t0;
		unsigned int iters, i;
		int udp;

		udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (udp < 0) {
			if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
				ns_unsupported_inet = true;
			return;
		}
		(void)setsockopt(udp, SOL_SOCKET, SO_BINDTODEVICE,
				 dev_name, strlen(dev_name) + 1);

		memset(&dst, 0, sizeof(dst));
		dst.sin_family      = AF_INET;
		dst.sin_port        = htons(TC_INNER_PORT);
		dst.sin_addr.s_addr = htonl(0x7f000001U);

		(void)clock_gettime(CLOCK_MONOTONIC, &t0);
		iters = BUDGETED(CHILD_OP_TC_QDISC_CHURN,
				 JITTER_RANGE(TC_PACKET_BASE));
		if (iters < TC_PACKET_FLOOR)
			iters = TC_PACKET_FLOOR;
		if (iters > TC_PACKET_CAP)
			iters = TC_PACKET_CAP;

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
				__atomic_add_fetch(&shm->stats.tc_qdisc_churn.peek_stack_burst_ok,
						   1, __ATOMIC_RELAXED);
		}

		close(udp);
	}
}

/*
 * Per-iteration scratchpad shared across the tc_qdisc_<phase> helpers.
 * Lifetime is exactly one tc_qdisc_churn_in_ns() invocation; avoids
 * threading half a dozen out-parameters through the phase helpers.
 * `child` is carried in so the in-ns callback can credit the per-op
 * stats arrays against the same op_type slot the wrapper sampled.
 */
struct tc_qdisc_iter_ctx {
	struct nl_ctx	nl;
	char		dummy_name[IFNAMSIZ];
	char		bridge_name[IFNAMSIZ];
	char		peer_name[IFNAMSIZ];
	int		udp;
	int		dummy_idx;
	int		bridge_idx;
	bool		dummy_added;
	bool		bridge_mode;
	bool		slave_dellinked;
	unsigned int	qidx;
	__u32		handle;
	__u32		class1;
	__u32		class2;
	struct childdata *child;
};

/*
 * Build the per-iteration parent netdev.  Default path: RTM_NEWLINK
 * type=dummy with a random name.  One iteration in three (when
 * supported) instead creates a fresh bridge + veth pair and enslaves
 * one end of the pair to the bridge — the slave port becomes the
 * DELLINK target raced against the flush burst at teardown, the
 * shape of the dequeue-after-parent-free UAF in
 * qdisc_pkt_len_segs_init.  Returns 0 with it->dummy_idx > 0 on
 * success; nonzero means the caller should goto out to clean up.
 */
static int tc_qdisc_add_link(struct tc_qdisc_iter_ctx *it)
{
	int rc;

	it->bridge_mode = !ns_unsupported_bridge && ONE_IN(3);
	if (it->bridge_mode) {
		snprintf(it->bridge_name, sizeof(it->bridge_name), "trbr%u",
			 (unsigned int)(rand32() & 0xffffu));
		snprintf(it->dummy_name, sizeof(it->dummy_name), "trv%u",
			 (unsigned int)(rand32() & 0xffffu));
		snprintf(it->peer_name, sizeof(it->peer_name), "trvp%u",
			 (unsigned int)(rand32() & 0xffffu));

		rc = build_bridge_create(&it->nl, it->bridge_name);
		if (rc != 0) {
			if (is_unsupported_err(rc))
				ns_unsupported_bridge = true;
			it->bridge_mode = false;
		} else {
			it->bridge_idx = (int)if_nametoindex(it->bridge_name);
			rc = build_veth_pair(&it->nl, it->dummy_name, it->peer_name);
			if (rc != 0) {
				if (it->bridge_idx > 0)
					(void)rtnl_dellink(&it->nl, it->bridge_idx);
				it->bridge_idx = 0;
				it->bridge_mode = false;
			} else {
				it->dummy_idx = (int)if_nametoindex(it->dummy_name);
				if (it->dummy_idx > 0 && it->bridge_idx > 0)
					(void)build_setlink_master(&it->nl, it->dummy_idx,
								   it->bridge_idx);
				if (it->bridge_idx > 0)
					(void)rtnl_setlink_up(&it->nl, it->bridge_idx);
				if (it->dummy_idx > 0)
					(void)rtnl_setlink_up(&it->nl, it->dummy_idx);
				it->dummy_added = true;
				__atomic_add_fetch(&shm->stats.tc_qdisc_churn.link_create_ok,
						   1, __ATOMIC_RELAXED);
				__atomic_add_fetch(&shm->stats.tc_qdisc_churn.bridge_parent_runs,
						   1, __ATOMIC_RELAXED);
			}
		}
	}

	if (!it->bridge_mode) {
		snprintf(it->dummy_name, sizeof(it->dummy_name), "trtcd%u",
			 (unsigned int)(rand32() & 0xffffu));

		rc = build_dummy_create(&it->nl, it->dummy_name);
		if (rc != 0) {
			if (is_unsupported_err(rc))
				ns_unsupported_dummy = true;
			return -1;
		}
		it->dummy_added = true;
		__atomic_add_fetch(&shm->stats.tc_qdisc_churn.link_create_ok,
				   1, __ATOMIC_RELAXED);

		it->dummy_idx = (int)if_nametoindex(it->dummy_name);
		if (it->dummy_idx == 0)
			return -1;

		(void)rtnl_setlink_up(&it->nl, it->dummy_idx);
	}

	if (it->dummy_idx <= 0)
		return -1;

	/* Kernel confirmed it->dummy_name now names a real device (the
	 * one tc_qdisc_churn_loop binds via SO_BINDTODEVICE); publish it
	 * via the NETDEV name pool so sibling childops and per-syscall
	 * fuzzers drawing this kind can reference it on subsequent
	 * invocations -- reaches bind-success / dev_get_by_name HIT
	 * codepaths instead of always-ENODEV near-miss space. */
	name_pool_record(NAME_KIND_NETDEV, it->dummy_name,
			 strlen(it->dummy_name));
	return 0;
}

/*
 * Pick a qdisc kind, modprobe sch_<kind> best-effort, and install
 * the root qdisc on it->dummy_idx with a random major in the safe
 * range [0x10, 0xfff0].  Stores qidx / handle / class{1,2} into it
 * for the filter+class and churn-loop helpers downstream.  Returns
 * 0 on success; nonzero (every kind latched, EOPNOTSUPP, etc.) means
 * the caller should bail to the cleanup path.
 */
static int tc_qdisc_add_qdisc(struct tc_qdisc_iter_ctx *it)
{
	__u32 major;
	int rc;

	it->qidx = pick_qdisc_idx();
	if (it->qidx >= NR_QDISC_KINDS)
		return -1;

	/* random major in [0x10, 0xfff0] keeps us clear of TC_H_MAJ
	 * values reserved for the kernel's own ingress / clsact / root
	 * qdiscs (0xffff* is the well-known reserved range). */
	major = (__u32)((rand32() % 0xfee0U) + 0x10U);
	it->handle = major << 16;
	it->class1 = it->handle | 1U;
	it->class2 = it->handle | 2U;

	modprobe_qdisc(it->qidx);
	rc = build_newqdisc(&it->nl, it->dummy_idx, it->handle, TC_H_ROOT,
			    qdisc_kinds[it->qidx].name,
			    NLM_F_CREATE | NLM_F_EXCL);
	if (rc != 0) {
		if (is_unsupported_err(rc))
			ns_unsupported_qdisc_kind[it->qidx] = true;
		return -1;
	}
	__atomic_add_fetch(&shm->stats.tc_qdisc_churn.qdisc_create_ok,
			   1, __ATOMIC_RELAXED);
	return 0;
}

/*
 * Stand up the rest of the tc tree on the freshly-installed root
 * qdisc: two classes at major:1 / major:2 if the kind is classful,
 * then one filter at root with a randomly-picked cls kind.  All
 * best-effort — install failures are latched per-kind but the rest
 * of the iteration still runs.
 */
static void tc_qdisc_add_filter_class(struct tc_qdisc_iter_ctx *it)
{
	unsigned int cidx;
	int rc;

	if (qdisc_kinds[it->qidx].classful) {
		if (build_newtclass(&it->nl, it->dummy_idx, it->class1, TC_H_ROOT,
				    qdisc_kinds[it->qidx].name) == 0)
			__atomic_add_fetch(&shm->stats.tc_qdisc_churn.tclass_create_ok,
					   1, __ATOMIC_RELAXED);
		if (build_newtclass(&it->nl, it->dummy_idx, it->class2, TC_H_ROOT,
				    qdisc_kinds[it->qidx].name) == 0)
			__atomic_add_fetch(&shm->stats.tc_qdisc_churn.tclass_create_ok,
					   1, __ATOMIC_RELAXED);
	}

	cidx = pick_cls_idx();
	if (cidx < NR_CLS_KINDS) {
		modprobe_cls(cidx);
		rc = build_newtfilter(&it->nl, it->dummy_idx, it->handle,
				      cls_kinds[cidx]);
		if (rc == 0) {
			__atomic_add_fetch(&shm->stats.tc_qdisc_churn.tfilter_create_ok,
					   1, __ATOMIC_RELAXED);
		} else if (is_unsupported_err(rc)) {
			ns_unsupported_cls_kind[cidx] = true;
		}
	}
}

/*
 * UDP GSO burst.  Enables UDP_SEGMENT with a small gso_size and
 * sends a payload > gso_size so the kernel builds a single super-skb
 * with skb_is_gso(skb)==true; qdisc enqueue takes the GSO branch and
 * calls qdisc_pkt_len_segs_init() to back-out per-segment lengths
 * into the parent qdisc's backlog accounting.  That accounting path
 * is the bridge-slave-dellink / qdisc-replace UAF window targeted
 * here; plain 64-byte UDP packets never reach it because they are
 * non-GSO.  Self-bounded by `iters` (caller picks a small constant)
 * and ignores all errors -- UDP_SEGMENT EOPNOTSUPP, sendto EMSGSIZE,
 * the dummy dropping segments after dequeue: the enqueue path that
 * runs the accounting code is what matters.
 */
static void send_udp_gso_burst(int udp, const struct sockaddr_in *dst,
			       unsigned int iters)
{
	int gso_size = 128;
	unsigned char payload[1024];
	unsigned int i;

	if (udp < 0)
		return;
	(void)setsockopt(udp, SOL_UDP, UDP_SEGMENT,
			 &gso_size, sizeof(gso_size));

	for (i = 0; i < iters; i++) {
		ssize_t n;

		generate_rand_bytes(payload, sizeof(payload));
		n = sendto(udp, payload, sizeof(payload), MSG_DONTWAIT,
			   (const struct sockaddr *)dst, sizeof(*dst));
		if (n > 0)
			__atomic_add_fetch(&shm->stats.tc_qdisc_churn.gso_burst_ok,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * Drive the freshly-installed qdisc/class/filter tree with a UDP
 * burst, then race the in-flight traffic against teardown.
 *
 * Burst: loopback UDP via dummy with SO_BINDTODEVICE; each send
 * walks __dev_xmit_skb / qdisc_enqueue / sch_direct_xmit through
 * the new tree.  BUDGETED+JITTER iters, STORM_BUDGET_NS wall-clock
 * cap.  dummy's xmit drops on the floor after dequeue, but the
 * classification / enqueue / dequeue cycle is what the CVE class
 * lives in.
 *
 * Mid-flow REPLACE: swap the root qdisc kind to a different
 * rotation entry while skbs are still draining — the targeted
 * qdisc_replace race window (CVE-2023-4623 sch_qfq UAF shape).
 *
 * Teardown:
 *   - normal path: RTM_DELTFILTER then RTM_DELQDISC, racing in-
 *     flight skbs against cls_*_destroy / qdisc_destroy.
 *   - bridge-slave path: prime a flush burst, RTM_DELLINK the
 *     slave veth, push a final flush burst.  netdev unregister
 *     hands off to a workqueue so subsequent sends can hit dequeue
 *     while cleanup is in flight — the dequeue-after-parent-free
 *     window for qdisc_pkt_len_segs_init.  Marks it->slave_dellinked
 *     so the shared cleanup at out: doesn't try to dellink twice.
 */
static void tc_qdisc_churn_loop(struct tc_qdisc_iter_ctx *it)
{
	struct timespec t0;
	unsigned int qidx2, iters, i;
	int rc;

	if (!ns_unsupported_inet) {
		it->udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (it->udp < 0) {
			if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
				ns_unsupported_inet = true;
		} else {
			(void)setsockopt(it->udp, SOL_SOCKET, SO_BINDTODEVICE,
					 it->dummy_name, strlen(it->dummy_name) + 1);
		}
	}

	if (it->udp >= 0) {
		struct sockaddr_in dst;

		memset(&dst, 0, sizeof(dst));
		dst.sin_family      = AF_INET;
		dst.sin_port        = htons(TC_INNER_PORT);
		dst.sin_addr.s_addr = htonl(0x7f000001U);	/* 127.0.0.1 */

		(void)clock_gettime(CLOCK_MONOTONIC, &t0);
		iters = BUDGETED(CHILD_OP_TC_QDISC_CHURN,
				 JITTER_RANGE(TC_PACKET_BASE));
		if (iters < TC_PACKET_FLOOR)
			iters = TC_PACKET_FLOOR;
		if (iters > TC_PACKET_CAP)
			iters = TC_PACKET_CAP;

		for (i = 0; i < iters; i++) {
			unsigned char payload[64];
			ssize_t n;

			if (ns_since(&t0) >= STORM_BUDGET_NS)
				break;

			generate_rand_bytes(payload, sizeof(payload));
			n = sendto(it->udp, payload, sizeof(payload),
				   MSG_DONTWAIT,
				   (struct sockaddr *)&dst, sizeof(dst));
			if (n > 0)
				__atomic_add_fetch(&shm->stats.tc_qdisc_churn.packet_sent_ok,
						   1, __ATOMIC_RELAXED);
		}

		/*
		 * Push a few GSO super-skbs so the imminent REPLACE
		 * (both modes) and DELLINK (bridge mode) race the
		 * qdisc_pkt_len_segs_init accounting on still-segmenting
		 * skbs.  4 sends * 8 segments each gives the kernel work
		 * to drain across the teardown window.
		 */
		send_udp_gso_burst(it->udp, &dst, 4);
	}

	qidx2 = pick_qdisc_idx_other(it->qidx);
	if (qidx2 < NR_QDISC_KINDS) {
		modprobe_qdisc(qidx2);
		rc = build_newqdisc(&it->nl, it->dummy_idx, it->handle, TC_H_ROOT,
				    qdisc_kinds[qidx2].name,
				    NLM_F_CREATE | NLM_F_REPLACE);
		if (rc == 0) {
			__atomic_add_fetch(&shm->stats.tc_qdisc_churn.qdisc_replace_ok,
					   1, __ATOMIC_RELAXED);
		} else if (is_unsupported_err(rc)) {
			ns_unsupported_qdisc_kind[qidx2] = true;
		}
	}

	if (!it->bridge_mode) {
		if (build_deltfilter(&it->nl, it->dummy_idx, it->handle) == 0)
			__atomic_add_fetch(&shm->stats.tc_qdisc_churn.tfilter_del_ok,
					   1, __ATOMIC_RELAXED);

		if (build_delqdisc(&it->nl, it->dummy_idx, it->handle, TC_H_ROOT) == 0)
			__atomic_add_fetch(&shm->stats.tc_qdisc_churn.qdisc_del_ok,
					   1, __ATOMIC_RELAXED);
	} else if (it->udp >= 0 && it->dummy_idx > 0) {
		struct sockaddr_in dst;
		unsigned char payload[64];
		unsigned int j;

		memset(&dst, 0, sizeof(dst));
		dst.sin_family      = AF_INET;
		dst.sin_port        = htons(TC_INNER_PORT);
		dst.sin_addr.s_addr = htonl(0x7f000001U);

		for (j = 0; j < 8; j++) {
			generate_rand_bytes(payload, sizeof(payload));
			(void)sendto(it->udp, payload, sizeof(payload),
				     MSG_DONTWAIT,
				     (struct sockaddr *)&dst, sizeof(dst));
		}
		if (rtnl_dellink(&it->nl, it->dummy_idx) == 0) {
			__atomic_add_fetch(&shm->stats.tc_qdisc_churn.link_del_ok,
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.tc_qdisc_churn.bridge_dellink_race_ok,
					   1, __ATOMIC_RELAXED);
			it->slave_dellinked = true;
		}
		for (j = 0; j < 8; j++) {
			generate_rand_bytes(payload, sizeof(payload));
			(void)sendto(it->udp, payload, sizeof(payload),
				     MSG_DONTWAIT,
				     (struct sockaddr *)&dst, sizeof(dst));
		}
		/*
		 * Final GSO sub-burst: slave is gone but the netdev
		 * unregister is workqueue-deferred, so the qdisc tree
		 * may still accept enqueue.  GSO super-skbs land in
		 * qdisc_pkt_len_segs_init on a parent whose lifetime
		 * is dropping out from underneath -- the exact UAF
		 * shape this childop chases.
		 */
		send_udp_gso_burst(it->udp, &dst, 4);
	}
}

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any qdisc,
 * class, filter, dummy / veth / bridge link and socket left behind is
 * reaped along with the namespace.  Explicit DELLINK / close() calls
 * are still issued so the in-ns stats counters (link_del_ok etc.)
 * move on the success path; correctness does not depend on them.
 * Return value is ignored by the helper.
 */
static int tc_qdisc_churn_in_ns(void *arg)
{
	struct tc_qdisc_iter_ctx *it = (struct tc_qdisc_iter_ctx *)arg;
	struct childdata *child = it->child;
	struct nl_open_opts nl_opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (nl_open(&it->nl, &nl_opts) < 0) {
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT)
			ns_unsupported_rtnl = true;
		__atomic_add_fetch(&shm->stats.tc_qdisc_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return 0;
	}

	if (!lo_brought_up) {
		rtnl_bring_lo_up(&it->nl);
		lo_brought_up = true;
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if (tc_qdisc_add_link(it) != 0)
		goto out;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	/*
	 * One iteration in four runs the deliberate peek-x-peek stack
	 * sub-mode instead of the standard rotation.  Cleanup
	 * (RTM_DELLINK on the dummy) still happens at the shared
	 * out: label so any qdisc tree the sub-mode installed gets
	 * cascaded down via dev_qdisc_destroy when the link goes.
	 */
	if (ONE_IN(4)) {
		do_peek_stack(&it->nl, it->dummy_idx, it->dummy_name);
		goto out;
	}

	if (tc_qdisc_add_qdisc(it) != 0)
		goto out;

	tc_qdisc_add_filter_class(it);
	tc_qdisc_churn_loop(it);

out:
	if (it->udp >= 0)
		close(it->udp);

	if (it->nl.fd >= 0) {
		if (it->dummy_added && it->dummy_idx > 0 && !it->slave_dellinked) {
			if (rtnl_dellink(&it->nl, it->dummy_idx) == 0)
				__atomic_add_fetch(&shm->stats.tc_qdisc_churn.link_del_ok,
						   1, __ATOMIC_RELAXED);
		}
		if (it->bridge_idx > 0)
			(void)rtnl_dellink(&it->nl, it->bridge_idx);
		nl_close(&it->nl);
	}

	return 0;
}

bool tc_qdisc_churn(struct childdata *child)
{
	struct tc_qdisc_iter_ctx it = {
		.nl    = { .fd = -1 },
		.udp   = -1,
		.child = child,
	};
	int rc;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.tc_qdisc_churn.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_tc_qdisc)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, tc_qdisc_churn_in_ns, &it);
	if (rc == -EPERM) {
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		warn_once_unsupported_tc_qdisc("userns_run_in_ns(CLONE_NEWNET)",
					       EPERM);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without
		 * latching -- the failure is not policy and may not
		 * recur. */
		return true;
	}
	return true;
}
