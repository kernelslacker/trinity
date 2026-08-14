/*
 * tc_standalone_action - exercise the standalone tc-action plane:
 * RTM_NEWACTION / RTM_DELACTION over TCA_ACT_TAB, racing action
 * replacement against in-flight traffic.
 *
 * Coverage gap this fills: the filter plane (live-traffic.c) never reaches
 * RTM_NEWACTION / RTM_DELACTION.  The standalone action plane is the only
 * caller of tcf_action_set_ctrlact() from userspace via RTM_NEWACTION +
 * NLM_F_REPLACE.  upstream: f60b396ee174 ('net/sched: act_api: fix TOCTOU
 * NULL deref on a->goto_chain') fixed a race between tcf_action_exec()
 * (which checked rcu_access_pointer(a->goto_chain) then called
 * tcf_action_goto_chain_exec() which did a second rcu_dereference_bh()
 * and dereferenced chain->filter_chain) and a concurrent
 * tcf_action_set_ctrlact() on the gact replace path clearing a->goto_chain
 * between the two reads.
 *
 * What this op does:
 *  1. Spawns a fresh CLONE_NEWUSER + CLONE_NEWNET grandchild so every
 *     device and namespace is fully private.
 *  2. Creates a veth pair (A + B ends), brings both up.
 *  3. Attaches clsact qdisc on A.
 *  4. Creates a shared gact action via RTM_NEWACTION with verdict
 *     TC_ACT_GOTO_CHAIN|1.  The action gets a fixed index (TCSA_ACTION_IDX)
 *     inside the fresh netns IDR so it is addressable for replace+delete.
 *  5. Installs a matchall filter on clsact ingress that references the
 *     shared action by index.
 *  6. Fires a UDP burst so packets cross tcf_action_exec() with the
 *     goto_chain verdict live.
 *  7. Mid-burst: RTM_NEWACTION + NLM_F_REPLACE with a flipped ctrlact
 *     (TC_ACT_OK ↔ TC_ACT_GOTO_CHAIN|1) -- this reaches
 *     tcf_action_set_ctrlact() while traffic is in flight and bumps the
 *     tc_action_replace_concurrent counter.
 *  8. Teardown: delete filter, delete shared action, delete veth pair.
 *
 * Brick-safety: only private veth ends inside the fresh netns are touched.
 * All netlink I/O uses SO_RCVTIMEO=1s.  Traffic burst is capped via
 * STORM_BUDGET_NS.  Every setup path fails soft; unsupported subsystems latch
 * off fleet-wide via shm exactly as the live-traffic sibling does.
 *
 * Kernel config: CONFIG_NET_CLS_ACT=y, CONFIG_NET_ACT_GACT=m both enabled.
 */

#if __has_include(<linux/pkt_sched.h>)
#include <linux/pkt_sched.h>
#endif
#if __has_include(<linux/pkt_cls.h>)
#include <linux/pkt_cls.h>
#endif
#if __has_include(<linux/tc_act/tc_gact.h>)
#include <linux/tc_act/tc_gact.h>
#endif

#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childop-outcome.h"
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

/* -------- UAPI fallbacks -------- */

#ifndef TC_H_ROOT
#define TC_H_ROOT		(0xFFFFFFFFU)
#endif
#ifndef TC_H_CLSACT
#define TC_H_CLSACT		(0xFFFFFFF1U)
#endif
#ifndef TC_H_MIN_INGRESS
#define TC_H_MIN_INGRESS	(0xFFF2U)
#endif

#ifndef TCA_UNSPEC
#define TCA_UNSPEC		0
#define TCA_KIND		1
#define TCA_OPTIONS		2
#endif

#ifndef RTM_NEWQDISC
#define RTM_NEWQDISC		36
#define RTM_NEWTFILTER		44
#define RTM_DELTFILTER		45
#endif

/* RTM_NEWACTION / RTM_DELACTION: standalone TC action plane.
 * RTM_NEWACTION = 48, RTM_DELACTION = 49 -- stable UAPI. */
#ifndef RTM_NEWACTION
#define RTM_NEWACTION		48
#define RTM_DELACTION		49
#endif

/* TCA_ACT_TAB (== TCA_ROOT_TAB == 1): top-level nest in struct tcamsg
 * messages that carries the per-index action nests. */
#ifndef TCA_ACT_TAB
#define TCA_ACT_TAB		1
#endif

/* struct tcamsg: header for RTM_NEWACTION / RTM_DELACTION messages.
 * Stable kernel UAPI (linux/rtnetlink.h).  The family field is the
 * only meaningful member for gact; pad bytes must be zero. */
struct fallback_tcamsg {
	unsigned char	tca_family;
	unsigned char	tca__pad1;
	unsigned short	tca__pad2;
};

/* Action attribute namespace (tca_id nests). */
#ifndef TCA_ACT_UNSPEC
#define TCA_ACT_UNSPEC		0
#define TCA_ACT_KIND		1
#define TCA_ACT_OPTIONS		2
#endif

/* matchall classifier attributes. */
#ifndef TCA_MATCHALL_UNSPEC
#define TCA_MATCHALL_UNSPEC	0
#define TCA_MATCHALL_CLASSID	1
#define TCA_MATCHALL_ACT	2
#define TCA_MATCHALL_FLAGS	3
#endif

/* gact verdict values. */
#ifndef TC_ACT_OK
#define TC_ACT_OK		0
#endif
#ifndef TC_ACT_PIPE
#define TC_ACT_PIPE		3
#endif
#ifndef TC_ACT_EXT_SHIFT
#define TC_ACT_EXT_SHIFT	28
#endif
#ifndef TC_ACT_GOTO_CHAIN
#define TC_ACT_GOTO_CHAIN	0x20000000U
#endif

/* Fallback struct tc_gact.  Covers distros whose sysroot does not carry
 * a clean linux/tc_act/tc_gact.h.  Sized exactly like the kernel struct
 * via explicit fixed-width fields. */
struct fallback_tc_gact {
	__u32	index;		/* action id; 0 = allocate, non-zero = use this slot */
	__u32	capab;
	int	action;		/* TC_ACT_* verdict */
	int	refcnt;
	int	bindcnt;
};

/* Fixed action index inside the private netns IDR.  Because we operate
 * inside a fresh CLONE_NEWNET the gact IDR starts empty; index 1 is
 * always free on first install.  Using a fixed index simplifies replace
 * and delete -- we never need to parse the kernel's response to learn
 * the assigned index. */
#define TCSA_ACTION_IDX		1U

/* Target chain for the TC_ACT_GOTO_CHAIN verdict.  Chain 1 is implicitly
 * created by the kernel on first reference; no RTM_NEWCHAIN needed. */
#define TCSA_GOTO_CHAIN		1U

#define RTNL_BUF_BYTES		4096

/* UDP burst tuning -- same knobs as live-traffic sibling. */
#define TCSA_PACKET_BASE	4U
#define TCSA_PACKET_FLOOR	6U
#define TCSA_PACKET_CAP		32U
#define STORM_BUDGET_NS		200000000L

#define TCSA_INNER_PORT		34574	/* different from live-traffic (34573) */

/* -------- shm latch helpers -------- */

static bool ns_unsupported_rtnl(void)
{
	return __atomic_load_n(&shm->tc_sa_ns_unsupported_rtnl,
			       __ATOMIC_RELAXED);
}
static void mark_ns_unsupported_rtnl(void)
{
	__atomic_store_n(&shm->tc_sa_ns_unsupported_rtnl, true,
			 __ATOMIC_RELAXED);
}

static bool ns_unsupported_veth(void)
{
	return __atomic_load_n(&shm->tc_sa_ns_unsupported_veth,
			       __ATOMIC_RELAXED);
}
static void mark_ns_unsupported_veth(void)
{
	__atomic_store_n(&shm->tc_sa_ns_unsupported_veth, true,
			 __ATOMIC_RELAXED);
}

static bool ns_unsupported_clsact(void)
{
	return __atomic_load_n(&shm->tc_sa_ns_unsupported_clsact,
			       __ATOMIC_RELAXED);
}
static void mark_ns_unsupported_clsact(void)
{
	__atomic_store_n(&shm->tc_sa_ns_unsupported_clsact, true,
			 __ATOMIC_RELAXED);
}

static bool ns_unsupported_matchall(void)
{
	return __atomic_load_n(&shm->tc_sa_ns_unsupported_matchall,
			       __ATOMIC_RELAXED);
}
static void mark_ns_unsupported_matchall(void)
{
	__atomic_store_n(&shm->tc_sa_ns_unsupported_matchall, true,
			 __ATOMIC_RELAXED);
}

static bool ns_unsupported_action(void)
{
	return __atomic_load_n(&shm->tc_sa_ns_unsupported_action,
			       __ATOMIC_RELAXED);
}
static void mark_ns_unsupported_action(void)
{
	__atomic_store_n(&shm->tc_sa_ns_unsupported_action, true,
			 __ATOMIC_RELAXED);
}

static bool ns_unsupported_inet(void)
{
	return __atomic_load_n(&shm->tc_sa_ns_unsupported_inet,
			       __ATOMIC_RELAXED);
}
static void mark_ns_unsupported_inet(void)
{
	__atomic_store_n(&shm->tc_sa_ns_unsupported_inet, true,
			 __ATOMIC_RELAXED);
}

static bool lo_brought_up(void)
{
	return __atomic_load_n(&shm->tc_sa_lo_brought_up,
			       __ATOMIC_RELAXED);
}
static void mark_lo_brought_up(void)
{
	__atomic_store_n(&shm->tc_sa_lo_brought_up, true,
			 __ATOMIC_RELAXED);
}

static bool modprobe_tried_ingress(void)
{
	return __atomic_load_n(&shm->tc_sa_modprobe_tried_ingress,
			       __ATOMIC_RELAXED);
}
static void mark_modprobe_tried_ingress(void)
{
	__atomic_store_n(&shm->tc_sa_modprobe_tried_ingress, true,
			 __ATOMIC_RELAXED);
}

static bool modprobe_tried_matchall(void)
{
	return __atomic_load_n(&shm->tc_sa_modprobe_tried_matchall,
			       __ATOMIC_RELAXED);
}
static void mark_modprobe_tried_matchall(void)
{
	__atomic_store_n(&shm->tc_sa_modprobe_tried_matchall, true,
			 __ATOMIC_RELAXED);
}

static bool modprobe_tried_act_gact(void)
{
	return __atomic_load_n(&shm->tc_sa_modprobe_tried_act_gact,
			       __ATOMIC_RELAXED);
}
static void mark_modprobe_tried_act_gact(void)
{
	__atomic_store_n(&shm->tc_sa_modprobe_tried_act_gact, true,
			 __ATOMIC_RELAXED);
}

/* Master gate: latched when userns_run_in_ns() returns -EPERM. */
static bool ns_setup_failed;

static void warn_once_setup_failed(int err)
{
	static bool warned;

	if (warned)
		return;
	warned = true;
	/* check-static: child-output-ok */
	outputerr("tc_standalone_action: userns_run_in_ns(CLONE_NEWNET) failed (errno=%d), latching ns_setup_failed\n",
		  err);
}

static bool is_unsupported_err(int rc)
{
	return rc == -EOPNOTSUPP || rc == -EAFNOSUPPORT ||
	       rc == -EPROTONOSUPPORT || rc == -ENOENT;
}

/* -------- Netlink message builders -------- */

/*
 * RTM_NEWLINK type=veth with peer.  Inlined from live-traffic.c (same
 * shape; we do not pull in qdisc-churn-internal.h which is private to
 * that TU pair).
 */
static int build_veth_pair(struct nl_ctx *ctx, const char *name,
			   const char *peer)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi, *peer_ifi;
	size_t off, li_off, id_off, p_off;

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
	if (!off) return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth");
	if (!off) return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off) return -EIO;

	p_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), VETH_INFO_PEER);
	if (!off) return -EIO;
	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, peer);
	if (!off) return -EIO;
	nla_nest_end(buf, p_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * RTM_NEWQDISC clsact root on ifindex.
 */
static int build_clsact(struct nl_ctx *ctx, int ifindex)
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
	tcm->tcm_handle  = 0xFFFF0000U;
	tcm->tcm_parent  = TC_H_CLSACT;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*tcm));
	off = nla_put_str(buf, off, sizeof(buf), TCA_KIND, "clsact");
	if (!off) return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * Build RTM_NEWACTION or RTM_DELACTION for a standalone gact.
 *
 * For create (NLM_F_CREATE set, no NLM_F_REPLACE):
 *   verdict = TC_ACT_GOTO_CHAIN|TCSA_GOTO_CHAIN
 *   index   = TCSA_ACTION_IDX  (fixed; netns IDR is empty at start)
 *
 * For replace (NLM_F_REPLACE set):
 *   verdict flips between TC_ACT_OK and TC_ACT_GOTO_CHAIN|TCSA_GOTO_CHAIN
 *   -- this enters tcf_action_set_ctrlact() on the existing gact struct
 *   while a concurrent tcf_action_exec() may be reading a->goto_chain.
 *
 * For delete (type=RTM_DELACTION):
 *   verdict ignored; index identifies the action to free.
 *
 * Message layout:
 *   nlmsghdr
 *   tcamsg   { tca_family=AF_UNSPEC }
 *   TCA_ACT_TAB (nested):
 *     [1] (nested):                <- action-table slot 1
 *       TCA_ACT_KIND: "gact"
 *       TCA_ACT_OPTIONS (nested):
 *         TCA_GACT_PARMS: struct fallback_tc_gact
 */
static int build_action_msg(struct nl_ctx *ctx,
			    __u16 nlmsg_type, __u16 extra_flags,
			    __u32 act_index, int verdict)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct fallback_tcamsg *tca;
	struct fallback_tc_gact gact;
	size_t off, tab_off, slot_off, opts_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = nlmsg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | extra_flags;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	tca = (struct fallback_tcamsg *)NLMSG_DATA(nlh);
	tca->tca_family = AF_UNSPEC;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*tca));

	/* TCA_ACT_TAB nest */
	tab_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TCA_ACT_TAB);
	if (!off) return -EIO;

	/* action slot [1] */
	slot_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), 1);
	if (!off) return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), TCA_ACT_KIND, "gact");
	if (!off) return -EIO;

	opts_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TCA_ACT_OPTIONS);
	if (!off) return -EIO;

	memset(&gact, 0, sizeof(gact));
	gact.index  = act_index;
	gact.action = verdict;
	/* TCA_GACT_PARMS = 1 */
	off = nla_put(buf, off, sizeof(buf), 1 /* TCA_GACT_PARMS */,
		      &gact, sizeof(gact));
	if (!off) return -EIO;

	nla_nest_end(buf, opts_off, off);
	nla_nest_end(buf, slot_off, off);
	nla_nest_end(buf, tab_off,  off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * RTM_NEWTFILTER matchall on clsact ingress, referencing the shared gact
 * action by its fixed index TCSA_ACTION_IDX.  Passing a non-zero index in
 * tc_gact.index causes tcf_action_init_1() to look up and bind the existing
 * shared action rather than creating a new one.  NLM_F_CREATE on the filter
 * is still set -- the filter itself is new; it is the action that is shared.
 */
static int build_matchall_shared_action(struct nl_ctx *ctx, int ifindex,
					__u32 prio, __u32 shared_act_idx)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct tcmsg *tcm;
	struct fallback_tc_gact gact;
	size_t off, opts_off, act_off, slot_off;
	__u32 prio_proto;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWTFILTER;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	tcm = (struct tcmsg *)NLMSG_DATA(nlh);
	tcm->tcm_family  = AF_UNSPEC;
	tcm->tcm_ifindex = ifindex;
	tcm->tcm_handle  = 0;
	tcm->tcm_parent  = 0xFFFF0000U | TC_H_MIN_INGRESS;
	prio_proto = (prio << 16) | (__u32)htons(ETH_P_ALL);
	tcm->tcm_info    = prio_proto;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*tcm));

	off = nla_put_str(buf, off, sizeof(buf), TCA_KIND, "matchall");
	if (!off) return -EIO;

	opts_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TCA_OPTIONS);
	if (!off) return -EIO;

	act_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TCA_MATCHALL_ACT);
	if (!off) return -EIO;

	/* Action slot [1]: reference shared gact by index.
	 * A non-zero gact.index tells tcf_action_init_1() to look up the
	 * existing action rather than allocate a new one. */
	slot_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), 1);
	if (!off) return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), TCA_ACT_KIND, "gact");
	if (!off) return -EIO;

	{
		size_t gopts_off = off;
		off = nla_nest_start(buf, off, sizeof(buf), TCA_ACT_OPTIONS);
		if (!off) return -EIO;

		memset(&gact, 0, sizeof(gact));
		gact.index  = shared_act_idx;
		/* verdict left 0 (TC_ACT_OK) -- the existing shared action's
		 * verdict governs; this field is ignored when binding. */
		gact.action = TC_ACT_OK;
		off = nla_put(buf, off, sizeof(buf), 1 /* TCA_GACT_PARMS */,
			      &gact, sizeof(gact));
		if (!off) return -EIO;
		nla_nest_end(buf, gopts_off, off);
	}

	nla_nest_end(buf, slot_off, off);
	nla_nest_end(buf, act_off,  off);
	nla_nest_end(buf, opts_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * RTM_DELTFILTER on the ingress parent at prio slot.
 */
static int build_deltfilter(struct nl_ctx *ctx, int ifindex, __u32 prio)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct tcmsg *tcm;
	size_t off;
	__u32 prio_proto = (prio << 16) | (__u32)htons(ETH_P_ALL);

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELTFILTER;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	tcm = (struct tcmsg *)NLMSG_DATA(nlh);
	tcm->tcm_family  = AF_UNSPEC;
	tcm->tcm_ifindex = ifindex;
	tcm->tcm_handle  = 0;
	tcm->tcm_parent  = 0xFFFF0000U | TC_H_MIN_INGRESS;
	tcm->tcm_info    = prio_proto;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*tcm));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/* -------- per-ns body -------- */

struct tcsa_ctx {
	struct childdata *child;
};

static int tcsa_in_ns(void *arg)
{
	struct tcsa_ctx *cctx = arg;
	struct childdata *child = cctx->child;
	struct nl_ctx nl = { .fd = -1 };
	struct nl_open_opts nl_opts = {
		.proto       = NETLINK_ROUTE,
		.recv_timeo_s = 1,
		.caller_op   = CHILD_OP_TC_STANDALONE_ACTION,
	};
	char a_name[IFNAMSIZ];
	char b_name[IFNAMSIZ];
	int a_idx = 0, b_idx = 0;
	bool pair_added      = false;
	bool clsact_added    = false;
	bool action_created  = false;
	bool filter_added    = false;
	int udp              = -1;
	__u32 prio;
	int rc;
	unsigned long direct_calls = 0;

	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unsupported_rtnl() || ns_unsupported_veth() ||
	    ns_unsupported_clsact() || ns_unsupported_matchall() ||
	    ns_unsupported_action())
		goto out;

	if (nl_open(&nl, &nl_opts) < 0) {
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT)
			mark_ns_unsupported_rtnl();
		__atomic_add_fetch(&shm->stats.tc_standalone_action.setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	if (!modprobe_tried_ingress()) {
		mark_modprobe_tried_ingress();
		try_modprobe("sch_ingress");
	}
	if (!modprobe_tried_matchall()) {
		mark_modprobe_tried_matchall();
		try_modprobe("cls_matchall");
	}
	if (!modprobe_tried_act_gact()) {
		mark_modprobe_tried_act_gact();
		try_modprobe("act_gact");
	}

	if (!lo_brought_up()) {
		rtnl_bring_lo_up(&nl);
		mark_lo_brought_up();
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	/* Random per-iter names to avoid collision between concurrent
	 * grandchildren or our own teardown races. */
	snprintf(a_name, sizeof(a_name), "tcsaa%u",
		 (unsigned int)(rand32() & 0xffffu));
	snprintf(b_name, sizeof(b_name), "tcsab%u",
		 (unsigned int)(rand32() & 0xffffu));

	rc = build_veth_pair(&nl, a_name, b_name);
	if (rc != 0) {
		if (is_unsupported_err(rc))
			mark_ns_unsupported_veth();
		__atomic_add_fetch(&shm->stats.tc_standalone_action.setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	pair_added = true;

	a_idx = (int)if_nametoindex(a_name);
	b_idx = (int)if_nametoindex(b_name);
	if (a_idx <= 0 || b_idx <= 0)
		goto out;

	name_pool_record(NAME_KIND_NETDEV, a_name, strlen(a_name));

	(void)rtnl_setlink_up(&nl, a_idx);
	(void)rtnl_setlink_up(&nl, b_idx);

	/* Step 3: clsact qdisc on A. */
	rc = build_clsact(&nl, a_idx);
	if (rc != 0) {
		if (is_unsupported_err(rc))
			mark_ns_unsupported_clsact();
		__atomic_add_fetch(&shm->stats.tc_standalone_action.qdisc_fail,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	clsact_added = true;
	__atomic_add_fetch(&shm->stats.tc_standalone_action.qdisc_ok,
			   1, __ATOMIC_RELAXED);

	/* Step 4: create shared gact with TC_ACT_GOTO_CHAIN|1 at fixed
	 * index TCSA_ACTION_IDX.  This allocates the action in the netns
	 * gact IDR and resolves a->goto_chain to the chain-1 pointer. */
	rc = build_action_msg(&nl, RTM_NEWACTION,
			      NLM_F_CREATE | NLM_F_EXCL,
			      TCSA_ACTION_IDX,
			      (int)(TC_ACT_GOTO_CHAIN |
				    (TCSA_GOTO_CHAIN &
				     ((1U << TC_ACT_EXT_SHIFT) - 1U))));
	if (rc != 0) {
		if (is_unsupported_err(rc) || rc == -ENOSYS)
			mark_ns_unsupported_action();
		__atomic_add_fetch(&shm->stats.tc_standalone_action.action_create_fail,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	action_created = true;
	__atomic_add_fetch(&shm->stats.tc_standalone_action.action_create_ok,
			   1, __ATOMIC_RELAXED);

	/* Step 5: matchall filter on ingress that binds to the shared action
	 * by index.  Any packet hitting clsact ingress will execute the shared
	 * gact whose verdict is the GOTO_CHAIN target currently set. */
	prio = (rand32() & 0x1fU) + 1U;
	rc = build_matchall_shared_action(&nl, a_idx, prio, TCSA_ACTION_IDX);
	if (rc != 0) {
		if (is_unsupported_err(rc))
			mark_ns_unsupported_matchall();
		__atomic_add_fetch(&shm->stats.tc_standalone_action.filter_fail,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	filter_added = true;
	__atomic_add_fetch(&shm->stats.tc_standalone_action.filter_ok,
			   1, __ATOMIC_RELAXED);

	/* Step 6 + 7: UDP burst with mid-burst RTM_NEWACTION + NLM_F_REPLACE.
	 * Packets cross tcf_action_exec() which reads a->goto_chain; the
	 * replace concurrently calls tcf_action_set_ctrlact() which writes
	 * a->goto_chain under RCU -- exactly the TOCTOU window upstream
	 * upstream: f60b396ee174 addressed. */
	if (!ns_unsupported_inet()) {
		struct sockaddr_in dst;
		struct timespec t0;
		unsigned int iters, i;
		bool flip = false;

		udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		direct_calls += 1;
		if (udp < 0) {
			if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
				mark_ns_unsupported_inet();
			goto out;
		}
		(void)setsockopt(udp, SOL_SOCKET, SO_BINDTODEVICE,
				 a_name, strlen(a_name) + 1);
		direct_calls += 1;

		memset(&dst, 0, sizeof(dst));
		dst.sin_family      = AF_INET;
		dst.sin_port        = htons(TCSA_INNER_PORT);
		dst.sin_addr.s_addr = htonl(0x7f000001U);

		(void)clock_gettime(CLOCK_MONOTONIC, &t0);
		iters = BUDGETED(CHILD_OP_TC_STANDALONE_ACTION,
				 JITTER_RANGE(TCSA_PACKET_BASE));
		if (iters < TCSA_PACKET_FLOOR)
			iters = TCSA_PACKET_FLOOR;
		if (iters > TCSA_PACKET_CAP)
			iters = TCSA_PACKET_CAP;

		if (valid_op)
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);

		/* Replace points: at 1/3 and 2/3 of the burst so the race
		 * window straddles the send loop at least twice. */
		const unsigned int replace_at_a = iters / 3;
		const unsigned int replace_at_b = (iters * 2) / 3;

		for (i = 0; i < iters; i++) {
			unsigned char payload[64];
			ssize_t n;

			if (ns_since(&t0) >= STORM_BUDGET_NS)
				break;

			generate_rand_bytes(payload, sizeof(payload));
			n = sendto(udp, payload, sizeof(payload),
				   MSG_DONTWAIT,
				   (struct sockaddr *)&dst, sizeof(dst));
			direct_calls += 1;
			if (n > 0)
				__atomic_add_fetch(
					&shm->stats.tc_standalone_action.packet_sent_ok,
					1, __ATOMIC_RELAXED);

			/* Mid-burst RTM_NEWACTION + NLM_F_REPLACE: flip the
			 * ctrlact on the shared action between TC_ACT_OK and
			 * TC_ACT_GOTO_CHAIN|1.  Each call reaches
			 * tcf_action_set_ctrlact() under RCU while concurrent
			 * tcf_action_exec() readers may hold an stale
			 * a->goto_chain pointer -- the race targeted by the
			 * upstream fix. */
			if (i == replace_at_a || i == replace_at_b) {
				int new_verdict;

				flip = !flip;
				if (flip)
					new_verdict = TC_ACT_OK;
				else
					new_verdict =
						(int)(TC_ACT_GOTO_CHAIN |
						      (TCSA_GOTO_CHAIN &
						       ((1U << TC_ACT_EXT_SHIFT) - 1U)));

				rc = build_action_msg(&nl, RTM_NEWACTION,
						      NLM_F_REPLACE,
						      TCSA_ACTION_IDX,
						      new_verdict);
				if (rc == 0) {
					__atomic_add_fetch(
						&shm->stats.tc_standalone_action.action_replace_ok,
						1, __ATOMIC_RELAXED);
					/* Concurrent replace completed while
					 * traffic was in flight. */
					__atomic_add_fetch(
						&shm->stats.tc_standalone_action.tc_action_replace_concurrent,
						1, __ATOMIC_RELAXED);
				}
			}
		}
	}

out:
	if (udp >= 0) {
		close(udp);
		direct_calls += 1;
	}
	if (nl.fd >= 0) {
		/* Delete the matchall filter first so the action refcount
		 * drops; then delete the shared action itself.  dellink
		 * on the veth pair cascades clsact and any remaining filters
		 * but does NOT automatically delete standalone actions -- those
		 * live in a netns-wide IDR and must be explicitly freed. */
		if (filter_added && a_idx > 0)
			(void)build_deltfilter(&nl, a_idx, prio);

		if (action_created) {
			rc = build_action_msg(&nl, RTM_DELACTION,
					      0 /* no extra flags */,
					      TCSA_ACTION_IDX,
					      TC_ACT_OK /* ignored */);
			if (rc == 0)
				__atomic_add_fetch(
					&shm->stats.tc_standalone_action.action_del_ok,
					1, __ATOMIC_RELAXED);
		}

		if (pair_added && a_idx > 0) {
			if (rtnl_dellink(&nl, a_idx) == 0)
				__atomic_add_fetch(
					&shm->stats.tc_standalone_action.link_del_ok,
					1, __ATOMIC_RELAXED);
		}
		(void)clsact_added;	/* cascades with dellink */
		nl_close(&nl);
	}

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);
	return 0;
}

bool tc_standalone_action(struct childdata *child)
{
	struct tcsa_ctx cctx = { .child = child };
	int rc;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.tc_standalone_action.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_setup_failed)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, tcsa_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_setup_failed = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.tc_standalone_action.setup_failed,
				   1, __ATOMIC_RELAXED);
		warn_once_setup_failed(EPERM);
		return true;
	}
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.tc_standalone_action.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
