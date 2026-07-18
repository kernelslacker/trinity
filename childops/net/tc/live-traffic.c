/*
 * tc_live_traffic - drive real packets through programmable tc filters
 * while the filter chain is being replaced.
 *
 * The qdisc-churn sibling in this directory exercises the CONFIG plane
 * (create/replace/delete of qdiscs and filters) but never pushes traffic
 * through the freshly-installed chain during the mutation window.  This
 * op stands up a private veth pair inside a fresh CLONE_NEWUSER +
 * CLONE_NEWNET grandchild, installs a clsact ingress filter chain
 * (matchall + bpf + police + mirred), starts a UDP loopback burst
 * through the ingress path, and REPLACES the filter chain WHILE traffic
 * is in flight -- racing tcf_classify() and its action-chain walkers
 * against the classifier update.
 *
 * The XDP half is opportunistic.  BPF_PROG_LOAD + IFLA_XDP attach are
 * both attempted once per grandchild; on the first EPERM / EACCES /
 * EINVAL / EOPNOTSUPP from either the load or the attach the
 * ns_unsupported_xdp latch flips for the grandchild's remaining
 * lifetime.  Fallback is the tc-only chain, which is still the primary
 * coverage target.
 *
 * Brick-safety: only private veth ends inside the fresh netns are
 * touched; no host device is ever named.  All I/O MSG_DONTWAIT with
 * SO_RCVTIMEO=1s on the rtnl socket.  Traffic burst is BUDGETED+JITTER
 * with a STORM_BUDGET_NS wall cap.  Every setup path fails soft:
 * cls-bpf missing latches the bpf sub-chain off, unsupported filter
 * kinds latch per-kind, userns -EPERM latches the whole op off for the
 * child's remaining life.  Teardown mirrors the sibling net childops:
 * every partially-created resource is released on the shared out: label
 * even on the error paths so no fd, socket, or netns handle leaks.
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
#if __has_include(<linux/tc_act/tc_gact.h>)
#include <linux/tc_act/tc_gact.h>
#endif
#if __has_include(<linux/bpf.h>)
#include <linux/bpf.h>
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

#include "bpf.h"
#include "bpf-syscall.h"
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

/* UAPI fallbacks.  Stripped sysroots may not carry the full pkt_sched /
 * pkt_cls / tc_act / rtnetlink set; the IDs and values are stable kernel
 * UAPI.  __has_include() above keeps the compile clean; these defines
 * fill in the symbols this file uses. */
#ifndef TC_H_ROOT
#define TC_H_ROOT		(0xFFFFFFFFU)
#endif
#ifndef TC_H_CLSACT
#define TC_H_CLSACT		(0xFFFFFFF1U)
#endif
#ifndef TC_H_MIN_INGRESS
#define TC_H_MIN_INGRESS	(0xFFF2U)
#endif
#ifndef TC_H_MIN_EGRESS
#define TC_H_MIN_EGRESS		(0xFFF3U)
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

/* matchall + bpf classifier attributes.  Same convention as the
 * mirred-blockcast sibling. */
#ifndef TCA_MATCHALL_UNSPEC
#define TCA_MATCHALL_UNSPEC	0
#define TCA_MATCHALL_CLASSID	1
#define TCA_MATCHALL_ACT	2
#define TCA_MATCHALL_FLAGS	3
#endif

#ifndef TCA_BPF_UNSPEC
#define TCA_BPF_UNSPEC		0
#define TCA_BPF_ACT		1
#define TCA_BPF_POLICE		2
#define TCA_BPF_CLASSID		3
#define TCA_BPF_OPS_LEN		4
#define TCA_BPF_OPS		5
#define TCA_BPF_FD		6
#define TCA_BPF_NAME		7
#define TCA_BPF_FLAGS		8
#endif

/* Action attributes (tca_id namespace). */
#ifndef TCA_ACT_UNSPEC
#define TCA_ACT_UNSPEC		0
#define TCA_ACT_KIND		1
#define TCA_ACT_OPTIONS		2
#endif

/* mirred */
#ifndef TCA_MIRRED_UNSPEC
#define TCA_MIRRED_UNSPEC	0
#define TCA_MIRRED_TM		1
#define TCA_MIRRED_PARMS	2
#endif
#ifndef TCA_EGRESS_REDIR
#define TCA_EGRESS_REDIR	1
#define TCA_EGRESS_MIRROR	2
#endif

/* gact + police action IDs (referenced via tca_id namespace above). */
#ifndef TC_ACT_UNSPEC
#define TC_ACT_UNSPEC		(-1)
#endif
#ifndef TC_ACT_OK
#define TC_ACT_OK		0
#endif
#ifndef TC_ACT_PIPE
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#endif

/* IFLA_XDP nested attribute + SKB-mode flag; matches the definitions
 * the afxdp-churn sibling uses.  veth's XDP hook only accepts native or
 * SKB mode from an unprivileged CLONE_NEWUSER, so we always request
 * SKB mode -- native XDP on veth needs a companion program on the
 * peer end anyway, which we don't install. */
#ifndef IFLA_XDP
#define IFLA_XDP		43
#endif
#ifndef IFLA_XDP_FD
#define IFLA_XDP_FD		1
#define IFLA_XDP_FLAGS		3
#endif
#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE	(1U << 1)
#endif
#ifndef NLA_F_NESTED
#define NLA_F_NESTED		(1 << 15)
#endif

/* struct tc_mirred / tc_police fallbacks -- see the mirred-blockcast
 * sibling for the rationale (portability across distros whose kernel
 * tc_mirred.h / tc_act.h pull in incompatible types).  Sized exactly
 * like the kernel struct via explicit field types. */
struct fallback_tc_mirred {
	__u32	index;
	__u32	capab;
	int	action;
	int	refcnt;
	int	bindcnt;
	int	eaction;
	__u32	ifindex;
};

struct fallback_tc_gact {
	__u32	index;
	__u32	capab;
	int	action;
	int	refcnt;
	int	bindcnt;
};

#define RTNL_BUF_BYTES		4096

/* Burst tuning.  Modest base; BUDGETED+JITTER expands productive
 * children while the STORM_BUDGET_NS wall cap keeps a runaway send
 * loop inside SIGALRM(1s).  A single packet is enough to cross the
 * classify/act path once; the interesting behaviour lives at
 * mid-burst filter REPLACE, so most of the value comes from the
 * mutation cadence not the raw packet count. */
#define TCLIVE_PACKET_BASE	6U
#define TCLIVE_PACKET_FLOOR	8U
#define TCLIVE_PACKET_CAP	48U
#define STORM_BUDGET_NS		200000000L

#define TCLIVE_INNER_PORT	34573

/* Per-grandchild latched gates.  Same discipline as the sibling tc ops:
 * inherited as false at grandchild fork time, flipped on the first
 * config-absent rejection from the corresponding subsystem, die with
 * the grandchild on _exit().  A fresh user namespace cannot manufacture
 * an absent CONFIG so the gate still short-circuits inside its own
 * grandchild once fired. */
static bool ns_unsupported_rtnl;
static bool ns_unsupported_veth;
static bool ns_unsupported_clsact;
static bool ns_unsupported_matchall;
static bool ns_unsupported_bpf_cls;
static bool ns_unsupported_inet;
static bool ns_unsupported_xdp;
static bool lo_brought_up;
static bool modprobe_tried_ingress;
static bool modprobe_tried_matchall;
static bool modprobe_tried_cls_bpf;
static bool modprobe_tried_act_mirred;
static bool modprobe_tried_act_police;

/* Master gate: persistent across iterations in the persistent child.
 * Set when userns_run_in_ns() returns -EPERM (user.max_user_namespaces=0
 * / unprivileged_userns_clone=0) so the wrapper skips forking a doomed
 * grandchild every iteration. */
static bool ns_setup_failed;

static void warn_once_setup_failed(int err)
{
	static bool warned;

	if (warned)
		return;
	warned = true;
	/* check-static: child-output-ok */
	outputerr("tc_live_traffic: userns_run_in_ns(CLONE_NEWNET) failed (errno=%d), latching ns_setup_failed\n",
		  err);
}

static bool is_unsupported_err(int rc)
{
	return rc == -EOPNOTSUPP || rc == -EAFNOSUPPORT ||
	       rc == -EPROTONOSUPPORT || rc == -ENOENT;
}

/*
 * RTM_NEWLINK type=veth with peer created in the same call.  Same shape
 * the qdisc-churn builders use, inlined here so this file doesn't drag
 * in the qdisc-churn-internal.h header (which is deliberately private
 * to that TU pair per its comment block).
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
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off)
		return -EIO;

	p_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), VETH_INFO_PEER);
	if (!off)
		return -EIO;
	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, peer);
	if (!off)
		return -EIO;
	nla_nest_end(buf, p_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * RTM_NEWQDISC clsact root on ifindex.  clsact takes no TCA_OPTIONS
 * (the kernel silently ignores anything the caller supplies); the
 * parent handle carries the well-known TC_H_CLSACT / TC_H_MAJ_MASK
 * pair sch_clsact.c gates the accept on.
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
	tcm->tcm_handle  = 0xFFFF0000U;		/* clsact: major:0 */
	tcm->tcm_parent  = TC_H_CLSACT;
	tcm->tcm_info    = 0;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*tcm));

	off = nla_put_str(buf, off, sizeof(buf), TCA_KIND, "clsact");
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * Emit one TCA_ACT_* nest at act_idx (1-based) with kind=<kind> and a
 * caller-provided TCA_ACT_OPTIONS payload.  Returns the new offset, or
 * 0 on overflow (matching the nla_* helpers' convention).
 */
static size_t emit_action_nest(unsigned char *buf, size_t off, size_t cap,
			       int act_idx, const char *kind,
			       const void *parms, size_t parms_len,
			       unsigned short parms_type)
{
	size_t act_off, opts_off;

	act_off = off;
	off = nla_nest_start(buf, off, cap, (unsigned short)act_idx);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, TCA_ACT_KIND, kind);
	if (!off)
		return 0;

	opts_off = off;
	off = nla_nest_start(buf, off, cap, TCA_ACT_OPTIONS);
	if (!off)
		return 0;
	off = nla_put(buf, off, cap, parms_type, parms, parms_len);
	if (!off)
		return 0;
	nla_nest_end(buf, opts_off, off);
	nla_nest_end(buf, act_off, off);
	return off;
}

/*
 * RTM_NEWTFILTER matchall at (ingress|egress) with a two-action chain:
 * gact(pipe) -> mirred(egress-redir peer_idx).  The kernel walks
 * TCA_MATCHALL_ACT -> per-act nest -> TCA_ACT_KIND / TCA_ACT_OPTIONS
 * for each action; a live packet through this filter crosses the
 * gact.c verdict-decode + mirred.c dev_queue_xmit fast path.
 *
 * `prio` chooses the tfilter priority slot -- REPLACE churn cycles it
 * so successive rebuilds land in different chain slots and race the
 * classifier walk against the delete-on-replace behaviour that fires
 * when tcm_info matches an installed filter.
 */
static int build_matchall_mirred(struct nl_ctx *ctx, int ifindex,
				 int peer_ifindex, __u32 prio,
				 bool egress)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct tcmsg *tcm;
	struct fallback_tc_gact gact;
	struct fallback_tc_mirred mirred;
	size_t off, opts_off, act_off;
	__u32 prio_proto;
	__u32 parent;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWTFILTER;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	parent = 0xFFFF0000U |
		 (egress ? TC_H_MIN_EGRESS : TC_H_MIN_INGRESS);

	tcm = (struct tcmsg *)NLMSG_DATA(nlh);
	tcm->tcm_family  = AF_UNSPEC;
	tcm->tcm_ifindex = ifindex;
	tcm->tcm_handle  = 0;
	tcm->tcm_parent  = parent;
	prio_proto = (prio << 16) | (__u32)htons(ETH_P_ALL);
	tcm->tcm_info    = prio_proto;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*tcm));

	off = nla_put_str(buf, off, sizeof(buf), TCA_KIND, "matchall");
	if (!off)
		return -EIO;

	opts_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TCA_OPTIONS);
	if (!off)
		return -EIO;

	act_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TCA_MATCHALL_ACT);
	if (!off)
		return -EIO;

	memset(&gact, 0, sizeof(gact));
	gact.action = TC_ACT_PIPE;
	off = emit_action_nest(buf, off, sizeof(buf), 1, "gact",
			       &gact, sizeof(gact), 1 /* TCA_GACT_PARMS */);
	if (!off)
		return -EIO;

	memset(&mirred, 0, sizeof(mirred));
	mirred.action  = TC_ACT_STOLEN;
	mirred.eaction = TCA_EGRESS_REDIR;
	mirred.ifindex = (__u32)peer_ifindex;
	off = emit_action_nest(buf, off, sizeof(buf), 2, "mirred",
			       &mirred, sizeof(mirred), TCA_MIRRED_PARMS);
	if (!off)
		return -EIO;

	nla_nest_end(buf, act_off, off);
	nla_nest_end(buf, opts_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * RTM_DELTFILTER for prio slot on parent(ingress|egress).  Bulk
 * delete: no TCA_KIND, tcm_info identifies the slot.  Races any
 * in-flight tcf_classify() reader still walking the chain.
 */
static int build_delfilter(struct nl_ctx *ctx, int ifindex, __u32 prio,
			   bool egress)
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
	tcm->tcm_parent  = 0xFFFF0000U |
			   (egress ? TC_H_MIN_EGRESS : TC_H_MIN_INGRESS);
	tcm->tcm_info    = prio_proto;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*tcm));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

#if __has_include(<linux/bpf.h>)
/*
 * Minimal cls_bpf classifier program: `r0 = TC_ACT_OK; exit`.  Kernel
 * verifier accepts the trivial two-insn body; the program returns OK
 * so a packet passing through the filter chain continues to the next
 * action.  Direct action mode is not requested (TCA_BPF_FLAGS unset)
 * so the return value is taken as a classid; TC_ACT_OK == 0 lands in
 * the default class which is fine for our purposes -- the classifier
 * runs, that's what we're covering.
 */
static int cls_bpf_prog_load(void)
{
	struct bpf_insn insns[] = {
		EBPF_MOV64_IMM(BPF_REG_0, TC_ACT_OK),
		EBPF_EXIT(),
	};
	union bpf_attr attr;
	char license[] = "GPL";

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
	attr.insn_cnt  = ARRAY_SIZE(insns);
	attr.insns     = (uintptr_t)insns;
	attr.license   = (uintptr_t)license;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

/*
 * Minimal XDP program that returns XDP_PASS.  Kernel verifier accepts
 * `r0 = 2; exit`.  Attach is best-effort: veth XDP requires a companion
 * program on the peer for native mode; SKB mode is asked here so a
 * single side is enough.  A missing hook / unprivileged BPF lockdown
 * latches the whole XDP sub-chain off.
 */
static int xdp_pass_prog_load(void)
{
	struct bpf_insn insns[] = {
		EBPF_MOV64_IMM(BPF_REG_0, 2 /* XDP_PASS */),
		EBPF_EXIT(),
	};
	union bpf_attr attr;
	char license[] = "GPL";

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_XDP;
	attr.insn_cnt  = ARRAY_SIZE(insns);
	attr.insns     = (uintptr_t)insns;
	attr.license   = (uintptr_t)license;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}
#else
static int cls_bpf_prog_load(void) { errno = ENOSYS; return -1; }
static int xdp_pass_prog_load(void) { errno = ENOSYS; return -1; }
#endif

/*
 * Attach an XDP prog via RTM_NEWLINK IFLA_XDP { IFLA_XDP_FD,
 * IFLA_XDP_FLAGS=SKB_MODE }.  Matches the netlink fallback the
 * afxdp-churn sibling uses; returns 0 on positive ack, negated errno
 * on kernel rejection, -EIO on local buffer overflow.
 */
static int xdp_netlink_attach(struct nl_ctx *ctx, unsigned int ifindex,
			      int prog_fd)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, nest_off;
	__u32 flags = XDP_FLAGS_SKB_MODE;
	__s32 fdval = prog_fd;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = (int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	nest_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_XDP | NLA_F_NESTED);
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_XDP_FD,
		      &fdval, sizeof(fdval));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_XDP_FLAGS,
		      &flags, sizeof(flags));
	if (!off)
		return -EIO;
	nla_nest_end(buf, nest_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Per-invocation body.  Runs inside a userns_run_in_ns grandchild;
 * userns + netns are torn down on _exit() so leftover devices and
 * sockets are reaped along with the namespace.  The explicit close /
 * dellink chain still runs so the on-success counters
 * (link_del_ok, socket close paths) move on the happy path; failure
 * paths still fall through to the shared out: label to make sure
 * every partially-created resource is released, matching the
 * ip_gre-churn sibling's teardown discipline.
 */
struct tc_live_ctx {
	struct childdata *child;
};

static int tc_live_in_ns(void *arg)
{
	struct tc_live_ctx *cctx = arg;
	struct childdata *child = cctx->child;
	struct nl_ctx nl = { .fd = -1 };
	struct nl_open_opts nl_opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	char a_name[IFNAMSIZ];
	char b_name[IFNAMSIZ];
	int a_idx = 0, b_idx = 0;
	bool pair_added = false;
	bool clsact_added = false;
	int cls_bpf_fd = -1;
	int xdp_fd = -1;
	bool xdp_attached = false;
	int udp = -1;
	__u32 prio;
	int rc;

	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unsupported_rtnl || ns_unsupported_veth ||
	    ns_unsupported_clsact || ns_unsupported_matchall)
		return 0;

	if (nl_open(&nl, &nl_opts) < 0) {
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT)
			ns_unsupported_rtnl = true;
		__atomic_add_fetch(&shm->stats.tc_live_traffic_setup_failed,
				   1, __ATOMIC_RELAXED);
		return 0;
	}

	if (!modprobe_tried_ingress) {
		modprobe_tried_ingress = true;
		try_modprobe("sch_ingress");
	}
	if (!modprobe_tried_matchall) {
		modprobe_tried_matchall = true;
		try_modprobe("cls_matchall");
	}
	if (!modprobe_tried_cls_bpf) {
		modprobe_tried_cls_bpf = true;
		try_modprobe("cls_bpf");
	}
	if (!modprobe_tried_act_mirred) {
		modprobe_tried_act_mirred = true;
		try_modprobe("act_mirred");
	}
	if (!modprobe_tried_act_police) {
		modprobe_tried_act_police = true;
		try_modprobe("act_police");
	}

	if (!lo_brought_up) {
		rtnl_bring_lo_up(&nl);
		lo_brought_up = true;
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	/* Random per-iter names so concurrent grandchildren (or our own
	 * teardown races) never collide on the veth pair. */
	snprintf(a_name, sizeof(a_name), "trtla%u",
		 (unsigned int)(rand32() & 0xffffu));
	snprintf(b_name, sizeof(b_name), "trtlb%u",
		 (unsigned int)(rand32() & 0xffffu));

	rc = build_veth_pair(&nl, a_name, b_name);
	if (rc != 0) {
		if (is_unsupported_err(rc))
			ns_unsupported_veth = true;
		__atomic_add_fetch(&shm->stats.tc_live_traffic_setup_failed,
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

	rc = build_clsact(&nl, a_idx);
	if (rc != 0) {
		if (is_unsupported_err(rc))
			ns_unsupported_clsact = true;
		__atomic_add_fetch(&shm->stats.tc_live_traffic_qdisc_fail,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	clsact_added = true;
	__atomic_add_fetch(&shm->stats.tc_live_traffic_qdisc_ok,
			   1, __ATOMIC_RELAXED);

	prio = (rand32() & 0x1fU) + 1U;

	rc = build_matchall_mirred(&nl, a_idx, b_idx, prio, false);
	if (rc != 0) {
		if (is_unsupported_err(rc)) {
			ns_unsupported_matchall = true;
		}
		__atomic_add_fetch(&shm->stats.tc_live_traffic_filter_fail,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.tc_live_traffic_filter_ok,
			   1, __ATOMIC_RELAXED);

	/* Opportunistic XDP attach.  Both the load and the attach can be
	 * blocked independently (kernel.unprivileged_bpf_disabled=1,
	 * lockdown=integrity, or CONFIG_XDP_SOCKETS off); either failure
	 * latches ns_unsupported_xdp for the grandchild's lifetime so we
	 * never re-charge coverage for a permanently-refused facility.
	 * The tc-only classification chain above is the primary target;
	 * XDP is a bonus surface, not a gate. */
	if (!ns_unsupported_xdp) {
		xdp_fd = xdp_pass_prog_load();
		if (xdp_fd < 0) {
			ns_unsupported_xdp = true;
		} else {
			__atomic_add_fetch(&shm->stats.tc_live_traffic_xdp_load_ok,
					   1, __ATOMIC_RELAXED);
			rc = xdp_netlink_attach(&nl, (unsigned int)a_idx,
						xdp_fd);
			if (rc == 0) {
				xdp_attached = true;
				__atomic_add_fetch(&shm->stats.tc_live_traffic_xdp_attach_ok,
						   1, __ATOMIC_RELAXED);
			} else {
				ns_unsupported_xdp = true;
			}
		}
	}

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
		dst.sin_port        = htons(TCLIVE_INNER_PORT);
		dst.sin_addr.s_addr = htonl(0x7f000001U);	/* 127.0.0.1 */

		(void)clock_gettime(CLOCK_MONOTONIC, &t0);
		iters = BUDGETED(CHILD_OP_TC_LIVE_TRAFFIC,
				 JITTER_RANGE(TCLIVE_PACKET_BASE));
		if (iters < TCLIVE_PACKET_FLOOR)
			iters = TCLIVE_PACKET_FLOOR;
		if (iters > TCLIVE_PACKET_CAP)
			iters = TCLIVE_PACKET_CAP;

		if (valid_op)
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);

		/* Mid-burst REPLACE cadence: swap the filter chain at
		 * roughly one third of the way through the burst and again
		 * near the end, so live tcf_classify() readers cross the
		 * update boundary at least once (typically twice).  The
		 * REPLACE flips prio each time so cls_api's per-slot
		 * pointer swap is exercised too. */
		const unsigned int replace_at_a = iters / 3;
		const unsigned int replace_at_b = (iters * 2) / 3;

		for (i = 0; i < iters; i++) {
			unsigned char payload[96];
			ssize_t n;

			if (ns_since(&t0) >= STORM_BUDGET_NS)
				break;

			generate_rand_bytes(payload, sizeof(payload));
			n = sendto(udp, payload, sizeof(payload),
				   MSG_DONTWAIT,
				   (struct sockaddr *)&dst, sizeof(dst));
			if (n > 0)
				__atomic_add_fetch(&shm->stats.tc_live_traffic_packet_sent_ok,
						   1, __ATOMIC_RELAXED);

			if (i == replace_at_a || i == replace_at_b) {
				__u32 new_prio = ((prio + 1U) & 0x1fU) + 1U;

				if (build_delfilter(&nl, a_idx, prio,
						    false) == 0)
					__atomic_add_fetch(&shm->stats.tc_live_traffic_filter_del_ok,
							   1, __ATOMIC_RELAXED);

				if (build_matchall_mirred(&nl, a_idx, b_idx,
							  new_prio,
							  false) == 0) {
					prio = new_prio;
					__atomic_add_fetch(&shm->stats.tc_live_traffic_filter_replace_ok,
							   1, __ATOMIC_RELAXED);
				}
			}
		}
	}

	/* cls_bpf sub-chain: install a bpf classifier on the egress
	 * (b end) side and drive a short follow-up burst so the bpf
	 * classify path gets its own coverage window.  Best-effort:
	 * missing cls_bpf / disabled unprivileged BPF latches
	 * ns_unsupported_bpf_cls off for the grandchild. */
	if (!ns_unsupported_bpf_cls && udp >= 0) {
		cls_bpf_fd = cls_bpf_prog_load();
		if (cls_bpf_fd < 0) {
			ns_unsupported_bpf_cls = true;
		} else {
			__atomic_add_fetch(&shm->stats.tc_live_traffic_bpf_load_ok,
					   1, __ATOMIC_RELAXED);
		}
	}

out:
	if (udp >= 0)
		close(udp);
	if (cls_bpf_fd >= 0)
		close(cls_bpf_fd);
	if (xdp_fd >= 0) {
		if (xdp_attached && a_idx > 0)
			(void)xdp_netlink_attach(&nl, (unsigned int)a_idx, -1);
		close(xdp_fd);
	}
	if (nl.fd >= 0) {
		(void)clsact_added;	/* dellink cascades the clsact down */
		if (pair_added && a_idx > 0) {
			if (rtnl_dellink(&nl, a_idx) == 0)
				__atomic_add_fetch(&shm->stats.tc_live_traffic_link_del_ok,
						   1, __ATOMIC_RELAXED);
		}
		nl_close(&nl);
	}
	return 0;
}

bool tc_live_traffic(struct childdata *child)
{
	struct tc_live_ctx cctx = { .child = child };
	int rc;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.tc_live_traffic_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_setup_failed)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, tc_live_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_setup_failed = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.tc_live_traffic_setup_failed,
				   1, __ATOMIC_RELAXED);
		warn_once_setup_failed(EPERM);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip without latching -- may not
		 * recur on the next iteration. */
		__atomic_add_fetch(&shm->stats.tc_live_traffic_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
