/*
 * veth_asymmetric_xdp - drive the veth-family rx-side txq lookup on an
 * asymmetric pair under XDP.  Targets the shape where the receiving side has
 * fewer rx queues than the sending side has tx queues (or vice-versa) and
 * skb_get_tx_queue() / hash-modulo selection walks past the per-queue array
 * -- veth_xdp_rcv_one() and adjacent asymmetric-queue accounting.  Isolated
 * syscall fuzz never assembles the coherent triple this op needs: pair created
 * with explicit asymmetric IFLA_NUM_{TX,RX}_QUEUES, XDP attached on one half
 * only, live raw-packet traffic through the pair.
 *
 * Four pair kinds rotate (each latched independently): veth, vxcan (same
 * nested-peer shape), ipvlan and macvlan slaves on a dummy parent (XDP on the
 * slave, raw traffic on the parent).  Each iteration runs inside a transient
 * userns_run_in_ns grandchild (identity userns + CLONE_NEWNET, _exit reaps),
 * loads a 2-insn "return XDP_REDIRECT" prog in SKB mode, blasts a small
 * AF_PACKET/SOCK_RAW burst, and RTM_DELLINK-tears everything down.
 *
 * Brick-safety: all work inside CLONE_NEWNET so the host has nothing to reap;
 * XDP attach in XDP_FLAGS_SKB_MODE only, so no native driver dependency.
 *
 * Latches: userns -EPERM latches the op off for the child's life.  Per-kind
 * ns_unsupported_{veth,vxcan,ipvlan,macvlan} and a separate
 * ns_unsupported_xdp keep the axes independent -- a missing kind doesn't
 * disable XDP, and no XDP doesn't disable the asymmetric-queue exercise.
 *
 * Header-gated by __has_include() on linux/if_link.h + linux/bpf.h.
 */

#if __has_include(<linux/if_link.h>) && __has_include(<linux/bpf.h>)

#include <errno.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "bpf.h"
#include "bpf-syscall.h"
#include "child.h"
#include "childops-netlink.h"
#include "name-pool.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"
#include "utils.h"

#ifndef IFLA_NUM_TX_QUEUES
#define IFLA_NUM_TX_QUEUES		31
#endif
#ifndef IFLA_NUM_RX_QUEUES
#define IFLA_NUM_RX_QUEUES		32
#endif
#ifndef IFLA_VETH_INFO_PEER
#define IFLA_VETH_INFO_PEER		1
#endif
#ifndef IFLA_VXCAN_INFO_PEER
#define IFLA_VXCAN_INFO_PEER		1
#endif
#ifndef IFLA_IPVLAN_MODE
#define IFLA_IPVLAN_MODE		1
#endif
#ifndef IPVLAN_MODE_L3
#define IPVLAN_MODE_L3			1
#endif
#ifndef IFLA_MACVLAN_MODE
#define IFLA_MACVLAN_MODE		1
#endif
#ifndef MACVLAN_MODE_BRIDGE
#define MACVLAN_MODE_BRIDGE		4
#endif
#ifndef IFLA_XDP
#define IFLA_XDP			43
#endif
#ifndef IFLA_XDP_FD
#define IFLA_XDP_FD			1
#define IFLA_XDP_FLAGS			3
#endif
#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE		(1U << 1)
#endif
#ifndef BPF_PROG_TYPE_XDP
#define BPF_PROG_TYPE_XDP		6
#endif

#define VAX_BUF				512
#define VAX_BURST_MIN			4U
#define VAX_BURST_MAX			16U

static const __u8 q_choices[] = { 1, 2, 4, 8 };

enum pair_kind {
	PK_VETH,
	PK_VXCAN,
	PK_IPVLAN,
	PK_MACVLAN,
	PK_NR
};

static const char * const kind_to_str[PK_NR] = {
	[PK_VETH]    = "veth",
	[PK_VXCAN]   = "vxcan",
	[PK_IPVLAN]  = "ipvlan",
	[PK_MACVLAN] = "macvlan",
};

static bool ns_unsupported;
static bool ns_unsupported_veth;
static bool ns_unsupported_vxcan;
static bool ns_unsupported_ipvlan;
static bool ns_unsupported_macvlan;
static bool ns_unsupported_xdp;
static __u32 g_iter;

static bool *const kind_latch[PK_NR] = {
	[PK_VETH]    = &ns_unsupported_veth,
	[PK_VXCAN]   = &ns_unsupported_vxcan,
	[PK_IPVLAN]  = &ns_unsupported_ipvlan,
	[PK_MACVLAN] = &ns_unsupported_macvlan,
};

/* Per-invocation state shared across the extracted phase helpers.
 * prog_fd / raw / ctx.fd default to -1 via the orchestrator's
 * designated initialiser so the teardown helper can close them
 * unconditionally regardless of which earlier phase bailed.  pk is
 * captured up front from pick_kind() before the netlink ctx is opened
 * so the teardown helper can still decide whether b_idx needs an
 * explicit DELLINK (ipvlan/macvlan only).  Name + queue-count fields
 * are filled in by setup; a_idx/b_idx by create_pair; prog_fd by
 * load_xdp; raw by drive_burst. */
struct veth_xdp_iter_ctx {
	struct nl_ctx	ctx;
	struct childdata *child;
	char		a_name[IFNAMSIZ];
	char		b_name[IFNAMSIZ];
	enum pair_kind	pk;
	__u32		ntx;
	__u32		nrx;
	__u32		ptx;
	__u32		prx;
	int		a_idx;
	int		b_idx;
	int		prog_fd;
	int		raw;
};

/*
 * RTM_NEWLINK creating an asymmetric-queue pair of @kind (veth or vxcan;
 * both use INFO_PEER == 1 inside IFLA_INFO_DATA).  Primary side gets
 * (ntx, nrx); peer gets (ptx, prx).  Caller picks values from q_choices[]
 * such that ntx != nrx, ptx != prx, and ntx != ptx so neither end matches
 * the other and the rcv-side hash-mod-queues lookup can wander.
 */
static int vax_create_pair(struct nl_ctx *ctx, const char *kind,
			   const char *a, const char *b,
			   __u32 ntx, __u32 nrx, __u32 ptx, __u32 prx)
{
	unsigned char buf[VAX_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi, *peer_ifi;
	size_t off, li_off, id_off, peer_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, a);
	if (!off) return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_NUM_TX_QUEUES, ntx);
	if (!off) return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_NUM_RX_QUEUES, nrx);
	if (!off) return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, kind);
	if (!off) return -EIO;
	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off) return -EIO;
	peer_off = off;
	/* IFLA_VETH_INFO_PEER == IFLA_VXCAN_INFO_PEER == 1 */
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_VETH_INFO_PEER);
	if (!off) return -EIO;

	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, b);
	if (!off) return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_NUM_TX_QUEUES, ptx);
	if (!off) return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_NUM_RX_QUEUES, prx);
	if (!off) return -EIO;

	nla_nest_end(buf, peer_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWLINK creating a "dummy" netdev to serve as the parent for an
 * ipvlan/macvlan slave.  Single attribute (IFLA_IFNAME) plus the
 * IFLA_LINKINFO { IFLA_INFO_KIND="dummy" } envelope -- no queue counts
 * (parent runs default), no nested IFLA_INFO_DATA.
 */
static int vax_create_dummy(struct nl_ctx *ctx, const char *name)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off) return -EIO;
	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "dummy");
	if (!off) return -EIO;
	nla_nest_end(buf, li_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWLINK creating an @kind slave atop parent ifindex @parent_idx.
 * Carries IFLA_LINK=parent_idx + asymmetric NUM_{TX,RX}_QUEUES on the
 * slave + IFLA_LINKINFO { IFLA_INFO_KIND=kind, IFLA_INFO_DATA {
 * mode_nla_type = mode_val } }.  Used for ipvlan (mode=IFLA_IPVLAN_MODE)
 * and macvlan (mode=IFLA_MACVLAN_MODE); the kernel rejects modes
 * unrelated to @kind, so the caller must pair them correctly.
 */
static int vax_create_slave(struct nl_ctx *ctx, const char *kind,
			    int parent_idx, const char *name,
			    __u16 mode_nla_type, __u32 mode_val,
			    __u32 ntx, __u32 nrx)
{
	unsigned char buf[VAX_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off, id_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off) return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_LINK, (__u32)parent_idx);
	if (!off) return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_NUM_TX_QUEUES, ntx);
	if (!off) return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_NUM_RX_QUEUES, nrx);
	if (!off) return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, kind);
	if (!off) return -EIO;
	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off) return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), mode_nla_type, mode_val);
	if (!off) return -EIO;
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Dispatch the create call for the chosen pair kind.  On success fills
 * *a_idx / *b_idx with the two ifindexes the rest of the childop needs.
 * For veth/vxcan, (a,b) are the two halves of the pair.  For ipvlan/
 * macvlan, "a" is the slave (XDP target) and "b" is the dummy parent
 * (raw-send target + cascade-delete root).
 */
static int vax_create_dispatch(struct nl_ctx *ctx, enum pair_kind pk,
			       const char *a, const char *b,
			       __u32 ntx, __u32 nrx, __u32 ptx, __u32 prx,
			       int *a_idx, int *b_idx)
{
	int rc;

	switch (pk) {
	case PK_VETH:
	case PK_VXCAN:
		rc = vax_create_pair(ctx, kind_to_str[pk], a, b,
				     ntx, nrx, ptx, prx);
		if (rc) return rc;
		*a_idx = (int)if_nametoindex(a);
		*b_idx = (int)if_nametoindex(b);
		return 0;
	case PK_IPVLAN:
	case PK_MACVLAN:
		rc = vax_create_dummy(ctx, b);
		if (rc) return rc;
		*b_idx = (int)if_nametoindex(b);
		if (*b_idx <= 0) return -ENODEV;
		if (pk == PK_IPVLAN)
			rc = vax_create_slave(ctx, "ipvlan", *b_idx, a,
					      IFLA_IPVLAN_MODE,
					      IPVLAN_MODE_L3, ntx, nrx);
		else
			rc = vax_create_slave(ctx, "macvlan", *b_idx, a,
					      IFLA_MACVLAN_MODE,
					      MACVLAN_MODE_BRIDGE, ntx, nrx);
		if (rc) return rc;
		*a_idx = (int)if_nametoindex(a);
		return 0;
	default:
		return -EINVAL;
	}
}

static int vax_setlink_up(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[64];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int vax_dellink(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[64];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWLINK SET with nested IFLA_XDP { IFLA_XDP_FD, IFLA_XDP_FLAGS=
 * XDP_FLAGS_SKB_MODE } -- attach (prog_fd >= 0) or detach (prog_fd = -1)
 * the XDP program on @ifindex.
 */
static int vax_xdp_attach(struct nl_ctx *ctx, int ifindex, int prog_fd)
{
	unsigned char buf[VAX_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, x_off;
	__u32 flags = XDP_FLAGS_SKB_MODE;
	__s32 fdval = prog_fd;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	x_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_XDP);
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_XDP_FD, &fdval, sizeof(fdval));
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_XDP_FLAGS, &flags, sizeof(flags));
	if (!off) return -EIO;
	nla_nest_end(buf, x_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Two-instruction XDP program: r0 = XDP_REDIRECT (3); exit.  No map,
 * no helper call -- the kernel's verifier accepts it; runtime
 * xdp_do_redirect() returns -EINVAL because no bpf_redirect_info was
 * stamped, but the rcv-side walked the XDP path before deciding to
 * drop, which is the goal.
 */
static int vax_load_xdp_prog(void)
{
	struct bpf_insn insns[] = {
		EBPF_MOV64_IMM(BPF_REG_0, 3),
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

static __u32 pick_q(void)
{
	return q_choices[rnd_modulo_u32(ARRAY_SIZE(q_choices))];
}

/*
 * Pick a pair_kind whose latch is not set, starting at a random offset
 * and round-robining forward.  Returns PK_NR if every kind is latched
 * off (caller should bail).
 */
static enum pair_kind pick_kind(void)
{
	unsigned int start = rnd_modulo_u32(PK_NR);
	unsigned int i;

	for (i = 0; i < PK_NR; i++) {
		enum pair_kind pk = (enum pair_kind)((start + i) % PK_NR);
		if (!*kind_latch[pk])
			return pk;
	}
	return PK_NR;
}

/*
 * Phase 1: roll the asymmetric queue counts and pick the pair's
 * interface names.  The shape ntx != nrx, ptx != prx, and (ntx,nrx)
 * != (ptx,prx) is what makes the rcv-side txq-lookup walk past
 * matching parameters on the peer; q_choices[] has 4 entries so the
 * 8-iter re-roll loop converges quickly.  (ptx,prx) are unused for
 * ipvlan/macvlan slaves but rolling them unconditionally keeps the
 * loop simple.  Names share the same 16-bit g_iter suffix so a
 * child's pairs correlate by suffix across iterations.  Cheap and
 * infallible -- no return value.
 */
static void veth_xdp_iter_setup(struct veth_xdp_iter_ctx *ictx)
{
	unsigned int i;

	for (i = 0; i < 8; i++) {
		ictx->ntx = pick_q();
		ictx->nrx = pick_q();
		ictx->ptx = pick_q();
		ictx->prx = pick_q();
		if (ictx->ntx != ictx->nrx && ictx->ptx != ictx->prx &&
		    (ictx->ntx != ictx->ptx || ictx->nrx != ictx->prx))
			break;
	}

	g_iter++;
	snprintf(ictx->a_name, sizeof(ictx->a_name), "vax%ua",
		 g_iter & 0xffffU);
	snprintf(ictx->b_name, sizeof(ictx->b_name), "vax%ub",
		 g_iter & 0xffffU);
}

/*
 * Phase 2: create the pair / slave-on-parent for ictx->pk, capture
 * a_idx / b_idx, and bring both ends UP.  Latches the per-kind
 * unsupported gate on the structural-errno set from
 * vax_create_dispatch so siblings stop probing that kind; EPERM bumps
 * the eperm counter but stays unlatched (transient capability state
 * can flip).  Returns 0 on success or -1 if the iteration should bail
 * to the orchestrator's out: teardown path.  Setlink-up failures are
 * best-effort -- a DOWN end still leaves the create-side of the
 * asymmetric-queue surface exercised even without traffic.
 */
static int veth_xdp_iter_create_pair(struct veth_xdp_iter_ctx *ictx)
{
	/* Snapshot ictx->child->op_type once and bounds-check before
	 * indexing the per-op stats arrays.  The field lives in shared
	 * memory and can be scribbled by a poisoned-arena write from a
	 * sibling; the child.c dispatch loop already gates its dispatch +
	 * alt-op accounting on the same valid_op snapshot.  Skip the
	 * stats write entirely when the snapshot is out of range. */
	const enum child_op_type op = ictx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	int rc;

	rc = vax_create_dispatch(&ictx->ctx, ictx->pk, ictx->a_name,
				 ictx->b_name, ictx->ntx, ictx->nrx,
				 ictx->ptx, ictx->prx,
				 &ictx->a_idx, &ictx->b_idx);
	if (rc != 0) {
		if (rc == -ENOENT || rc == -EOPNOTSUPP || rc == -EAFNOSUPPORT) {
			*kind_latch[ictx->pk] = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.veth_asym_unsupported,
					   1, __ATOMIC_RELAXED);
		} else if (rc == -EPERM) {
			__atomic_add_fetch(&shm->stats.veth_asym_eperm,
					   1, __ATOMIC_RELAXED);
		}
		return -1;
	}
	if (ictx->a_idx <= 0 || ictx->b_idx <= 0)
		return -1;

	__atomic_add_fetch(&shm->stats.veth_asym_pair_ok, 1, __ATOMIC_RELAXED);

	/* Kernel confirmed ictx->a_name now names a real device (NEWLINK
	 * ACK + if_nametoindex > 0); publish it via the NETDEV name pool
	 * so sibling childops and per-syscall fuzzers drawing this kind
	 * can collide with it on subsequent invocations.  Record only the
	 * primary (a) side -- the per-kind ring is 16 slots so flooding
	 * both pair leaves would churn the pool. */
	name_pool_record(NAME_KIND_NETDEV, ictx->a_name,
			 strlen(ictx->a_name));

	(void)vax_setlink_up(&ictx->ctx, ictx->a_idx);
	(void)vax_setlink_up(&ictx->ctx, ictx->b_idx);
	return 0;
}

/*
 * Phase 3: BPF_PROG_LOAD an opaque "r0 = XDP_REDIRECT; exit" program
 * and attach it to the a-side via RTM_NEWLINK + IFLA_XDP nest in
 * SKB_MODE.  Latches ns_unsupported_xdp on the EPERM / EACCES /
 * EINVAL / EOPNOTSUPP set BPF_PROG_LOAD returns when XDP load is
 * unavailable (unprivileged-bpf disabled, CONFIG_BPF_SYSCALL absent,
 * BPF_PROG_TYPE_XDP not enabled).  Kept separate from the per-kind
 * latches so a missing kind doesn't disable XDP for the others and a
 * missing XDP doesn't disable the asymmetric-queue exercise.  Attach
 * failure leaves prog_fd alive so the teardown helper still closes
 * it; ictx->prog_fd starts at -1 from the orchestrator's initialiser
 * so that guard fires correctly whether load skipped, failed, or
 * succeeded.  No return value -- later phases gate on prog_fd / a_idx
 * independently.
 */
static void veth_xdp_iter_load_xdp(struct veth_xdp_iter_ctx *ictx)
{
	/* Snapshot ictx->child->op_type once and bounds-check before
	 * indexing the per-op stats arrays.  The field lives in shared
	 * memory and can be scribbled by a poisoned-arena write from a
	 * sibling; the child.c dispatch loop already gates its dispatch +
	 * alt-op accounting on the same valid_op snapshot.  Skip the
	 * stats write entirely when the snapshot is out of range. */
	const enum child_op_type op = ictx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unsupported_xdp)
		return;

	ictx->prog_fd = vax_load_xdp_prog();
	if (ictx->prog_fd < 0) {
		if (errno == EPERM || errno == EACCES ||
		    errno == EINVAL || errno == EOPNOTSUPP) {
			ns_unsupported_xdp = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.veth_asym_unsupported,
					   1, __ATOMIC_RELAXED);
		}
		return;
	}

	if (vax_xdp_attach(&ictx->ctx, ictx->a_idx, ictx->prog_fd) == 0)
		__atomic_add_fetch(&shm->stats.veth_asym_xdp_attach_ok,
				   1, __ATOMIC_RELAXED);
}

/*
 * Phase 4: open an AF_PACKET/SOCK_RAW socket and spray a 4..16-frame
 * burst of eth+IP-shaped garbage at the b-side ifindex.  Frames are
 * intentionally not well-formed past the ethertype -- the goal is to
 * drive the kernel's hash-modulo txq selection on the rcv (a) side
 * under the asymmetric-queue config, which only needs link-layer
 * framing.  Socket open failure (EPERM under unprivileged AF_PACKET,
 * or EAFNOSUPPORT on a kernel without CONFIG_PACKET) leaves
 * ictx->raw at -1 so the teardown helper skips the close.  No return
 * value -- per-send success is recorded as stats.veth_asym_send_ok
 * and failures are silently tolerated (sendto is MSG_DONTWAIT, so
 * the burst can't wedge past the SIGALRM(1s) child cap).
 */
static void veth_xdp_iter_drive_burst(struct veth_xdp_iter_ctx *ictx)
{
	struct sockaddr_ll sll;
	unsigned char frame[64];
	unsigned int burst, i;

	ictx->raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
			   htons(ETH_P_IP));
	if (ictx->raw < 0)
		return;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);
	sll.sll_ifindex  = ictx->b_idx;
	sll.sll_halen    = 6;
	memset(sll.sll_addr, 0xff, 6);

	burst = VAX_BURST_MIN +
		rnd_modulo_u32(VAX_BURST_MAX - VAX_BURST_MIN + 1U);
	for (i = 0; i < burst; i++) {
		generate_rand_bytes(frame, sizeof(frame));
		frame[12] = 0x08; frame[13] = 0x00;	/* ethertype IP */
		if (sendto(ictx->raw, frame, sizeof(frame), MSG_DONTWAIT,
			   (struct sockaddr *)&sll, sizeof(sll)) > 0)
			__atomic_add_fetch(&shm->stats.veth_asym_send_ok,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * Phase 5: close whichever resources we managed to open.  Runs on
 * every exit path -- both the success path after drive_burst and any
 * early-bail goto out from nl_open or create_pair.  Order: raw
 * AF_PACKET fd first (any frames still buffered get discarded), then
 * the XDP detach + prog_fd close (detach is best-effort and only
 * issued if the a-side ifindex + rtnl ctx are both live), then the
 * link teardown via the rtnl ctx.  For veth/vxcan, dellink(a)
 * cascades the peer through the kernel's pair-teardown path; for
 * ipvlan/macvlan the slave (a) and parent dummy (b) are independent
 * net_devices and must be deleted explicitly so the netns doesn't
 * accumulate stale devices across many iterations in the same child.
 * All fields default to -1 / 0 via the orchestrator's designated
 * initialiser so the guards skip work that was never set up.
 */
static void veth_xdp_iter_teardown(struct veth_xdp_iter_ctx *ictx)
{
	if (ictx->raw >= 0)
		close(ictx->raw);
	if (ictx->prog_fd >= 0) {
		if (ictx->a_idx > 0 && ictx->ctx.fd >= 0)
			(void)vax_xdp_attach(&ictx->ctx, ictx->a_idx, -1);
		close(ictx->prog_fd);
	}
	if (ictx->ctx.fd >= 0) {
		if (ictx->a_idx > 0)
			(void)vax_dellink(&ictx->ctx, ictx->a_idx);
		if (ictx->b_idx > 0 &&
		    (ictx->pk == PK_IPVLAN || ictx->pk == PK_MACVLAN))
			(void)vax_dellink(&ictx->ctx, ictx->b_idx);
		nl_close(&ictx->ctx);
	}
}

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any links,
 * XDP attachments, raw sockets and netlink ctxs the phase helpers
 * leave behind are reaped by the kernel along with the namespace.
 * Return value is ignored by the helper.
 */
static int veth_asymmetric_xdp_in_ns(void *arg)
{
	struct veth_xdp_iter_ctx *ictx = (struct veth_xdp_iter_ctx *)arg;
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	const enum child_op_type op = ictx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (nl_open(&ictx->ctx, &opts) < 0)
		goto out;

	if (veth_xdp_iter_create_pair(ictx) != 0)
		goto out;
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	veth_xdp_iter_load_xdp(ictx);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	veth_xdp_iter_drive_burst(ictx);

out:
	veth_xdp_iter_teardown(ictx);
	return 0;
}

bool veth_asymmetric_xdp(struct childdata *child)
{
	struct veth_xdp_iter_ctx ictx = {
		.ctx = { .fd = -1 },
		.child = child,
		.prog_fd = -1,
		.raw = -1,
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

	__atomic_add_fetch(&shm->stats.veth_asym_iters, 1, __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	ictx.pk = pick_kind();
	if (ictx.pk == PK_NR)
		return true;

	/* Roll names + asymmetric queue counts in the persistent child so
	 * g_iter advances across iterations regardless of how the
	 * grandchild exits; the COW-snapshotted ictx carries the values
	 * into the in-ns callback. */
	veth_xdp_iter_setup(&ictx);

	rc = userns_run_in_ns(CLONE_NEWNET, veth_asymmetric_xdp_in_ns, &ictx);
	if (rc == -EPERM) {
		ns_unsupported = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.veth_asym_eperm, 1,
				   __ATOMIC_RELAXED);
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

#else  /* missing <linux/if_link.h> or <linux/bpf.h> */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

#include "kernel/socket.h"
bool veth_asymmetric_xdp(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.veth_asym_iters, 1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.veth_asym_unsupported, 1, __ATOMIC_RELAXED);
	return true;
}

#endif
