/*
 * veth_asymmetric_xdp - asymmetric-queue paired/slave netdev + XDP_REDIRECT
 * prog + raw packet burst, aimed at the veth tx-queue lookup OOB shape that
 * upstream commit 08f566e8f83b ("veth: prevent NULL pointer dereference in
 * veth_xdp_rcv_one()" and the surrounding asymmetric-queue handling) was
 * about: when the receiving side has fewer rx queues than the sending side
 * has tx queues (or vice-versa), skb_get_tx_queue() / hash-modulo selection
 * on the rcv side can index past the per-queue array.  Random isolated
 * syscall fuzzing essentially never assembles all of (a) a pair created
 * with explicit IFLA_NUM_{TX,RX}_QUEUES asymmetric across the two halves,
 * (b) an XDP program attached on one half only, and (c) live packet traffic
 * through the resulting pair, in a single child's lifetime.  This childop
 * drives the full sequence per outer iteration so the txq lookup path
 * actually runs against an asymmetric pair under XDP.
 *
 * Pair kinds (picked uniformly per iteration; latched off independently):
 *   PK_VETH    -- classic veth pair.  IFLA_INFO_KIND="veth", nested
 *                 IFLA_INFO_DATA { IFLA_VETH_INFO_PEER { ... } } carries
 *                 the peer's ifinfomsg + IFLA_IFNAME + per-side queue
 *                 counts.  Asymmetric queues straightforward.
 *   PK_VXCAN   -- CAN-bus virtual pair.  Same nested-peer shape as veth
 *                 (IFLA_VXCAN_INFO_PEER == 1 == IFLA_VETH_INFO_PEER) so
 *                 the same builder serves both with just a kind string
 *                 swap.  Raw AF_PACKET send into a CAN device will fail
 *                 at bind/sendto time -- that's fine, the goal is to
 *                 exercise the rtnl pair-create + XDP attach paths and
 *                 their asymmetric-queue accounting.
 *   PK_IPVLAN  -- slave-on-parent: first create a "dummy" parent, then
 *                 RTM_NEWLINK an ipvlan slave with IFLA_LINK=parent_idx
 *                 and IFLA_INFO_DATA { IFLA_IPVLAN_MODE=IPVLAN_MODE_L3 }.
 *                 The "pair" is (slave, parent) -- XDP attach lands on
 *                 the slave (dummy doesn't support XDP), raw traffic on
 *                 the parent.
 *   PK_MACVLAN -- as above with IFLA_MACVLAN_MODE=MACVLAN_MODE_BRIDGE.
 *
 * Per iteration:
 *   (a) unshare(CLONE_NEWNET) once per child.  EPERM latches off.
 *   (b) Pick a non-latched pair kind (round-robin from random start).
 *   (c) Create the pair/slave with random asymmetric queue counts.
 *   (d) RTM_NEWLINK SET IFF_UP on both ends.
 *   (e) bpf(BPF_PROG_LOAD, BPF_PROG_TYPE_XDP) for "r0 = XDP_REDIRECT;
 *       exit".  Two-insn opaque blob; no map dependency.  Loadable on
 *       any kernel that accepts unprivileged XDP load (the runtime
 *       redirect will fail without an installed map, but the program
 *       returning XDP_REDIRECT is enough to walk the kernel's
 *       xdp_do_redirect path on the rcv side).
 *   (f) Attach the prog to the "a" side via RTM_NEWLINK + nested
 *       IFLA_XDP { IFLA_XDP_FD, IFLA_XDP_FLAGS=XDP_FLAGS_SKB_MODE }.
 *       SKB mode works without driver native-XDP and is what veth and
 *       friends fall back to anyway.
 *   (g) AF_PACKET / SOCK_RAW socket bound to the "b" side's ifindex,
 *       sendto a 4-16 frame burst of small ethernet+IP+UDP-shaped
 *       payloads.  Hash-driven txq selection on the rcv side walks the
 *       asymmetric-queue array.
 *   (h) RTM_DELLINK the "a" side (cascades to peer for veth/vxcan; for
 *       ipvlan/macvlan the parent dummy is also torn down).  Close
 *       prog + raw fds.
 *
 * Latches:
 *   ns_unsupported_veth     -- first ENOENT/EOPNOTSUPP from veth NEWLINK.
 *   ns_unsupported_vxcan    -- ditto for vxcan (CAN_VCAN/CAN_VXCAN module).
 *   ns_unsupported_ipvlan   -- ditto for the ipvlan slave (also tripped
 *                              if the dummy parent NEWLINK fails, since
 *                              ipvlan needs a parent regardless).
 *   ns_unsupported_macvlan  -- ditto for macvlan.
 *   ns_unsupported_xdp      -- first EPERM/EINVAL from BPF_PROG_LOAD.
 *                              Kept separate from the per-kind latches so
 *                              a missing kind doesn't disable XDP for the
 *                              others and a missing XDP doesn't disable
 *                              the asymmetric-queue exercise.
 */

#if __has_include(<linux/if_link.h>) && __has_include(<linux/bpf.h>)

#include <errno.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
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
#include "child.h"
#include "childops-netlink.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
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

static bool ns_unsupported_veth;
static bool ns_unsupported_vxcan;
static bool ns_unsupported_ipvlan;
static bool ns_unsupported_macvlan;
static bool ns_unsupported_xdp;
static bool vax_unshared;
static __u32 g_iter;

static bool *const kind_latch[PK_NR] = {
	[PK_VETH]    = &ns_unsupported_veth,
	[PK_VXCAN]   = &ns_unsupported_vxcan,
	[PK_IPVLAN]  = &ns_unsupported_ipvlan,
	[PK_MACVLAN] = &ns_unsupported_macvlan,
};

static int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return (int)syscall(__NR_bpf, cmd, attr, size);
}

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

bool veth_asymmetric_xdp(struct childdata *child)
{
	struct nl_ctx ctx = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	int prog_fd = -1, raw = -1;
	int a_idx = 0, b_idx = 0;
	__u32 ntx, nrx, ptx, prx;
	unsigned int burst, i;
	char a_name[IFNAMSIZ], b_name[IFNAMSIZ];
	enum pair_kind pk;
	int rc;

	(void)child;

	__atomic_add_fetch(&shm->stats.veth_asym_iters, 1, __ATOMIC_RELAXED);

	pk = pick_kind();
	if (pk == PK_NR)
		return true;

	if (!vax_unshared) {
		if (unshare(CLONE_NEWNET) < 0) {
			if (errno == EPERM || errno == EACCES) {
				/* netns creation refused -- latch every
				 * kind off, no point retrying any of them. */
				ns_unsupported_veth = true;
				ns_unsupported_vxcan = true;
				ns_unsupported_ipvlan = true;
				ns_unsupported_macvlan = true;
				__atomic_add_fetch(&shm->stats.veth_asym_eperm,
						   1, __ATOMIC_RELAXED);
			}
			return true;
		}
		vax_unshared = true;
	}

	if (nl_open(&ctx, &opts) < 0)
		goto out;

	/* Asymmetric: ntx != nrx and (ntx,nrx) != (ptx,prx).  Bounded
	 * roll loop -- q_choices has 4 entries so a few rolls suffice.
	 * (ptx,prx) are unused for ipvlan/macvlan slaves but rolling them
	 * unconditionally keeps the loop simple.) */
	for (i = 0; i < 8; i++) {
		ntx = pick_q();
		nrx = pick_q();
		ptx = pick_q();
		prx = pick_q();
		if (ntx != nrx && ptx != prx && (ntx != ptx || nrx != prx))
			break;
	}

	g_iter++;
	snprintf(a_name, sizeof(a_name), "vax%ua", g_iter & 0xffffU);
	snprintf(b_name, sizeof(b_name), "vax%ub", g_iter & 0xffffU);

	rc = vax_create_dispatch(&ctx, pk, a_name, b_name,
				 ntx, nrx, ptx, prx, &a_idx, &b_idx);
	if (rc != 0) {
		if (rc == -ENOENT || rc == -EOPNOTSUPP || rc == -EAFNOSUPPORT) {
			*kind_latch[pk] = true;
			__atomic_add_fetch(&shm->stats.veth_asym_unsupported,
					   1, __ATOMIC_RELAXED);
		} else if (rc == -EPERM) {
			__atomic_add_fetch(&shm->stats.veth_asym_eperm,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}
	if (a_idx <= 0 || b_idx <= 0)
		goto out;

	__atomic_add_fetch(&shm->stats.veth_asym_pair_ok, 1, __ATOMIC_RELAXED);

	(void)vax_setlink_up(&ctx, a_idx);
	(void)vax_setlink_up(&ctx, b_idx);

	if (!ns_unsupported_xdp) {
		prog_fd = vax_load_xdp_prog();
		if (prog_fd < 0) {
			if (errno == EPERM || errno == EACCES ||
			    errno == EINVAL || errno == EOPNOTSUPP) {
				ns_unsupported_xdp = true;
				__atomic_add_fetch(&shm->stats.veth_asym_unsupported,
						   1, __ATOMIC_RELAXED);
			}
		} else if (vax_xdp_attach(&ctx, a_idx, prog_fd) == 0) {
			__atomic_add_fetch(&shm->stats.veth_asym_xdp_attach_ok,
					   1, __ATOMIC_RELAXED);
		}
	}

	/* Raw send into veth_b.  Frames are eth+IPv4+UDP-shaped garbage --
	 * sufficient to drive the kernel's hash-modulo txq selection on the
	 * rcv (veth_a) side under the asymmetric-queue config. */
	raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_IP));
	if (raw >= 0) {
		struct sockaddr_ll sll;
		unsigned char frame[64];

		memset(&sll, 0, sizeof(sll));
		sll.sll_family   = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_IP);
		sll.sll_ifindex  = b_idx;
		sll.sll_halen    = 6;
		memset(sll.sll_addr, 0xff, 6);

		burst = VAX_BURST_MIN +
			(rand32() % (VAX_BURST_MAX - VAX_BURST_MIN + 1U));
		for (i = 0; i < burst; i++) {
			generate_rand_bytes(frame, sizeof(frame));
			frame[12] = 0x08; frame[13] = 0x00;	/* ethertype IP */
			if (sendto(raw, frame, sizeof(frame), MSG_DONTWAIT,
				   (struct sockaddr *)&sll, sizeof(sll)) > 0)
				__atomic_add_fetch(&shm->stats.veth_asym_send_ok,
						   1, __ATOMIC_RELAXED);
		}
	}

out:
	if (raw >= 0)
		close(raw);
	if (prog_fd >= 0) {
		if (a_idx > 0 && ctx.fd >= 0)
			(void)vax_xdp_attach(&ctx, a_idx, -1);
		close(prog_fd);
	}
	if (ctx.fd >= 0) {
		/* veth/vxcan: dellink(a) cascades the peer.  ipvlan/macvlan:
		 * slave (a) and parent dummy (b) are independent -- delete
		 * both so the netns doesn't accumulate stale devices across
		 * many iterations in the same child. */
		if (a_idx > 0)
			(void)vax_dellink(&ctx, a_idx);
		if (b_idx > 0 && (pk == PK_IPVLAN || pk == PK_MACVLAN))
			(void)vax_dellink(&ctx, b_idx);
		nl_close(&ctx);
	}
	return true;
}

#else  /* missing <linux/if_link.h> or <linux/bpf.h> */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

bool veth_asymmetric_xdp(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.veth_asym_iters, 1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.veth_asym_unsupported, 1, __ATOMIC_RELAXED);
	return true;
}

#endif
