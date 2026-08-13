/*
 * bridge_fdb_stp - link setup builders.
 *
 * Netlink RTM_NEWLINK / RTM_SETLINK message builders for the bridge
 * device, its enslaved veth ports, and the per-port BR_LEARNING arm.
 * All four are self-contained, take a nl_ctx and return 0 on ack or a
 * negated errno on rejection.  Called by the orchestrator in
 * bridge-fdb-stp.c and by the mass-VLAN sub-mode in
 * bridge-fdb-stp-vlan-mass.c.
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#include "childops-netlink.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#include "bridge-fdb-stp-internal.h"

/* UAPI fallbacks for stripped sysroots */
#ifndef ETH_P_IP
#define ETH_P_IP			0x0800
#endif
#ifndef MCAST_EXCLUDE
#define MCAST_EXCLUDE			0
#endif
#ifndef MCAST_INCLUDE
#define MCAST_INCLUDE			1
#endif
/* IFLA_BR_MCAST_SNOOPING = 23 (stable UAPI enum position) */
#ifndef IFLA_BR_MCAST_SNOOPING
#define IFLA_BR_MCAST_SNOOPING		23
#endif
/* IFLA_BRPORT_STATE = 1 (stable UAPI) */
#ifndef IFLA_BRPORT_STATE
#define IFLA_BRPORT_STATE		1
#endif

/*
 * RTM_NEWLINK type=bridge with the supplied dev name.  No
 * IFLA_INFO_DATA — defaults are fine for our purposes (STP off,
 * default ageing, default forward delay).  STP gets toggled later
 * via sysfs.  Returns 0 on accept, negated errno on rejection,
 * -EIO on local failure.
 */
int bfs_build_bridge_create(struct nl_ctx *ctx, const char *name)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;
	size_t li_off;

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

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "bridge");
	if (!off)
		return -EIO;

	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWLINK type=veth with VETH_INFO_PEER carrying the peer's
 * ifinfomsg + IFLA_IFNAME.  Distinct peer names per pair so the four
 * veth ends in this op are unambiguously addressable by name.
 */
int bfs_build_veth_create(struct nl_ctx *ctx, const char *name,
		      const char *peer_name)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct ifinfomsg *peer_ifi;
	size_t off;
	size_t li_off, id_off, peer_off;

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

	peer_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), VETH_INFO_PEER);
	if (!off)
		return -EIO;

	/* VETH_INFO_PEER's payload starts with an ifinfomsg, then
	 * regular IFLA attributes (IFLA_IFNAME for the peer name). */
	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, peer_name);
	if (!off)
		return -EIO;

	nla_nest_end(buf, peer_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_SETLINK with IFLA_MASTER=master_ifindex on ifindex.  Enslaves
 * the veth end to the bridge.
 */
int bfs_build_setlink_master(struct nl_ctx *ctx, int ifindex,
			 int master_ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_MASTER,
			  (__u32)master_ifindex);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_SETLINK family=AF_BRIDGE with IFLA_PROTINFO containing
 * IFLA_BRPORT_LEARNING=1 — arms BR_LEARNING on the port.  This is
 * what makes the receive-path frame ingress drive br_fdb_update
 * (the rx-driven learning path the op exists to exercise).
 */
int bfs_build_setlink_brport_learning(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, pi_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_BRIDGE;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	pi_off = off;
	off = nla_nest_start(buf, off, sizeof(buf),
			     IFLA_PROTINFO | NLA_F_NESTED);
	if (!off)
		return -EIO;

	off = nla_put_u8(buf, off, sizeof(buf), IFLA_BRPORT_LEARNING, 1);
	if (!off)
		return -EIO;

	nla_nest_end(buf, pi_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/* ================================================================
 * star_g port-group UAF oracle
 *
 * Deterministic 5-step recipe for the port->mglist use-after-free in
 * br_multicast_del_port() / __br_multicast_disable_port_ctx().
 * hlist_for_each_entry_safe latches `next` before the body; deleting
 * the (*,G) EXCLUDE entry cascades __fwd_del_star_excl() which frees
 * later (S,G) entries whose pointers are already latched.
 *
 * Oracle A (KASAN): set port DISABLED then un-enslave -- KASAN fires
 *   slab-use-after-free in the walk on a buggy kernel.
 * Oracle B (no-KASAN): count MDB entries before and after; on a buggy
 *   kernel entries freed by cascade deletion still appear in the dump.
 *
 * Positive-control invariant: mdb_star_g_created and mdb_sg_created must be non-zero
 * for any result to be trusted.  If both stay 0 the src-list builder
 * or policy gate is broken; do not report a clean kernel.
 * ================================================================ */

#if __has_include(<linux/if_bridge.h>)

/* Fixed group and source addresses for the arm.  Group 239.1.1.1 is
 * a valid global multicast address that bridge snooping accepts.
 * Sources are RFC 1918 unicast -- valid as multicast source addrs. */
#define BSGU_GROUP_H	0xef010101u	/* 239.1.1.1 host-byte-order */
#define BSGU_SRC0_H	0x0a010101u	/* 10.1.1.1 */
#define BSGU_SRC1_H	0x0a010102u	/* 10.1.1.2 */
#define BSGU_NSRCS	2

/*
 * RTM_NEWLINK type=bridge with IFLA_BR_MCAST_SNOOPING=1 inside
 * IFLA_INFO_DATA.  Multicast snooping must be enabled for the kernel
 * to maintain the mglist that the UAF walks.
 */
static int bfs_build_bridge_create_mcast(struct nl_ctx *ctx, const char *name)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off, id_off;

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

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "bridge");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off)
		return -EIO;

	/* IFLA_BR_MCAST_SNOOPING=1: enable multicast snooping so the kernel
	 * maintains port->mglist which the UAF walks on port teardown. */
	off = nla_put_u8(buf, off, sizeof(buf), IFLA_BR_MCAST_SNOOPING, 1);
	if (!off)
		return -EIO;

	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Build a proper two-level MDBE_ATTR_SRC_LIST nest into buf at absolute
 * offset `off`:
 *
 *   MDBE_ATTR_SRC_LIST (NLA_F_NESTED)
 *     MDBE_SRC_LIST_ENTRY (NLA_F_NESTED) x nsrcs
 *       MDBE_SRCATTR_ADDRESS  4 bytes (IPv4 network-byte-order)
 *
 * Returns new absolute offset on success, 0 on failure.  Bumps
 * shm->stats.bridge_fdb_stp.star_g_mdbe_src_list_built on success
 * so the caller can confirm the builder is reaching the kernel.
 */
static size_t bsgu_build_src_list(unsigned char *buf, size_t off, size_t cap,
				   const __u32 *srcs, int nsrcs)
{
	size_t outer_off = off;
	size_t inner_off;
	int i;

	off = nla_nest_start(buf, off, cap, MDBE_ATTR_SRC_LIST | NLA_F_NESTED);
	if (!off)
		return 0;

	for (i = 0; i < nsrcs; i++) {
		inner_off = off;
		off = nla_nest_start(buf, off, cap,
				     MDBE_SRC_LIST_ENTRY | NLA_F_NESTED);
		if (!off)
			return 0;
		off = nla_put(buf, off, cap, MDBE_SRCATTR_ADDRESS, &srcs[i], 4);
		if (!off)
			return 0;
		nla_nest_end(buf, inner_off, off);
	}

	nla_nest_end(buf, outer_off, off);
	__atomic_add_fetch(&shm->stats.bridge_fdb_stp.star_g_mdbe_src_list_built,
			   1, __ATOMIC_RELAXED);
	return off;
}

/*
 * RTM_NEWMDB for a (*,G) EXCLUDE entry with src-list.
 * Build order matters: (*,G) must be created FIRST so it ends up
 * last in port->mglist (head-inserted list, walked newest-first),
 * after the (S,G) entries that __fwd_del_star_excl() will free.
 */
static int bsgu_newmdb_star_g(struct nl_ctx *ctx, int br_idx, int port_idx,
				const __u32 *srcs, int nsrcs)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh;
	struct br_port_msg *bpm;
	struct br_mdb_entry mdb_e;
	size_t off, attrs_off;
	__be32 group;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWMDB;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	off = NLMSG_HDRLEN;
	bpm = (struct br_port_msg *)(buf + off);
	bpm->family  = AF_BRIDGE;
	bpm->ifindex = (__u32)br_idx;
	off += NLMSG_ALIGN(sizeof(*bpm));

	/* struct br_mdb_entry: (*,G) entry for group 239.1.1.1 */
	memset(&mdb_e, 0, sizeof(mdb_e));
	mdb_e.ifindex    = (__u32)port_idx;
	mdb_e.state      = MDB_TEMPORARY;
	mdb_e.addr.proto = htons(ETH_P_IP);
	group            = htonl(BSGU_GROUP_H);
	mdb_e.addr.u.ip4 = group;

	off = nla_put(buf, off, sizeof(buf), MDBA_SET_ENTRY,
		      &mdb_e, sizeof(mdb_e));
	if (!off)
		return -EIO;

	/* MDBA_SET_ENTRY_ATTRS nest: GROUP_MODE + SRC_LIST */
	attrs_off = off;
	off = nla_nest_start(buf, off, sizeof(buf),
			     MDBA_SET_ENTRY_ATTRS | NLA_F_NESTED);
	if (!off)
		return -EIO;

	off = nla_put_u8(buf, off, sizeof(buf),
			 MDBE_ATTR_GROUP_MODE, MCAST_EXCLUDE);
	if (!off)
		return -EIO;

	off = bsgu_build_src_list(buf, off, sizeof(buf), srcs, nsrcs);
	if (!off)
		return -EIO;

	nla_nest_end(buf, attrs_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWMDB for an explicit (S,G) entry.  These become the
 * MDB_PG_FLAGS_STAR_EXCL entries that get freed out from under the
 * latched hlist `next` pointer when (*,G) is deleted.
 */
static int bsgu_newmdb_sg(struct nl_ctx *ctx, int br_idx, int port_idx,
			  __u32 src_be)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct br_port_msg *bpm;
	struct br_mdb_entry mdb_e;
	size_t off, attrs_off;
	__be32 group;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWMDB;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	off = NLMSG_HDRLEN;
	bpm = (struct br_port_msg *)(buf + off);
	bpm->family  = AF_BRIDGE;
	bpm->ifindex = (__u32)br_idx;
	off += NLMSG_ALIGN(sizeof(*bpm));

	/* (S,G) entry: same group, source identifies the SG */
	memset(&mdb_e, 0, sizeof(mdb_e));
	mdb_e.ifindex    = (__u32)port_idx;
	mdb_e.state      = MDB_TEMPORARY;
	mdb_e.addr.proto = htons(ETH_P_IP);
	group            = htonl(BSGU_GROUP_H);
	mdb_e.addr.u.ip4 = group;

	off = nla_put(buf, off, sizeof(buf), MDBA_SET_ENTRY,
		      &mdb_e, sizeof(mdb_e));
	if (!off)
		return -EIO;

	/* MDBA_SET_ENTRY_ATTRS: MDBE_ATTR_SOURCE identifies this as (S,G) */
	attrs_off = off;
	off = nla_nest_start(buf, off, sizeof(buf),
			     MDBA_SET_ENTRY_ATTRS | NLA_F_NESTED);
	if (!off)
		return -EIO;

	off = nla_put(buf, off, sizeof(buf), MDBE_ATTR_SOURCE, &src_be, 4);
	if (!off)
		return -EIO;

	nla_nest_end(buf, attrs_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_SETLINK AF_BRIDGE: set the port's STP state via IFLA_BRPORT_STATE.
 * BR_STATE_DISABLED -> __br_multicast_disable_port_ctx() -> mglist walk.
 */
static int bsgu_set_port_state(struct nl_ctx *ctx, int port_idx, __u8 state)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, pi_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_BRIDGE;
	ifi->ifi_index  = port_idx;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	pi_off = off;
	off = nla_nest_start(buf, off, sizeof(buf),
			     IFLA_PROTINFO | NLA_F_NESTED);
	if (!off)
		return -EIO;

	off = nla_put_u8(buf, off, sizeof(buf), IFLA_BRPORT_STATE, state);
	if (!off)
		return -EIO;

	nla_nest_end(buf, pi_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_SETLINK with IFLA_MASTER=0: un-enslave the port from the bridge.
 * Enters br_multicast_del_port() -> second mglist walk.
 */
static int bsgu_unenslave(struct nl_ctx *ctx, int port_idx)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = port_idx;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_u32(buf, off, sizeof(buf), IFLA_MASTER, 0);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Callback for nl_send_recv_dump_cb(): count RTM_NEWMDB messages
 * returned by an RTM_GETMDB dump, used for Oracle B.
 */
static int bsgu_count_mdb_cb(const struct nlmsghdr *nlh, void *arg)
{
	unsigned long *cnt = (unsigned long *)arg;

	if (nlh->nlmsg_type == RTM_NEWMDB)
		(*cnt)++;
	return 0;
}

/*
 * RTM_GETMDB dump on the bridge; count total MDB entries returned.
 * Oracle B: stale entries that should have been cascade-deleted remain
 * visible on a buggy kernel.
 */
static int bsgu_count_mdb(struct nl_ctx *ctx, int br_idx,
			   unsigned long *count_out)
{
	unsigned char req[NLMSG_HDRLEN + 16];
	struct nlmsghdr *nlh;
	struct br_port_msg *bpm;
	size_t off;

	*count_out = 0;
	memset(req, 0, sizeof(req));
	nlh = (struct nlmsghdr *)req;
	nlh->nlmsg_type  = RTM_GETMDB;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	off = NLMSG_HDRLEN;
	bpm = (struct br_port_msg *)(req + off);
	bpm->family  = AF_BRIDGE;
	bpm->ifindex = (__u32)br_idx;
	off += NLMSG_ALIGN(sizeof(*bpm));
	nlh->nlmsg_len = (__u32)off;

	return nl_send_recv_dump_cb(ctx, req, off, bsgu_count_mdb_cb, count_out);
}

/*
 * do_bridge_star_g_uaf -- star_g port-group UAF oracle arm.
 *
 * Runs inside the private net namespace (grandchild of userns_run_in_ns).
 * Creates its own bridge and veth pair; does not touch the main
 * bridge_fdb_stp iteration state.
 *
 * Gate rule: if mdb_star_g_created stays 0 after this
 * returns the src-list builder is broken; do not read the result as a
 * clean kernel.  star_g_arm_setup_failed covers earlier failures.
 */
void do_bridge_star_g_uaf(struct nl_ctx *ctx)
{
	char br_name[IFNAMSIZ], veth_a[IFNAMSIZ], veth_b[IFNAMSIZ];
	int br_idx = 0, port_idx = 0, peer_idx = 0;
	int rc, i;
	unsigned long mdb_before = 0, mdb_after = 0;
	__u32 srcs_be[BSGU_NSRCS];

	/* Network-byte-order source addresses reused for (*,G) src-list
	 * and the explicit (S,G) RTM_NEWMDB entries. */
	srcs_be[0] = htonl(BSGU_SRC0_H);
	srcs_be[1] = htonl(BSGU_SRC1_H);

	/* Unique names per invocation via low 16 bits of rand32() */
	{
		unsigned int rng = rand32() & 0xffffu;

		snprintf(br_name, sizeof(br_name), "sgbr%04x", rng);
		snprintf(veth_a,  sizeof(veth_a),  "sgva%04x", rng);
		snprintf(veth_b,  sizeof(veth_b),  "sgvb%04x", rng);
	}

	/* Step 1a: veth pair */
	rc = bfs_build_veth_create(ctx, veth_a, veth_b);
	if (rc != 0) {
		__atomic_add_fetch(
			&shm->stats.bridge_fdb_stp.star_g_arm_setup_failed,
			1, __ATOMIC_RELAXED);
		return;
	}

	/* Step 1b: bridge with MCAST_SNOOPING=1 */
	rc = bfs_build_bridge_create_mcast(ctx, br_name);
	if (rc != 0) {
		__atomic_add_fetch(
			&shm->stats.bridge_fdb_stp.star_g_arm_setup_failed,
			1, __ATOMIC_RELAXED);
		goto out_cleanup;
	}

	br_idx   = (int)if_nametoindex(br_name);
	port_idx = (int)if_nametoindex(veth_a);
	peer_idx = (int)if_nametoindex(veth_b);

	if (br_idx <= 0 || port_idx <= 0) {
		__atomic_add_fetch(
			&shm->stats.bridge_fdb_stp.star_g_arm_setup_failed,
			1, __ATOMIC_RELAXED);
		goto out_cleanup;
	}

	/* Step 1c: enslave veth_a to bridge */
	rc = bfs_build_setlink_master(ctx, port_idx, br_idx);
	if (rc != 0) {
		__atomic_add_fetch(
			&shm->stats.bridge_fdb_stp.star_g_arm_setup_failed,
			1, __ATOMIC_RELAXED);
		goto out_cleanup;
	}

	(void)rtnl_setlink_up(ctx, br_idx);
	(void)rtnl_setlink_up(ctx, port_idx);

	/* Step 2: RTM_NEWMDB (*,G) EXCLUDE -- created FIRST so it ends up
	 * LAST in port->mglist (head-insertion).  Deleting it triggers
	 * br_multicast_star_g_handle_mode() -> __fwd_del_star_excl().
	 * Count success: if this stays 0 src-list nesting is broken. */
	rc = bsgu_newmdb_star_g(ctx, br_idx, port_idx, srcs_be, BSGU_NSRCS);
	if (rc != 0)
		goto out_cleanup;
	__atomic_add_fetch(&shm->stats.bridge_fdb_stp.mdb_star_g_created,
			   1, __ATOMIC_RELAXED);

	/* Step 3: explicit (S,G) entries for each source.
	 * These are the MDB_PG_FLAGS_STAR_EXCL entries that live AFTER
	 * (*,G) in the list and get freed under the latched next ptr.
	 * Count per entry so partial success is visible. */
	for (i = 0; i < BSGU_NSRCS; i++) {
		if (bsgu_newmdb_sg(ctx, br_idx, port_idx, srcs_be[i]) == 0)
			__atomic_add_fetch(
				&shm->stats.bridge_fdb_stp.mdb_sg_created,
				1, __ATOMIC_RELAXED);
	}

	/* Oracle B pre: count MDB entries before the trigger */
	(void)bsgu_count_mdb(ctx, br_idx, &mdb_before);
	__atomic_add_fetch(&shm->stats.bridge_fdb_stp.star_g_mdb_before,
			   mdb_before, __ATOMIC_RELAXED);

	/* Oracle A step A: set port to BR_STATE_DISABLED.
	 * Enters __br_multicast_disable_port_ctx() -> mglist walk.
	 * On a buggy kernel KASAN fires slab-use-after-free here. */
	(void)bsgu_set_port_state(ctx, port_idx, BR_STATE_DISABLED);

	/* Oracle A step B: un-enslave port (IFLA_MASTER=0).
	 * Enters br_multicast_del_port() -> second mglist walk.
	 * Second KASAN trigger on buggy kernel; both must fire per spec. */
	(void)bsgu_unenslave(ctx, port_idx);

	/* Oracle B post: count entries after; stale surviving entries
	 * indicate cascade-free failure on a buggy kernel. */
	(void)bsgu_count_mdb(ctx, br_idx, &mdb_after);
	__atomic_add_fetch(&shm->stats.bridge_fdb_stp.star_g_mdb_after,
			   mdb_after, __ATOMIC_RELAXED);

out_cleanup:
	/* Bridge RTM_DELLINK cascades the enslaved veths */
	if (br_idx > 0)
		(void)rtnl_dellink(ctx, br_idx);
	/* Mop up veths in case bridge cascade missed them */
	if (port_idx > 0)
		(void)rtnl_dellink(ctx, port_idx);
	if (peer_idx > 0)
		(void)rtnl_dellink(ctx, peer_idx);
}

#endif /* __has_include(<linux/if_bridge.h>) */
