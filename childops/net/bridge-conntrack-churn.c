/*
 * bridge_conntrack_churn - race IPCTNL_MSG_CT_FLUSH against ingress
 * traffic on a NFPROTO_BRIDGE conntrack chain.
 *
 * Targets the upstream nf_ct_bridge_post WARN (upstream CI reproducer): a
 * base chain in the bridge family that references conntrack via the
 * nft "ct" expression triggers nf_conntrack registration on the
 * bridge family, hooking the pre/post-routing handlers in
 * net/bridge/netfilter/nf_conntrack_bridge.c.  Conntrack flush from
 * the ctnetlink subsystem then walks every confirmed tuple and tears
 * state out from under packets in flight at the bridge hooks; the
 * race window is the WARN_ON in nf_ct_bridge_post that fires when a
 * skb's nfct pointer disappears mid-traversal.
 *
 * Sequence (per invocation):
 *   1. Enter a private net namespace via userns_run_in_ns(): a
 *      transient grandchild fork installs an identity user namespace
 *      plus a fresh CLONE_NEWNET, runs the body below, and _exit()s
 *      so the kernel reaps every interface, rule, address, hook and
 *      socket with the grandchild's netns.  The persistent fuzz
 *      child never changes its own credentials or namespace stack,
 *      so the cap-drop oracle keeps observing the host credential
 *      profile.  Helper -EPERM (hardened userns policy refused
 *      CLONE_NEWUSER) latches the childop off for the remainder of
 *      this child's lifetime; -EAGAIN (transient setup failure: fork,
 *      id-map write, secondary unshare) skips the iteration without
 *      latching.  Bring lo up inside the grandchild's netns.
 *   2. RTM_NEWLINK bridge br0 + veth pair v0/v1; enslave v0 to br0;
 *      up bridge + both veth ends.
 *   3. nf_tables transaction: NEWTABLE family=NFPROTO_BRIDGE
 *      "br_ct"; NEWCHAIN base, hook=NF_BR_PRE_ROUTING,
 *      priority=NF_BR_PRI_CT_PRE-1; NEWRULE with one nft_ct
 *      expression (NFTA_CT_KEY=NFT_CT_STATE, NFTA_CT_DREG=NFT_REG_1).
 *   4. AF_PACKET raw socket on v1; pthread sends crafted UDP/4
 *      frames addressed to v0's MAC across the bridge ingress hook.
 *      Bounded by BRCT_PACKET_CAP / BRCT_BUDGET_NS.
 *   5. Main thread: tight bounded loop of IPCTNL_MSG_CT_FLUSH
 *      (BUDGETED+JITTER base 5 cap 16, 200 ms wall, MSG_DONTWAIT).
 *   6. Join sender thread; drain its socket.
 *   7. RTM_DELLINK br0 (cascades v0); RTM_DELLINK v1 survivor.
 *
 * Three latches probe-once-and-stick: ns_unsupported_bridge,
 * ns_unsupported_nf_tables, ns_unsupported_ctnetlink set on
 * EAFNOSUPPORT/EPROTONOSUPPORT/ENOTSUP/EOPNOTSUPP from each
 * subsystem's first message.  ONE_IN(8) gate at top of dispatch
 * keeps the cost low in the altop bucket.  All ctnetlink and packet
 * I/O is MSG_DONTWAIT; the rtnl/nfnl ack sockets carry SO_RCVTIMEO=1s
 * so an unresponsive netlink can't wedge us past the inherited
 * SIGALRM(1s) cap.  Loopback only (private netns).
 */

#include <errno.h>
#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "child.h"
#include "childop-outcome.h"
#include "childops-netlink.h"
#include "childops-nfnl.h"
#include "jitter.h"
#include "name-pool.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"
#ifndef NFPROTO_BRIDGE
#define NFPROTO_BRIDGE			7
#endif
#ifndef NF_BR_PRE_ROUTING
#define NF_BR_PRE_ROUTING		0
#endif
#ifndef NF_BR_PRI_CT_PRE
#define NF_BR_PRI_CT_PRE		(-200)
#endif

#ifndef NFNL_SUBSYS_CTNETLINK
#define NFNL_SUBSYS_CTNETLINK		1
#endif
#ifndef NFNL_SUBSYS_NFTABLES
#define NFNL_SUBSYS_NFTABLES		10
#endif
#ifndef NFNL_MSG_BATCH_BEGIN
#define NFNL_MSG_BATCH_BEGIN		16
#endif
#ifndef NFNL_MSG_BATCH_END
#define NFNL_MSG_BATCH_END		17
#endif
#ifndef IPCTNL_MSG_CT_FLUSH
#define IPCTNL_MSG_CT_FLUSH		4
#endif

/* nf_tables UAPI subset - kept local so a stripped sysroot still
 * builds; values are stable in include/uapi/linux/netfilter/nf_tables.h. */
#define BRCT_NFT_MSG_NEWTABLE		0
#define BRCT_NFT_MSG_NEWCHAIN		3
#define BRCT_NFT_MSG_NEWRULE		6
#define BRCT_NFTA_TABLE_NAME		1
#define BRCT_NFTA_CHAIN_TABLE		1
#define BRCT_NFTA_CHAIN_NAME		3
#define BRCT_NFTA_CHAIN_HOOK		4
#define BRCT_NFTA_CHAIN_TYPE		7
#define BRCT_NFTA_HOOK_HOOKNUM		1
#define BRCT_NFTA_HOOK_PRIORITY		2
#define BRCT_NFTA_RULE_TABLE		1
#define BRCT_NFTA_RULE_CHAIN		2
#define BRCT_NFTA_RULE_EXPRESSIONS	4
#define BRCT_NFTA_LIST_ELEM		1
#define BRCT_NFTA_EXPR_NAME		1
#define BRCT_NFTA_EXPR_DATA		2
#define BRCT_NFTA_CT_DREG		1
#define BRCT_NFTA_CT_KEY		2
#define BRCT_NFT_CT_STATE		0
#define BRCT_NFT_REG_1			8

#define BRCT_FLUSH_BASE			5U
#define BRCT_FLUSH_CAP			16U
#define BRCT_BUDGET_NS			200000000L
#define BRCT_PACKET_CAP			32U
#define BRCT_RTNL_BUF_BYTES		2048
#define BRCT_NFT_BUF_BYTES		2048

/* nf_tables object message type for NFT_MSG_NEWOBJ */
#define BRCT_NFT_MSG_NEWOBJ		18
/* NFTA_OBJ_* top-level attrs */
#define BRCT_NFTA_OBJ_TABLE		1
#define BRCT_NFTA_OBJ_NAME		2
#define BRCT_NFTA_OBJ_TYPE		3
#define BRCT_NFTA_OBJ_DATA		4
/* CT_TIMEOUT object type id (NFT_OBJECT_CT_TIMEOUT) */
#define BRCT_NFT_OBJECT_CT_TIMEOUT	7
/* NFTA_CT_TIMEOUT_* attrs nested under NFTA_OBJ_DATA */
#define BRCT_NFTA_CT_TIMEOUT_L4PROTO	2
#define BRCT_NFTA_CT_TIMEOUT_DATA	3
/* CTA_TIMEOUT_TCP_* state attrs nested under NFTA_CT_TIMEOUT_DATA */
#define BRCT_CTA_TIMEOUT_TCP_SYN_SENT		1
#define BRCT_CTA_TIMEOUT_TCP_ESTABLISHED	3
/* nft_objref IMM-mode attrs nested under NFTA_EXPR_DATA */
#define BRCT_NFTA_OBJREF_IMM_TYPE	1
#define BRCT_NFTA_OBJREF_IMM_NAME	2
/* Bridge-family priority after the conntrack PRE hook (-200+100 = -100) */
#define BRCT_NF_BR_PRI_AFTER_CT_PRE	(NF_BR_PRI_CT_PRE + 100)
/* Intermediate priority: fires after CT_PRE (-200) but before ct-timeout
 * chain (-100).  The mangle rule rewrites pkt->tprot in this window. */
#define BRCT_NF_BR_PRI_MANGLE		(NF_BR_PRI_CT_PRE + 50)
#define BRCT_IPPROTO_TCP		6
/* IPv4 protocol field: byte 9 of the network (IP) header. */
#define BRCT_IPV4_PROTO_OFFSET		9

/* nft_immediate expression attributes */
#define BRCT_NFTA_IMMEDIATE_DREG	1
#define BRCT_NFTA_IMMEDIATE_DATA	2
#define BRCT_NFTA_DATA_VALUE		1
/* nft_payload expression attributes and constants (SET / store path) */
#define BRCT_NFTA_PAYLOAD_DREG		1
#define BRCT_NFTA_PAYLOAD_BASE		2
#define BRCT_NFTA_PAYLOAD_OFFSET	3
#define BRCT_NFTA_PAYLOAD_LEN		4
#define BRCT_NFTA_PAYLOAD_SREG		5
#define BRCT_NFTA_PAYLOAD_OP		6
#define BRCT_NFT_PAYLOAD_NETWORK_HEADER	1	/* NFT_PAYLOAD_NETWORK_HEADER */
#define BRCT_NFT_PAYLOAD_OP_STORE	1	/* NFT_PAYLOAD_OP_STORE */

/* Latched per-child: userns_run_in_ns() reported -EPERM, meaning the
 * grandchild's unshare(CLONE_NEWUSER) was refused by a hardened policy
 * (user.max_user_namespaces=0 or kernel.unprivileged_userns_clone=0).
 * Without a private netns we MUST NOT touch the host's main routing
 * table or netfilter tables, so the op stays disabled for the
 * remainder of this child's lifetime.  Transient setup failures
 * (helper return -EAGAIN) do not set this — they may not recur on the
 * next iteration. */
static bool ns_unsupported;

/* Per-grandchild "lo up" setup latch lives in shm
 * (shm->bridge_conntrack_lo_up_done).  Write site sits inside the
 * userns_run_in_ns() grandchild body -- a process-local static would
 * die with the grandchild and every subsequent invocation would re-pay
 * the "lo up" rtnetlink round-trip.  RELAXED atomic load/store is
 * safe: only false -> true, idempotent write. */
static bool lo_up_done(void)
{
	return __atomic_load_n(&shm->bridge_conntrack_lo_up_done,
			       __ATOMIC_RELAXED);
}

static void mark_lo_up_done(void)
{
	__atomic_store_n(&shm->bridge_conntrack_lo_up_done, true,
			 __ATOMIC_RELAXED);
}

/* Per-subsystem config-absent gates live in shm
 * (shm->bridge_ct_churn_ns_unsupported_{bridge,nf_tables,ctnetlink}).
 * The write site is inside the userns_run_in_ns() grandchild -- a
 * process-local static would die with the grandchild on _exit() and
 * every subsequent invocation would re-attempt the same unsupported
 * RTM_NEWLINK / nf_tables NEWTABLE / ctnetlink FLUSH forever
 * (latch-in-grandchild bug).  Set when the corresponding subsystem
 * rejects with the CONFIG-absent errno set; persists fleet-wide via
 * shm so the unsupported attempt is paid once per fleet rather than
 * once per grandchild.  RELAXED atomic load/store from multiple
 * grandchildren is safe -- only false -> true, and the write is
 * idempotent. */

static bool ns_unsupported_bridge(void)
{
	return __atomic_load_n(&shm->bridge_ct_churn_ns_unsupported_bridge,
			       __ATOMIC_RELAXED);
}

static void mark_ns_unsupported_bridge(void)
{
	__atomic_store_n(&shm->bridge_ct_churn_ns_unsupported_bridge, true,
			 __ATOMIC_RELAXED);
}

static bool ns_unsupported_nf_tables(void)
{
	return __atomic_load_n(&shm->bridge_ct_churn_ns_unsupported_nf_tables,
			       __ATOMIC_RELAXED);
}

static void mark_ns_unsupported_nf_tables(void)
{
	__atomic_store_n(&shm->bridge_ct_churn_ns_unsupported_nf_tables, true,
			 __ATOMIC_RELAXED);
}

static bool ns_unsupported_ctnetlink(void)
{
	return __atomic_load_n(&shm->bridge_ct_churn_ns_unsupported_ctnetlink,
			       __ATOMIC_RELAXED);
}

static void mark_ns_unsupported_ctnetlink(void)
{
	__atomic_store_n(&shm->bridge_ct_churn_ns_unsupported_ctnetlink, true,
			 __ATOMIC_RELAXED);
}

/* Per-invocation state handed to the in-ns callback so it can keep
 * accounting against the right childop slot. */
struct bridge_conntrack_churn_ctx {
	struct childdata *child;
};

static size_t nla_put_be32(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, __u32 v)
{
	__u32 be = htonl(v);

	return nla_put(buf, off, cap, type, &be, sizeof(be));
}

static int rtnl_create_bridge(struct nl_ctx *rtnl, const char *name)
{
	unsigned char buf[BRCT_RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
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
	return nl_send_recv(rtnl, buf, off);
}

static int rtnl_create_veth(struct nl_ctx *rtnl, const char *a, const char *b)
{
	unsigned char buf[BRCT_RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi, *peer_ifi;
	size_t off, li_off, id_off, peer_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, a);
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
	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, b);
	if (!off)
		return -EIO;
	nla_nest_end(buf, peer_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

static int rtnl_setlink_master(struct nl_ctx *rtnl, int idx, int master)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = idx;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_MASTER, (__u32)master);
	if (!off)
		return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

/*
 * Build the full BATCH_BEGIN / NEWTABLE / NEWCHAIN / NEWRULE / BATCH_END
 * transaction and ship it as one sendmsg via nfnl_send_recv_batched().
 * Returns 0 on a clean end-of-batch, -errno on the first rejection.
 * The shared helper collapses sendmsg failures (EPERM/EOPNOTSUPP) into
 * -EIO so the caller's structural-latch checks won't fire from a local
 * send error — bridge / nf_tables availability is probed via the
 * NEWTABLE / NEWCHAIN rejection codes that come back through the
 * coalesced ack drain instead.
 */
static int nft_install_bridge_ct(struct nfnl_ctx *nf, const char *table,
				 const char *chain)
{
	unsigned char buf[BRCT_NFT_BUF_BYTES];
	size_t off = 0, hook_off, exprs_off, elem_off, expr_data_off;
	__u8 family = NFPROTO_BRIDGE;
	__u32 prio = (__u32)(NF_BR_PRI_CT_PRE - 1);

	memset(buf, 0, sizeof(buf));

	off = nfnl_batch_begin(buf, off, sizeof(buf),
			       nl_seq_next(&nf->nl), NFNL_SUBSYS_NFTABLES);
	if (!off)
		return -EIO;

	/* NEWTABLE */
	{
		size_t msg_off = off;

		off = nfnl_msg_put(buf, off, sizeof(buf), nl_seq_next(&nf->nl),
				   NFNL_SUBSYS_NFTABLES, BRCT_NFT_MSG_NEWTABLE,
				   NLM_F_CREATE, family);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_TABLE_NAME, table);
		if (!off)
			return -EIO;
		((struct nlmsghdr *)(buf + msg_off))->nlmsg_len =
			(__u32)(off - msg_off);
	}

	/* NEWCHAIN base, hook=PRE_ROUTING, priority=NF_BR_PRI_CT_PRE-1 */
	{
		size_t msg_off = off;

		off = nfnl_msg_put(buf, off, sizeof(buf), nl_seq_next(&nf->nl),
				   NFNL_SUBSYS_NFTABLES, BRCT_NFT_MSG_NEWCHAIN,
				   NLM_F_CREATE, family);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_CHAIN_TABLE, table);
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_CHAIN_NAME, chain);
		if (!off)
			return -EIO;
		hook_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_CHAIN_HOOK | NLA_F_NESTED);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_NFTA_HOOK_HOOKNUM, NF_BR_PRE_ROUTING);
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_NFTA_HOOK_PRIORITY, prio);
		if (!off)
			return -EIO;
		nla_nest_end(buf, hook_off, off);
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_CHAIN_TYPE, "filter");
		if (!off)
			return -EIO;
		((struct nlmsghdr *)(buf + msg_off))->nlmsg_len =
			(__u32)(off - msg_off);
	}

	/* NEWRULE: one nft_ct expression — drives nf_conntrack registration
	 * on the bridge family even though the rule's verdict path is unused. */
	{
		size_t msg_off = off;

		off = nfnl_msg_put(buf, off, sizeof(buf), nl_seq_next(&nf->nl),
				   NFNL_SUBSYS_NFTABLES, BRCT_NFT_MSG_NEWRULE,
				   NLM_F_CREATE | NLM_F_APPEND, family);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_RULE_TABLE, table);
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_RULE_CHAIN, chain);
		if (!off)
			return -EIO;
		exprs_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_RULE_EXPRESSIONS | NLA_F_NESTED);
		if (!off)
			return -EIO;
		elem_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_LIST_ELEM | NLA_F_NESTED);
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_EXPR_NAME, "ct");
		expr_data_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_EXPR_DATA | NLA_F_NESTED);
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_NFTA_CT_KEY, BRCT_NFT_CT_STATE);
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_NFTA_CT_DREG, BRCT_NFT_REG_1);
		if (!off)
			return -EIO;
		nla_nest_end(buf, expr_data_off, off);
		nla_nest_end(buf, elem_off, off);
		nla_nest_end(buf, exprs_off, off);
		((struct nlmsghdr *)(buf + msg_off))->nlmsg_len =
			(__u32)(off - msg_off);
	}

	off = nfnl_batch_end(buf, off, sizeof(buf),
			     nl_seq_next(&nf->nl), NFNL_SUBSYS_NFTABLES);
	if (!off)
		return -EIO;

	return nfnl_send_recv_batched(nf, buf, off);
}

/*
 * Install an intermediate-priority base chain "br_mangle" that rewrites
 * the IPv4 protocol byte (network-header offset 9) from IPPROTO_UDP to
 * IPPROTO_TCP via nft_payload SET, using an nft_immediate expression to
 * load the TCP value into NFT_REG32_00 first.
 *
 * Hook priority BRCT_NF_BR_PRI_MANGLE (-150) puts this chain AFTER the
 * bridge conntrack PRE hook (-200, which records nf_ct_protonum(ct)=UDP)
 * and BEFORE the ct-timeout eval chain (-100).  When the packet reaches
 * the ct-timeout chain, the kernel re-reads the IP protocol field and
 * sets pkt->tprot = IPPROTO_TCP.  The TCP timeout object (priv->l4proto
 * = TCP) then passes the old guard `priv->l4proto != pkt->tprot` but
 * fails the new guard `priv->l4proto != nf_ct_protonum(ct)` added by
 * Kyle Zeng's 2026-08-10 patch.  Without the fix the code proceeds to
 * index the TCP state array with a UDP conntrack entry, producing the
 * targeted OOB read.
 *
 * Caller must have already committed the br_ct NEWTABLE batch.
 * Returns 0 on batch acceptance; non-zero is a soft failure (the
 * ct-timeout install continues regardless).
 */
static int nft_install_ct_mangle(struct nfnl_ctx *nf, const char *table,
				  const char *mangle_chain)
{
	unsigned char buf[BRCT_NFT_BUF_BYTES];
	size_t off = 0;
	size_t msg_off, hook_off, exprs_off;
	size_t elem_off, expr_data_off, imm_data_off;
	__u8 family = NFPROTO_BRIDGE;
	__u32 prio = (__u32)(int)(BRCT_NF_BR_PRI_MANGLE);
	/* Four-byte immediate value: byte 0 = IPPROTO_TCP (6), rest zero.
	 * nft_payload_set_eval copies priv->len (1) bytes from the start
	 * of the register, so byte 0 must hold the protocol constant. */
	static const unsigned char tcp_proto_val[4] = {
		BRCT_IPPROTO_TCP, 0, 0, 0
	};

	memset(buf, 0, sizeof(buf));

	off = nfnl_batch_begin(buf, off, sizeof(buf),
			       nl_seq_next(&nf->nl), NFNL_SUBSYS_NFTABLES);
	if (!off)
		return -EIO;

	/* NEWCHAIN "br_mangle" at NF_BR_PRE_ROUTING priority -150.
	 * Fires after conntrack marks the packet UDP, before ct-timeout
	 * chain evaluates the TCP timeout object. */
	{
		msg_off = off;
		off = nfnl_msg_put(buf, off, sizeof(buf), nl_seq_next(&nf->nl),
				   NFNL_SUBSYS_NFTABLES, BRCT_NFT_MSG_NEWCHAIN,
				   NLM_F_CREATE, family);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_CHAIN_TABLE, table);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_CHAIN_NAME, mangle_chain);
		if (!off)
			return -EIO;
		hook_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_CHAIN_HOOK | NLA_F_NESTED);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_NFTA_HOOK_HOOKNUM, NF_BR_PRE_ROUTING);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_NFTA_HOOK_PRIORITY, prio);
		if (!off)
			return -EIO;
		nla_nest_end(buf, hook_off, off);
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_CHAIN_TYPE, "filter");
		if (!off)
			return -EIO;
		((struct nlmsghdr *)(buf + msg_off))->nlmsg_len =
			(__u32)(off - msg_off);
	}

	/* NEWRULE: two expressions -- immediate (IPPROTO_TCP -> reg0)
	 * then payload SET (reg0[0] -> network-header[9], len=1). */
	{
		msg_off = off;
		off = nfnl_msg_put(buf, off, sizeof(buf), nl_seq_next(&nf->nl),
				   NFNL_SUBSYS_NFTABLES, BRCT_NFT_MSG_NEWRULE,
				   NLM_F_CREATE | NLM_F_APPEND, family);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_RULE_TABLE, table);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_RULE_CHAIN, mangle_chain);
		if (!off)
			return -EIO;
		exprs_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_RULE_EXPRESSIONS | NLA_F_NESTED);
		if (!off)
			return -EIO;

		/* expr[0]: immediate -- dreg=NFT_REG32_00, value=6 */
		elem_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_LIST_ELEM | NLA_F_NESTED);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_EXPR_NAME, "immediate");
		if (!off)
			return -EIO;
		expr_data_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_EXPR_DATA | NLA_F_NESTED);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_NFTA_IMMEDIATE_DREG, BRCT_NFT_REG_1);
		if (!off)
			return -EIO;
		imm_data_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_IMMEDIATE_DATA | NLA_F_NESTED);
		if (!off)
			return -EIO;
		off = nla_put(buf, off, sizeof(buf),
			      BRCT_NFTA_DATA_VALUE,
			      tcp_proto_val, sizeof(tcp_proto_val));
		if (!off)
			return -EIO;
		nla_nest_end(buf, imm_data_off, off);
		nla_nest_end(buf, expr_data_off, off);
		nla_nest_end(buf, elem_off, off);

		/* expr[1]: payload SET -- sreg=reg0, base=NETWORK_HEADER,
		 * offset=9 (IPv4 proto field), len=1.  No checksum attrs:
		 * kernel defaults to NFT_PAYLOAD_CSUM_NONE, which is
		 * sufficient for synthetic traffic. */
		elem_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_LIST_ELEM | NLA_F_NESTED);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_EXPR_NAME, "payload");
		if (!off)
			return -EIO;
		expr_data_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_EXPR_DATA | NLA_F_NESTED);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_NFTA_PAYLOAD_OP,
				   BRCT_NFT_PAYLOAD_OP_STORE);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_NFTA_PAYLOAD_SREG, BRCT_NFT_REG_1);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_NFTA_PAYLOAD_BASE,
				   BRCT_NFT_PAYLOAD_NETWORK_HEADER);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_NFTA_PAYLOAD_OFFSET,
				   BRCT_IPV4_PROTO_OFFSET);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_NFTA_PAYLOAD_LEN, 1);
		if (!off)
			return -EIO;
		nla_nest_end(buf, expr_data_off, off);
		nla_nest_end(buf, elem_off, off);

		nla_nest_end(buf, exprs_off, off);
		((struct nlmsghdr *)(buf + msg_off))->nlmsg_len =
			(__u32)(off - msg_off);
	}

	off = nfnl_batch_end(buf, off, sizeof(buf),
			     nl_seq_next(&nf->nl), NFNL_SUBSYS_NFTABLES);
	if (!off)
		return -EIO;

	return nfnl_send_recv_batched(nf, buf, off);
}

/*
 * Install a CT_TIMEOUT named object (for TCP) in the pre-existing
 * br_ct table, then attach it to a hooked chain that runs after the
 * bridge conntrack PRE hook (priority NF_BR_PRI_CT_PRE + 100 = -100).
 * The objref IMM expression makes nft_ct_timeout_obj_eval() run on
 * every bridged packet that already has a conntrack entry.
 *
 * This exercises the code path targeted by Kyle Zeng's 2026-08-10 patch
 * (nft_ct: validate timeout object protocol against ct entry's l4proto).
 * The mismatch that triggers the OOB read requires a payload set to
 * rewrite pkt->tprot between conntrack and this chain; that arm is
 * tracked separately.  Without the mangle, the early
 * `priv->l4proto != pkt->tprot' guard will short-circuit for UDP
 * traffic, but the NEWOBJ + NEWCHAIN + NEWRULE install path is still
 * exercised end-to-end each invocation.
 *
 * Returns 0 when the batch is accepted; the caller treats non-zero
 * as a soft failure (the conntrack-flush burst runs regardless).
 */
static int nft_install_ct_timeout(struct nfnl_ctx *nf, const char *table,
				  const char *ct_chain, const char *obj_name)
{
	unsigned char buf[BRCT_NFT_BUF_BYTES];
	size_t off = 0;
	size_t msg_off, obj_data_off, l4_data_off;
	size_t hook_off, exprs_off, elem_off, expr_data_off;
	__u8 family = NFPROTO_BRIDGE;
	__u32 prio = (__u32)(int)(BRCT_NF_BR_PRI_AFTER_CT_PRE);
	__u8 l4proto = BRCT_IPPROTO_TCP;

	memset(buf, 0, sizeof(buf));

	off = nfnl_batch_begin(buf, off, sizeof(buf),
			       nl_seq_next(&nf->nl), NFNL_SUBSYS_NFTABLES);
	if (!off)
		return -EIO;

	/* NFT_MSG_NEWOBJ: CT_TIMEOUT for TCP.
	 * L4PROTO=IPPROTO_TCP lets nft_ct_timeout_obj_eval() reach the
	 * per-proto state-array access; NFTA_CT_TIMEOUT_DATA carries two
	 * representative TCP state timeouts (seconds, big-endian u32). */
	{
		msg_off = off;
		off = nfnl_msg_put(buf, off, sizeof(buf), nl_seq_next(&nf->nl),
				   NFNL_SUBSYS_NFTABLES, BRCT_NFT_MSG_NEWOBJ,
				   NLM_F_CREATE, family);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_OBJ_TABLE, table);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_OBJ_NAME, obj_name);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_NFTA_OBJ_TYPE, BRCT_NFT_OBJECT_CT_TIMEOUT);
		if (!off)
			return -EIO;
		obj_data_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_OBJ_DATA | NLA_F_NESTED);
		if (!off)
			return -EIO;
		off = nla_put_u8(buf, off, sizeof(buf),
				 BRCT_NFTA_CT_TIMEOUT_L4PROTO, l4proto);
		if (!off)
			return -EIO;
		l4_data_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_CT_TIMEOUT_DATA | NLA_F_NESTED);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_CTA_TIMEOUT_TCP_SYN_SENT, 120);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_CTA_TIMEOUT_TCP_ESTABLISHED, 432000);
		if (!off)
			return -EIO;
		nla_nest_end(buf, l4_data_off, off);
		nla_nest_end(buf, obj_data_off, off);
		((struct nlmsghdr *)(buf + msg_off))->nlmsg_len =
			(__u32)(off - msg_off);
	}

	/* NFT_MSG_NEWCHAIN: base chain on NF_BR_PRE_ROUTING at priority
	 * BRCT_NF_BR_PRI_AFTER_CT_PRE (-100), which fires after the
	 * kernel bridge conntrack PRE hook (-200).  Traffic that crosses
	 * this hook therefore already has a conntrack entry. */
	{
		msg_off = off;
		off = nfnl_msg_put(buf, off, sizeof(buf), nl_seq_next(&nf->nl),
				   NFNL_SUBSYS_NFTABLES, BRCT_NFT_MSG_NEWCHAIN,
				   NLM_F_CREATE, family);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_CHAIN_TABLE, table);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_CHAIN_NAME, ct_chain);
		if (!off)
			return -EIO;
		hook_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_CHAIN_HOOK | NLA_F_NESTED);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_NFTA_HOOK_HOOKNUM, NF_BR_PRE_ROUTING);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_NFTA_HOOK_PRIORITY, prio);
		if (!off)
			return -EIO;
		nla_nest_end(buf, hook_off, off);
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_CHAIN_TYPE, "filter");
		if (!off)
			return -EIO;
		((struct nlmsghdr *)(buf + msg_off))->nlmsg_len =
			(__u32)(off - msg_off);
	}

	/* NFT_MSG_NEWRULE: objref IMM expression referencing the
	 * CT_TIMEOUT object.  nft_objref with IMM mode calls
	 * nft_obj_lookup() then nft_ct_timeout_obj_eval() on each skb
	 * that reaches this chain with a non-confirmed conntrack entry. */
	{
		msg_off = off;
		off = nfnl_msg_put(buf, off, sizeof(buf), nl_seq_next(&nf->nl),
				   NFNL_SUBSYS_NFTABLES, BRCT_NFT_MSG_NEWRULE,
				   NLM_F_CREATE | NLM_F_APPEND, family);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_RULE_TABLE, table);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_RULE_CHAIN, ct_chain);
		if (!off)
			return -EIO;
		exprs_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_RULE_EXPRESSIONS | NLA_F_NESTED);
		if (!off)
			return -EIO;
		elem_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_LIST_ELEM | NLA_F_NESTED);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_EXPR_NAME, "objref");
		if (!off)
			return -EIO;
		expr_data_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BRCT_NFTA_EXPR_DATA | NLA_F_NESTED);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   BRCT_NFTA_OBJREF_IMM_TYPE,
				   BRCT_NFT_OBJECT_CT_TIMEOUT);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BRCT_NFTA_OBJREF_IMM_NAME, obj_name);
		if (!off)
			return -EIO;
		nla_nest_end(buf, expr_data_off, off);
		nla_nest_end(buf, elem_off, off);
		nla_nest_end(buf, exprs_off, off);
		((struct nlmsghdr *)(buf + msg_off))->nlmsg_len =
			(__u32)(off - msg_off);
	}

	off = nfnl_batch_end(buf, off, sizeof(buf),
			     nl_seq_next(&nf->nl), NFNL_SUBSYS_NFTABLES);
	if (!off)
		return -EIO;

	return nfnl_send_recv_batched(nf, buf, off);
}

/*
 * Best-effort IPCTNL_MSG_CT_FLUSH.  nfnl_send_recv_dump() tolerates the
 * EAGAIN-on-drain that a kernel without CONFIG_NF_CONNTRACK produces by
 * collapsing it to -EIO, which the caller treats the same as any other
 * structural failure.  Successful flushes return 0 once NLMSG_DONE
 * arrives.
 */
static int ctnetlink_flush(struct nfnl_ctx *nf)
{
	unsigned char buf[256];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&nf->nl),
			   NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_FLUSH,
			   0, AF_INET);
	if (!off)
		return -EIO;
	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv_dump(nf, buf, off);
}

struct sender_args {
	int		raw_fd;
	int		ifindex;
	unsigned char	dst_mac[6];
	struct timespec	t0;
	/* Direct-syscall tally accumulated inside brct_packet_sender.
	 * Written by the sender thread and read by the main thread after
	 * pthread_join() completes -- the join provides the necessary
	 * happens-before edge so no atomic is required.  Bumped once per
	 * sendto() attempt (not per success) since even ENOBUFS / EMSGSIZE
	 * returns paid the syscall entry. */
	unsigned long	direct_syscalls;
};

/* Per-invocation state shared across the extracted phase helpers.  Fd
 * fields default to -1 via the orchestrator's designated initialiser
 * so the teardown helper can close them unconditionally regardless of
 * which earlier phase bailed.  Name buffers are filled in by
 * setup_names; ifindex/bridge_added/veth_added by bridge_create and
 * veth_attach; raw/sa/tid/sender_started by traffic_burst. */
struct bridge_conntrack_iter_ctx {
	char			br_name[IFNAMSIZ];
	char			veth_a[IFNAMSIZ];
	char			veth_b[IFNAMSIZ];
	struct nl_ctx		rtnl;
	struct nfnl_ctx		nfnl_nft;
	struct nfnl_ctx		nfnl_ct;
	struct sender_args	sa;
	pthread_t		tid;
	int			raw;
	int			br_idx;
	int			va_idx;
	int			vb_idx;
	bool			bridge_added;
	bool			veth_added;
	bool			sender_started;
	struct childdata	*child;
	/* Direct-syscall tally for non-netlink raw syscalls: each
	 * nl_send_recv wrapper (rtnl_create_bridge / rtnl_setlink_up /
	 * rtnl_dellink / ...) == 2 (sendmsg + recv), each
	 * nfnl_send_recv_batched / _dump == 3 (sendmsg + blocking recv +
	 * one MSG_DONTWAIT drain recv), each AF_PACKET socket / bind /
	 * close == 1, each recv() in the drain loop == 1.  The pthread
	 * sender's tally is folded in from ctx->sa.direct_syscalls after
	 * pthread_join().  Netlink transport syscalls (socket + bind +
	 * setsockopt from nl_open / nfnl_open, close from nl_close /
	 * nfnl_close) are tracked internally by each nl_ctx and published
	 * automatically by nl_close() via caller_op.  Published once in
	 * bridge_conntrack_churn_in_ns() via childop_direct_syscalls_add()
	 * so the hot path pays one atomic add per invocation instead of
	 * per-syscall.  Setup-latched short-circuit paths publish whatever
	 * they issued before bailing, which correctly attributes no data-
	 * path work to those exits. */
	unsigned long		direct_syscalls;
};

static long brct_ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (now.tv_sec - t0->tv_sec) * 1000000000L +
	       (now.tv_nsec - t0->tv_nsec);
}

static void *brct_packet_sender(void *arg)
{
	struct sender_args *a = arg;
	unsigned long calls = 0;
	unsigned int i;

	for (i = 0; i < BRCT_PACKET_CAP; i++) {
		struct sockaddr_ll sll;
		unsigned char frame[64];
		unsigned char src_mac[6];

		if (brct_ns_since(&a->t0) >= BRCT_BUDGET_NS)
			break;

		generate_rand_bytes(src_mac, 6);
		src_mac[0] = (unsigned char)((src_mac[0] & 0xfc) | 0x02);

		memset(frame, 0, sizeof(frame));
		memcpy(frame +  0, a->dst_mac, 6);
		memcpy(frame +  6, src_mac, 6);
		frame[12] = 0x08;	/* ETH_P_IP */
		frame[13] = 0x00;
		/* Minimal IPv4+UDP header so the bridge ct hook sees a
		 * parseable L4 tuple to insert into the conntrack table. */
		frame[14] = 0x45;	/* IPv4, ihl=5 */
		frame[16] = 0x00; frame[17] = 0x2c;	/* tot_len = 44 */
		frame[22] = 0x40;	/* ttl */
		frame[23] = 0x11;	/* IPPROTO_UDP */
		frame[26] = 10; frame[27] = 0;
		/* source address rotates every 4 iters so each flow sees >=2 packets;
		 * required for ct-timeout probes that need the L4 handler invoked post-attach */
		frame[28] = 0; frame[29] = (unsigned char)((i / 4) & 0xff);
		frame[30] = 10; frame[31] = 0;
		frame[32] = 0; frame[33] = 1;
		frame[34] = 0x30; frame[35] = 0x39;	/* sport 12345 */
		frame[36] = 0x30; frame[37] = 0x3a;	/* dport 12346 */
		frame[38] = 0x00; frame[39] = 0x10;	/* len = 16 */

		memset(&sll, 0, sizeof(sll));
		sll.sll_family   = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_IP);
		sll.sll_ifindex  = a->ifindex;
		sll.sll_halen    = 6;
		memcpy(sll.sll_addr, a->dst_mac, 6);

		/* sendto(): one raw kernel call per attempt (not per success)
		 * since even ENOBUFS / EMSGSIZE returns paid the syscall
		 * entry. */
		calls++;
		if (sendto(a->raw_fd, frame, sizeof(frame), MSG_DONTWAIT,
			   (struct sockaddr *)&sll, sizeof(sll)) > 0)
			__atomic_add_fetch(&shm->stats.bridge_ct.pkts_sent,
					   1, __ATOMIC_RELAXED);
	}
	a->direct_syscalls = calls;
	return NULL;
}

/*
 * Phase 1: pick the per-invocation interface names and bring the
 * iteration's rtnl context online.  Names are derived from a single
 * 16-bit random suffix so the three interfaces share a stable
 * correlator inside the netns.  The rtnl socket is opened here because
 * every subsequent phase needs it (bridge_create, veth_attach,
 * teardown).  lo is brought up exactly once per process via the
 * lo_up_done latch — first call only, subsequent invocations skip the
 * RTM_NEWLINK round trip.  Returns 0 on success or -1 if the iteration
 * should bail to the out: cleanup path.
 */
static int bridge_conntrack_iter_setup_names(struct bridge_conntrack_iter_ctx *ctx)
{
	struct nl_open_opts rtnl_opts = {
		.proto         = NETLINK_ROUTE,
		.recv_timeo_s  = 1,
		.caller_op     = CHILD_OP_BRIDGE_CT_CHURN,
	};
	unsigned int rng;

	if (nl_open(&ctx->rtnl, &rtnl_opts) < 0)
		return -1;
	if (!lo_up_done()) {
		rtnl_bring_lo_up(&ctx->rtnl);
		/* rtnl_bring_lo_up wraps one nl_send_recv (sendmsg + recv)
		 * when the lo lookup succeeds; the if_nametoindex libc probe
		 * stays unattributed to match the surrounding per-childop
		 * convention. */
		ctx->direct_syscalls += 2;
		mark_lo_up_done();
	}

	rng = (unsigned int)(rand32() & 0xffffu);
	snprintf(ctx->br_name, sizeof(ctx->br_name), "trbc%u", rng);
	snprintf(ctx->veth_a,  sizeof(ctx->veth_a),  "trbcv%ua", rng);
	snprintf(ctx->veth_b,  sizeof(ctx->veth_b),  "trbcv%ub", rng);
	return 0;
}

/*
 * Phase 2: create the bridge link and capture its ifindex.  Latches
 * ns_unsupported_bridge on the family/proto rejection codes the
 * rtnetlink layer returns when the bridge module isn't present, so
 * siblings stop probing.  The if_nametoindex call is treated as part
 * of the same phase because losing the index makes every later step a
 * no-op.  Returns 0 on success or -1 if the iteration should bail to
 * the out: cleanup path; on success ctx->bridge_added is set so the
 * teardown helper knows to RTM_DELLINK it.
 */
static int bridge_conntrack_iter_bridge_create(struct bridge_conntrack_iter_ctx *ctx)
{
	int rc;

	/* Snapshot ctx->child->op_type once and bounds-check before
	 * indexing the per-op latch slot.  The field lives in shared
	 * memory and can be scribbled by a poisoned-arena write from a
	 * sibling; the child.c dispatch loop already gates its dispatch
	 * + alt-op accounting on the same valid_op snapshot.  Skip the
	 * latch store entirely when the snapshot is out of range. */
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	rc = rtnl_create_bridge(&ctx->rtnl, ctx->br_name);
	/* rtnl_create_bridge wraps one nl_send_recv (sendmsg + recv). */
	ctx->direct_syscalls += 2;
	if (rc != 0) {
		if (rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -ENOTSUP || rc == -EPROTONOSUPPORT) {
			mark_ns_unsupported_bridge();
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return -1;
	}
	ctx->bridge_added = true;
	ctx->br_idx = (int)if_nametoindex(ctx->br_name);
	if (ctx->br_idx <= 0)
		return -1;

	/* Kernel confirmed ctx->br_name now names a real device; publish it
	 * via the NETDEV name pool so sibling childops (and per-syscall
	 * fuzzers drawing this kind) can reference it on subsequent
	 * invocations -- exercises SO_BINDTODEVICE / dev_get_by_name HIT
	 * paths instead of always-fresh-random ENODEV space.  Only the
	 * primary bridge is recorded; the veth leaves are deliberately
	 * skipped to keep the 16-slot per-kind ring from thrashing. */
	name_pool_record(NAME_KIND_NETDEV, ctx->br_name, strlen(ctx->br_name));
	return 0;
}

/*
 * Phase 3: create the veth pair, enslave the bridge-side end, and
 * bring all three interfaces up.  The setlink_master / setlink_up
 * calls are best-effort by design (they were (void)-casts in the
 * original) — a missing slave-master link still leaves the ct hook
 * reachable on the bridge ingress; the failure shape just changes the
 * traffic-burst coverage rather than aborting the iteration.  Returns
 * 0 on success or -1 if the iteration should bail to the out: cleanup
 * path; on success ctx->veth_added is set so the teardown helper
 * knows to RTM_DELLINK the survivor.
 */
static int bridge_conntrack_iter_veth_attach(struct bridge_conntrack_iter_ctx *ctx)
{
	int rc = rtnl_create_veth(&ctx->rtnl, ctx->veth_a, ctx->veth_b);
	/* rtnl_create_veth wraps one nl_send_recv (sendmsg + recv). */
	ctx->direct_syscalls += 2;
	if (rc != 0)
		return -1;
	ctx->veth_added = true;
	ctx->va_idx = (int)if_nametoindex(ctx->veth_a);
	ctx->vb_idx = (int)if_nametoindex(ctx->veth_b);
	if (ctx->va_idx <= 0 || ctx->vb_idx <= 0)
		return -1;

	(void)rtnl_setlink_master(&ctx->rtnl, ctx->va_idx, ctx->br_idx);
	(void)rtnl_setlink_up(&ctx->rtnl, ctx->br_idx);
	(void)rtnl_setlink_up(&ctx->rtnl, ctx->va_idx);
	(void)rtnl_setlink_up(&ctx->rtnl, ctx->vb_idx);
	/* Four nl_send_recv wrappers: setlink_master + 3x setlink_up.
	 * Each is sendmsg + recv. */
	ctx->direct_syscalls += 8;
	return 0;
}

/*
 * Phase 4: open the nf_tables nfnl socket and install the bridge-family
 * ct table/chain/rule transaction.  The NEWTABLE/NEWCHAIN/NEWRULE
 * batch drives nf_conntrack registration on NFPROTO_BRIDGE — the
 * required precondition for the ctnetlink flush in the next phase to
 * actually race against bridge ct state.  Latches
 * ns_unsupported_nf_tables on family/proto rejection codes so siblings
 * stop probing.  Returns -1 if the nfnl_open itself fails (iteration
 * bails) or 0 otherwise — a nft_install rejection is not a hard
 * failure: the packet/flush burst still runs because the kernel may
 * accept ctnetlink even when nf_tables is gated.
 */
static int bridge_conntrack_iter_nft_setup(struct bridge_conntrack_iter_ctx *ctx)
{
	struct nfnl_open_opts nfnl_opts = {
		.recv_timeo_s  = 1,
	};
	int rc;

	/* Snapshot ctx->child->op_type once and bounds-check before
	 * indexing the per-op latch slot.  The field lives in shared
	 * memory and can be scribbled by a poisoned-arena write from a
	 * sibling; the child.c dispatch loop already gates its dispatch
	 * + alt-op accounting on the same valid_op snapshot.  Skip the
	 * latch store entirely when the snapshot is out of range. */
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (nfnl_open(&ctx->nfnl_nft, &nfnl_opts) < 0)
		return -1;
	/* Set caller_op so nfnl_close() -> nl_close() auto-publishes the
	 * netlink transport syscalls (socket + bind + setsockopt from
	 * nfnl_open, all send/recv calls, close from nfnl_close). */
	ctx->nfnl_nft.nl.caller_op = CHILD_OP_BRIDGE_CT_CHURN;
	rc = nft_install_bridge_ct(&ctx->nfnl_nft, "br_ct", "in");
	/* nft_install_bridge_ct wraps one nfnl_send_recv_batched: one
	 * sendmsg for the coalesced batch + one blocking recv + one
	 * MSG_DONTWAIT drain recv that typically returns EAGAIN. */
	ctx->direct_syscalls += 3;
	if (rc == -EAFNOSUPPORT || rc == -EPROTONOSUPPORT ||
	    rc == -EOPNOTSUPP || rc == -ENOTSUP) {
		mark_ns_unsupported_nf_tables();
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return 0;
	}

	/* Install the proto-mangle chain (priority -150): rewrites IPv4
	 * proto byte from UDP → TCP between the conntrack PRE hook and
	 * the ct-timeout eval chain.  Best-effort; a soft failure means
	 * the mismatch arm won't fire this iteration but the remaining
	 * ct-timeout install still runs.  Two nfnl_send_recv_batched
	 * calls total (mangle batch + ct-timeout batch), each
	 * sendmsg + recv + drain recv. */
	if (nft_install_ct_mangle(&ctx->nfnl_nft, "br_ct", "br_mangle") == 0)
		__atomic_add_fetch(&shm->stats.bridge_ct.ct_mangle_ok,
				   1, __ATOMIC_RELAXED);
	ctx->direct_syscalls += 3;

	/* Install the CT_TIMEOUT object + post-conntrack chain + objref
	 * rule.  Best-effort: a rejection (e.g. CONFIG_NFT_CT=n) does
	 * not abort the iteration - the conntrack-flush burst runs
	 * regardless and the original NEWTABLE/NEWCHAIN/NEWRULE batch
	 * has already committed.  Count as a separate
	 * nfnl_send_recv_batched call (sendmsg + recv + drain recv). */
	if (nft_install_ct_timeout(&ctx->nfnl_nft,
				   "br_ct", "ct_to", "ct_tmo") == 0)
		__atomic_add_fetch(&shm->stats.bridge_ct.ct_timeout_obj_ok,
				   1, __ATOMIC_RELAXED);
	ctx->direct_syscalls += 3;
	return 0;
}

/*
 * Phase 5: spin up the AF_PACKET sender on v1, open the ctnetlink
 * socket, and race a bounded burst of IPCTNL_MSG_CT_FLUSH against the
 * in-flight bridge traffic.  Each I/O side has its own wall-cap: the
 * sender thread bounds itself via BRCT_BUDGET_NS in brct_packet_sender,
 * and the flush loop's local t0 holds the main thread to the same
 * budget so the join below can't outlive child.c's SIGALRM(1s) cap.
 * Raw socket / nfnl_ct open failures degrade gracefully — neither is
 * the targeted race window on its own, so a missing half just yields
 * fewer concurrent stimuli rather than aborting the iteration.
 */
static void bridge_conntrack_iter_traffic_burst(struct bridge_conntrack_iter_ctx *ctx)
{
	struct nfnl_open_opts nfnl_opts = {
		.recv_timeo_s  = 1,
	};
	unsigned int iters, i;
	int rc;

	/* Snapshot ctx->child->op_type once and bounds-check before
	 * indexing the per-op latch slot.  The field lives in shared
	 * memory and can be scribbled by a poisoned-arena write from a
	 * sibling; the child.c dispatch loop already gates its dispatch
	 * + alt-op accounting on the same valid_op snapshot.  Skip the
	 * latch store entirely when the snapshot is out of range. */
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	ctx->raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
	/* socket() is a raw kernel call, counted whether it succeeds or
	 * not since the syscall entry ran either way. */
	ctx->direct_syscalls += 1;
	if (ctx->raw >= 0) {
		struct sockaddr_ll bind_sll;

		memset(&bind_sll, 0, sizeof(bind_sll));
		bind_sll.sll_family   = AF_PACKET;
		bind_sll.sll_protocol = htons(ETH_P_ALL);
		bind_sll.sll_ifindex  = ctx->vb_idx;
		(void)bind(ctx->raw, (struct sockaddr *)&bind_sll,
			   sizeof(bind_sll));
		/* bind() is a raw kernel call. */
		ctx->direct_syscalls += 1;

		memset(&ctx->sa, 0, sizeof(ctx->sa));
		ctx->sa.raw_fd  = ctx->raw;
		ctx->sa.ifindex = ctx->vb_idx;
		/* Send to v0's MAC; we don't know it cheaply, so use the
		 * broadcast — bridge floods on unknown unicast / broadcast
		 * and the ct hook sees the frame either way. */
		memset(ctx->sa.dst_mac, 0xff, sizeof(ctx->sa.dst_mac));
		(void)clock_gettime(CLOCK_MONOTONIC, &ctx->sa.t0);
		if (pthread_create(&ctx->tid, NULL, brct_packet_sender,
				   &ctx->sa) == 0)
			ctx->sender_started = true;
	}

	if (nfnl_open(&ctx->nfnl_ct, &nfnl_opts) == 0) {
		struct timespec t0;

		/* Set caller_op so nfnl_close() -> nl_close() auto-publishes
		 * the netlink transport syscalls (socket + bind + setsockopt
		 * from nfnl_open, all send/recv calls, close from nfnl_close). */
		ctx->nfnl_ct.nl.caller_op = CHILD_OP_BRIDGE_CT_CHURN;

		(void)clock_gettime(CLOCK_MONOTONIC, &t0);
		iters = BUDGETED(CHILD_OP_BRIDGE_CT_CHURN,
				 JITTER_RANGE(BRCT_FLUSH_BASE));
		if (iters < 1)
			iters = 1;
		if (iters > BRCT_FLUSH_CAP)
			iters = BRCT_FLUSH_CAP;

		for (i = 0; i < iters; i++) {
			if (brct_ns_since(&t0) >= BRCT_BUDGET_NS)
				break;
			rc = ctnetlink_flush(&ctx->nfnl_ct);
			/* ctnetlink_flush wraps one nfnl_send_recv_dump:
			 * one sendmsg + one blocking recv + one MSG_DONTWAIT
			 * drain recv (typically returns 0 or EAGAIN since a
			 * fresh netns has no confirmed tuples to stream). */
			ctx->direct_syscalls += 3;
			if (rc == -EAFNOSUPPORT || rc == -EPROTONOSUPPORT ||
			    rc == -EOPNOTSUPP || rc == -ENOTSUP) {
				mark_ns_unsupported_ctnetlink();
				if (valid_op)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_NS_UNSUPPORTED,
							 __ATOMIC_RELAXED);
				break;
			}
			__atomic_add_fetch(&shm->stats.bridge_ct.flushes,
					   1, __ATOMIC_RELAXED);
		}
	}

	if (ctx->sender_started) {
		(void)pthread_join(ctx->tid, NULL);
		/* pthread_join provides the happens-before edge so the
		 * sender's final ctx->sa.direct_syscalls store is visible
		 * here without any explicit atomic barrier. */
		ctx->direct_syscalls += ctx->sa.direct_syscalls;
	}
}

/*
 * Phase 6: close whichever resources we managed to open.  Runs on
 * every exit path — both the success path after traffic_burst returns
 * and any early-bail goto out from an earlier phase.  Order matches
 * the original out: cleanup: drain + close the raw fd first (any
 * received packets buffered there get discarded), then both nfnl
 * contexts, then the rtnl-side dellinks before closing rtnl itself.
 * The bridge dellink cascades v0; v1 (the survivor) is removed
 * explicitly.  All fields default to -1 / false via the orchestrator's
 * designated initialiser so the guards skip work that was never set
 * up.
 */
static void bridge_conntrack_iter_teardown(struct bridge_conntrack_iter_ctx *ctx)
{
	if (ctx->raw >= 0) {
		unsigned char drain[256];

		while (recv(ctx->raw, drain, sizeof(drain), MSG_DONTWAIT) > 0)
			/* Each successful drain recv is a raw kernel call;
			 * the terminating EAGAIN return also paid a syscall
			 * entry, so count one per loop iteration. */
			ctx->direct_syscalls += 1;
		/* Terminating EAGAIN / EOF recv still paid the syscall
		 * entry. */
		ctx->direct_syscalls += 1;
		close(ctx->raw);
		/* close() is a raw kernel call. */
		ctx->direct_syscalls += 1;
	}
	/* nfnl_close wraps nl_close: caller_op is set on each nfnl_ct and
	 * nfnl_nft context so nl_close() auto-publishes their transport
	 * syscalls (including close()).  No manual tally needed here. */
	nfnl_close(&ctx->nfnl_ct);
	nfnl_close(&ctx->nfnl_nft);
	if (ctx->rtnl.fd >= 0) {
		if (ctx->bridge_added && ctx->br_idx > 0) {
			(void)rtnl_dellink(&ctx->rtnl, ctx->br_idx);
			/* rtnl_dellink wraps one nl_send_recv (sendmsg +
			 * recv). */
			ctx->direct_syscalls += 2;
		}
		if (ctx->veth_added && ctx->vb_idx > 0) {
			(void)rtnl_dellink(&ctx->rtnl, ctx->vb_idx);
			/* rtnl_dellink wraps one nl_send_recv (sendmsg +
			 * recv). */
			ctx->direct_syscalls += 2;
		}
		/* nl_close auto-publishes via caller_op = CHILD_OP_BRIDGE_CT_CHURN;
		 * close() is included in the nl_ctx direct_syscalls tally. */
		nl_close(&ctx->rtnl);
	}
}

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any links,
 * addrs, rules, hooks and sockets left behind are reaped by the kernel
 * along with the namespace.  Return value is ignored by the helper.
 */
static int bridge_conntrack_churn_in_ns(void *arg)
{
	struct bridge_conntrack_churn_ctx *cctx =
		(struct bridge_conntrack_churn_ctx *)arg;
	struct childdata *child = cctx->child;
	struct bridge_conntrack_iter_ctx ctx = {
		.rtnl     = { .fd = -1 },
		.nfnl_nft = { .nl = { .fd = -1 } },
		.nfnl_ct  = { .nl = { .fd = -1 } },
		.raw      = -1,
		.child    = child,
	};

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (bridge_conntrack_iter_setup_names(&ctx) != 0)
		goto out;

	if (bridge_conntrack_iter_bridge_create(&ctx) != 0)
		goto out;

	if (bridge_conntrack_iter_veth_attach(&ctx) != 0)
		goto out;

	if (bridge_conntrack_iter_nft_setup(&ctx) != 0)
		goto out;
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	bridge_conntrack_iter_traffic_burst(&ctx);

out:
	bridge_conntrack_iter_teardown(&ctx);

	/* Publish this invocation's non-netlink direct-syscall load in ONE
	 * RELAXED atomic add.  ctx.direct_syscalls covers nl_send_recv
	 * wrappers (rtnl_create_bridge / rtnl_setlink_* / rtnl_dellink /
	 * nft_install / ctnetlink_flush), the AF_PACKET socket / bind /
	 * close, the raw-socket drain recvs, and the pthread sender's
	 * sendto tally (folded in from ctx.sa.direct_syscalls after
	 * pthread_join).  Netlink open / close syscalls (socket + bind +
	 * setsockopt + close) are published automatically by nl_close() /
	 * nfnl_close() via caller_op = CHILD_OP_BRIDGE_CT_CHURN set on
	 * each nl_ctx.  The grandchild's write on the shm slot is visible
	 * to the parent after _exit() because shm is a shared mapping.
	 * Gated on valid_op to match the surrounding per-op stats bumps. */
	if (valid_op)
		childop_direct_syscalls_add(op, ctx.direct_syscalls);
	return 0;
}

bool bridge_conntrack_churn(struct childdata *child)
{
	struct bridge_conntrack_churn_ctx cctx = { .child = child };
	int rc;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op latch slot.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the latch
	 * store entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.bridge_ct.runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported || ns_unsupported_bridge() ||
	    ns_unsupported_nf_tables() || ns_unsupported_ctnetlink())
		return true;

	if (!ONE_IN(8))
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, bridge_conntrack_churn_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without latching
		 * — the failure is not policy and may not recur. */
		return true;
	}

	return true;
}
