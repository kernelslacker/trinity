/*
 * nftables_churn - nftables table/chain/set/rule churn racing live traffic.
 *
 * Per-syscall fuzzing rolls a fresh NFT_MSG_* per call and never gets
 * past nf_tables_api's per-message lookup gates: NEWCHAIN demands an
 * existing table, NEWRULE demands an existing chain, DELRULE demands
 * a chain that has rules.  The interesting bug surface lives in the
 * transaction-commit path (nf_tables_commit / nft_chain_commit_drop_policy
 * / nft_rule_destroy / nft_set_destroy), where the rule/set/chain has
 * to actually have references — live verdicts pointing at it, an
 * ongoing lookup walking it, an in-flight skb traversing the hook
 * while the commit tears it down.  Without a coherent table -> chain
 * -> rule chain plus traffic into the registered hook, the whole
 * commit machinery never engages and the recent CVE-class window
 * (CVE-2024-1086 nft_verdict UAF, CVE-2023-32233 anonymous-set
 * double-free, CVE-2024-26642 nft_setelem, CVE-2024-26581
 * nft_set_rbtree, CVE-2023-3390 nft_chain) stays cold.
 *
 * Sequence (per invocation):
 *   1. unshare(CLONE_NEWNET) once per child into a private net
 *      namespace so no host nftables ruleset is touched.  Failure
 *      latches the whole op off.
 *   2. Bring lo up inside the netns (one-time).
 *   3. socket(AF_NETLINK, NETLINK_NETFILTER).  EPROTONOSUPPORT here
 *      means CONFIG_NF_NETLINK is off — latch ns_unsupported_nfnetlink
 *      and skip permanently.
 *   4. NFT_MSG_NEWTABLE with a random nf_tables family chosen from
 *      {NFPROTO_INET, NFPROTO_BRIDGE, NFPROTO_NETDEV} per call.  The
 *      family is rolled per-iteration so the commit path runs against
 *      different per-family afinfo registrations, not just one.
 *      EOPNOTSUPP / EAFNOSUPPORT / EPROTONOSUPPORT all latch
 *      ns_unsupported_nf_tables — the kernel's nf_tables module is
 *      unavailable, no point retrying.
 *   5. NFT_MSG_NEWSET creating an anonymous (NFT_SET_ANONYMOUS) +
 *      dynamic (NFT_SET_DYNAMIC) set keyed on ipv4_addr (key_len = 4).
 *      The anonymous flag is what the CVE-2023-32233 double-free
 *      window hangs off — anonymous sets are tied to the rule that
 *      owns them and torn down on rule removal, with a refcount
 *      arrangement that historically races commit vs abort.
 *   6. NFT_MSG_NEWCHAIN creating an auxiliary regular (no-hook) chain
 *      "chain_aux" — the jump target referenced by the rule's verdict
 *      in step 8.  Created before the base chain so the base-chain
 *      rule's NFT_JUMP/NFT_GOTO can bind successfully on first commit.
 *   7. NFT_MSG_NEWCHAIN creating a base chain "chain_in" with
 *      hook=NF_INET_LOCAL_IN, prio=0, type="filter".  This is the
 *      chain the loopback traffic in step 9 will traverse.
 *   8. NFT_MSG_NEWRULE on chain_in carrying one immediate-verdict
 *      expression: dreg=NFT_REG_VERDICT, code in {NFT_JUMP, NFT_GOTO}
 *      (rolled per call), chain="chain_aux".  A jumping verdict is
 *      what arms the nft_verdict UAF window the CVE-2024-1086 lineage
 *      lives in.
 *   9. socket(AF_INET, SOCK_DGRAM); sendto a small payload to
 *      127.0.0.1:NFT_INNER_PORT inside the netns.  Drives the input
 *      hook via nf_hook_slow on the receive side, walking the freshly
 *      installed chain_in -> chain_aux jump.  BUDGETED+JITTER around
 *      base 3 with a STORM_BUDGET_NS 200 ms wall-clock cap and a
 *      64-frame upper limit on the inner send loop.
 *  10. NFT_MSG_NEWRULE inserted at NFTA_RULE_POSITION = 1 (small
 *      handle guess) on chain_in, mid-traffic.  The position-based
 *      insert path is a different commit-time codepath from the
 *      append-only path in step 8 and historically has its own
 *      reference-count windows.
 *  11. NFT_MSG_DELRULE on chain_in with no NFTA_RULE_HANDLE — kernel
 *      treats this as "delete every rule in chain_in", racing any
 *      in-flight skb from step 9 still draining through softirq.
 *      This is the targeted commit-vs-traffic teardown window.
 *  12. NFT_MSG_DELSET on the anonymous set, then NFT_MSG_DELTABLE on
 *      the table.  DELTABLE cascades cleanup of any chain/rule/set
 *      survivors via nf_tables_table_destroy, racing the same
 *      in-flight skbs.
 *
 * CVE class: CVE-2024-1086 nft_verdict use-after-free (in-the-wild
 * LPE), CVE-2023-32233 anonymous set double-free, CVE-2024-26642
 * nft_setelem ref window, CVE-2024-26581 nft_set_rbtree race,
 * CVE-2023-3390 nft_chain reference window — the most CVE-productive
 * subsystem in the kernel for the last 24 months.  Subsystems reached:
 * net/netfilter/nf_tables_api.c, net/netfilter/nft_immediate.c,
 * net/netfilter/nft_set_*.c, net/netfilter/nf_tables_offload.c,
 * net/netfilter/core.c (nf_hook_slow).
 *
 * Self-bounding: one full create/destroy cycle per invocation, packet
 * burst count BUDGETED+JITTER around base 3 with a STORM_BUDGET_NS
 * 200 ms wall-clock cap and a 64-frame ceiling on the inner send
 * loop.  All netlink and socket I/O is MSG_DONTWAIT, SO_RCVTIMEO=1s
 * on the netfilter ack socket, so an unresponsive kernel can't wedge
 * us past the SIGALRM(1s) cap inherited from child.c.  Loopback only
 * (private netns).  Three latches so a kernel without
 * CONFIG_NF_NETLINK / CONFIG_NF_TABLES / CONFIG_INET pays the EFAIL
 * once and skips that path permanently.
 */

#if __has_include(<linux/netfilter/nf_tables.h>)
#include <linux/netfilter/nf_tables.h>
#endif
#if __has_include(<linux/netfilter/nfnetlink.h>)
#include <linux/netfilter/nfnetlink.h>
#endif

#include <errno.h>
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
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/*
 * UAPI fallbacks.  The header on stripped sysroots may not have
 * nf_tables.h / nfnetlink.h at all — we still want to compile on those
 * systems and let the latches catch the missing kernel support at
 * runtime.  IDs come from the in-tree UAPI and are stable.
 */
#ifndef NFNL_SUBSYS_NFTABLES
#define NFNL_SUBSYS_NFTABLES		10
#endif
#ifndef NFNETLINK_V0
#define NFNETLINK_V0			0
#endif

#ifndef NFPROTO_INET
#define NFPROTO_INET			1
#endif
#ifndef NFPROTO_NETDEV
#define NFPROTO_NETDEV			5
#endif
#ifndef NFPROTO_BRIDGE
#define NFPROTO_BRIDGE			7
#endif

#ifndef NF_INET_LOCAL_IN
#define NF_INET_LOCAL_IN		1
#endif

/* nf_tables msg types */
#ifndef NFT_MSG_NEWTABLE
#define NFT_MSG_NEWTABLE		0
#define NFT_MSG_DELTABLE		2
#define NFT_MSG_NEWCHAIN		3
#define NFT_MSG_NEWRULE			6
#define NFT_MSG_DELRULE			8
#define NFT_MSG_NEWSET			9
#define NFT_MSG_DELSET			11
#endif

/* nf_tables verdicts (stored as __be32 in NFTA_VERDICT_CODE) */
#ifndef NFT_JUMP
#define NFT_JUMP			(0xfffffffdU)
#define NFT_GOTO			(0xfffffffcU)
#endif

#ifndef NFT_REG_VERDICT
#define NFT_REG_VERDICT			0
#endif

/* set flags */
#ifndef NFT_SET_ANONYMOUS
#define NFT_SET_ANONYMOUS		0x1
#endif
#ifndef NFT_SET_DYNAMIC
#define NFT_SET_DYNAMIC			0x10
#endif

/* nft data types: NFT_DATA_VALUE = 0; per-data-type IDs come from
 * include/net/netfilter/nf_tables.h NFT_DATATYPE_*.  ipv4_addr is
 * type id 7 in the kernel's nft_*data* registry; key_len is the
 * width in bytes (4). */
#ifndef NFT_DATATYPE_IPADDR
#define NFT_DATATYPE_IPADDR		7
#endif

/* Top-level NFTA_* attr IDs we emit.  Numbering matches kernel UAPI
 * (per-namespace; numbers reused across namespaces). */
#ifndef NFTA_TABLE_NAME
#define NFTA_TABLE_NAME			1
#define NFTA_TABLE_FLAGS		2
#endif

#ifndef NFTA_CHAIN_TABLE
#define NFTA_CHAIN_TABLE		1
#define NFTA_CHAIN_HANDLE		2
#define NFTA_CHAIN_NAME			3
#define NFTA_CHAIN_HOOK			4
#define NFTA_CHAIN_TYPE			7
#endif

#ifndef NFTA_HOOK_HOOKNUM
#define NFTA_HOOK_HOOKNUM		1
#define NFTA_HOOK_PRIORITY		2
#endif

#ifndef NFTA_RULE_TABLE
#define NFTA_RULE_TABLE			1
#define NFTA_RULE_CHAIN			2
#define NFTA_RULE_HANDLE		3
#define NFTA_RULE_EXPRESSIONS		4
#define NFTA_RULE_POSITION		5
#endif

#ifndef NFTA_LIST_ELEM
#define NFTA_LIST_ELEM			1
#endif

#ifndef NFTA_EXPR_NAME
#define NFTA_EXPR_NAME			1
#define NFTA_EXPR_DATA			2
#endif

#ifndef NFTA_IMMEDIATE_DREG
#define NFTA_IMMEDIATE_DREG		1
#define NFTA_IMMEDIATE_DATA		2
#endif

#ifndef NFTA_DATA_VERDICT
#define NFTA_DATA_VERDICT		2
#endif

#ifndef NFTA_VERDICT_CODE
#define NFTA_VERDICT_CODE		1
#define NFTA_VERDICT_CHAIN		2
#endif

#ifndef NFTA_SET_TABLE
#define NFTA_SET_TABLE			1
#define NFTA_SET_NAME			2
#define NFTA_SET_FLAGS			3
#define NFTA_SET_KEY_TYPE		4
#define NFTA_SET_KEY_LEN		5
#define NFTA_SET_ID			10
#endif

/* Reasonable ceiling on a single nfnetlink message + payload.  The
 * rule message with one nested expression containing a verdict +
 * chain string is the largest we emit; well under 1 KiB.  2 KiB
 * leaves headroom. */
#define NFNL_BUF_BYTES			2048
#define NFNL_RECV_TIMEO_S		1

/* Per-iteration packet burst base.  BUDGETED+JITTER scales it: a
 * productive run grows toward the cap, an unproductive one shrinks
 * to floor.  Sends are MSG_DONTWAIT; the inner loop also clamps to
 * STORM_BUDGET_NS wall-clock so even an unbounded burst can't stall
 * the iteration past the SIGALRM(1s) cap. */
#define NFT_PACKET_BASE			3U
#define NFT_PACKET_FLOOR		8U	/* always send at least this many */
#define NFT_PACKET_CAP			64U	/* upper clamp on per-iter burst */
#define STORM_BUDGET_NS			200000000L	/* 200 ms */

/* UDP destination port for the loopback drive packet.  Loopback-only
 * inside a private netns — the value doesn't matter functionally; a
 * fixed non-privileged port keeps any escaped packet trivially
 * identifiable in a tcpdump trace during triage. */
#define NFT_INNER_PORT			34568

/* Per-child latched gates.  Set on the first failure of the
 * corresponding subsystem and never cleared — kernel module / config
 * presence is static for the child's lifetime, so we pay the EFAIL
 * once and skip the path on subsequent invocations. */
static bool ns_unsupported_nfnetlink;
static bool ns_unsupported_nf_tables;
static bool ns_unsupported_inet;

static bool ns_unshared;
static bool ns_setup_failed;
static bool lo_brought_up;

static __u32 g_seq;

static __u32 next_seq(void)
{
	return ++g_seq;
}

static long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (now.tv_sec - t0->tv_sec) * 1000000000L +
	       (now.tv_nsec - t0->tv_nsec);
}

static int rtnl_open(void)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	tv.tv_sec  = NFNL_RECV_TIMEO_S;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	return fd;
}

static int nfnl_open(void)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	tv.tv_sec  = NFNL_RECV_TIMEO_S;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	return fd;
}

static size_t nla_put(unsigned char *buf, size_t off, size_t cap,
		      unsigned short type, const void *data, size_t len)
{
	struct nlattr *nla;
	size_t total = NLA_HDRLEN + len;
	size_t aligned = NLA_ALIGN(total);

	if (off + aligned > cap)
		return 0;

	nla = (struct nlattr *)(buf + off);
	nla->nla_type = type;
	nla->nla_len  = (unsigned short)total;
	if (len)
		memcpy(buf + off + NLA_HDRLEN, data, len);
	if (aligned > total)
		memset(buf + off + total, 0, aligned - total);
	return off + aligned;
}

static size_t nla_put_be32(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, __u32 v)
{
	__u32 be = htonl(v);

	return nla_put(buf, off, cap, type, &be, sizeof(be));
}

static size_t nla_put_str(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, const char *s)
{
	return nla_put(buf, off, cap, type, s, strlen(s) + 1);
}

/*
 * Send via NETLINK_NETFILTER and consume one ack.  Returns 0 on a
 * positive ack (nlmsgerr.error == 0), the negated kernel errno on a
 * rejection, and -EIO on local sendmsg / recv failure.
 */
static int nfnl_send_recv(int fd, void *msg, size_t len)
{
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	unsigned char rbuf[1024];
	struct nlmsghdr *nlh;
	ssize_t n;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;

	iov.iov_base = msg;
	iov.iov_len  = len;

	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;

	if (sendmsg(fd, &mh, 0) < 0)
		return -EIO;

	n = recv(fd, rbuf, sizeof(rbuf), 0);
	if (n < 0)
		return -EIO;
	if ((size_t)n < NLMSG_HDRLEN)
		return -EIO;

	nlh = (struct nlmsghdr *)rbuf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
		return err->error;
	}
	return -EIO;
}

/*
 * nfnetlink message header skeleton: nlmsghdr (with type encoded as
 * (subsys << 8) | msg_id) followed by an nfgenmsg carrying the family
 * and version.  Caller fills attributes after the returned offset.
 */
struct nfgenmsg_local {
	__u8  nfgen_family;
	__u8  version;
	__u16 res_id;	/* network byte order */
};

static size_t nfnl_hdr(unsigned char *buf, __u16 msg_id, __u16 flags,
		       __u8 family)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg_local *nfg;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = (NFNL_SUBSYS_NFTABLES << 8) | msg_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	nlh->nlmsg_seq   = next_seq();

	nfg = (struct nfgenmsg_local *)NLMSG_DATA(nlh);
	nfg->nfgen_family = family;
	nfg->version      = NFNETLINK_V0;
	nfg->res_id       = htons(0);

	return NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*nfg));
}

static void nfnl_finalize(unsigned char *buf, size_t off)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

	nlh->nlmsg_len = (__u32)off;
}

/*
 * Bring lo up inside the private netns.  A freshly-unshared netns
 * has lo present but DOWN; the loopback sendto in step 9 silently
 * drops if lo is down, and without the rx-side completion the input
 * hook never runs and the rule's verdict path stays cold.  Setlink
 * errors are ignored — a kernel that refuses lo up is also one where
 * the rest of the sequence will fail visibly.
 */
static void bring_lo_up(int rtnl)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	int lo_idx = (int)if_nametoindex("lo");

	if (lo_idx <= 0)
		return;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = lo_idx;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	nlh->nlmsg_len = (__u32)(NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi)));
	(void)nfnl_send_recv(rtnl, buf, nlh->nlmsg_len);
}

/*
 * NFT_MSG_NEWTABLE.  Family is randomised per call; flags=0.
 * NLM_F_CREATE | NLM_F_EXCL fails if the name already exists, which
 * is what we want — the caller rolls a fresh suffix per iteration.
 */
static int build_newtable(int fd, __u8 family, const char *table_name)
{
	unsigned char buf[NFNL_BUF_BYTES];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_EXCL, family);

	off = nla_put_str(buf, off, sizeof(buf), NFTA_TABLE_NAME, table_name);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_TABLE_FLAGS, 0);
	if (!off)
		return -EIO;

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

static int build_deltable(int fd, __u8 family, const char *table_name)
{
	unsigned char buf[256];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_DELTABLE, 0, family);

	off = nla_put_str(buf, off, sizeof(buf), NFTA_TABLE_NAME, table_name);
	if (!off)
		return -EIO;

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

/*
 * NFT_MSG_NEWSET, anonymous + dynamic, keyed on ipv4_addr (key_len 4).
 * NFTA_SET_ID is a userspace-assigned cookie so subsequent in-batch
 * commands could reference the set; we don't reference it but the
 * kernel still expects the attr present for newer set-create paths.
 */
static int build_newset(int fd, __u8 family, const char *table_name,
			const char *set_name, __u32 set_id)
{
	unsigned char buf[NFNL_BUF_BYTES];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_NEWSET, NLM_F_CREATE | NLM_F_EXCL, family);

	off = nla_put_str(buf, off, sizeof(buf), NFTA_SET_TABLE, table_name);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_SET_NAME, set_name);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_SET_FLAGS,
			   NFT_SET_ANONYMOUS | NFT_SET_DYNAMIC);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_SET_KEY_TYPE,
			   NFT_DATATYPE_IPADDR);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_SET_KEY_LEN, 4);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_SET_ID, set_id);
	if (!off)
		return -EIO;

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

static int build_delset(int fd, __u8 family, const char *table_name,
			const char *set_name)
{
	unsigned char buf[512];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_DELSET, 0, family);

	off = nla_put_str(buf, off, sizeof(buf), NFTA_SET_TABLE, table_name);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_SET_NAME, set_name);
	if (!off)
		return -EIO;

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

/*
 * NFT_MSG_NEWCHAIN.  When hook_present is true, emits NFTA_CHAIN_HOOK
 * (HOOKNUM=NF_INET_LOCAL_IN, PRIORITY=0) + NFTA_CHAIN_TYPE="filter"
 * — that's a base chain attached to the input hook.  Otherwise emits
 * a regular (no-hook) chain usable as a jump target.
 */
static int build_newchain(int fd, __u8 family, const char *table_name,
			  const char *chain_name, bool hook_present)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *hook_attr;
	size_t off, hook_off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_NEWCHAIN, NLM_F_CREATE | NLM_F_EXCL, family);

	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_TABLE, table_name);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_NAME, chain_name);
	if (!off)
		return -EIO;

	if (hook_present) {
		hook_off = off;
		off = nla_put(buf, off, sizeof(buf),
			      NFTA_CHAIN_HOOK | NLA_F_NESTED, NULL, 0);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_IN);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   NFTA_HOOK_PRIORITY, 0);
		if (!off)
			return -EIO;
		hook_attr = (struct nlattr *)(buf + hook_off);
		hook_attr->nla_len = (unsigned short)(off - hook_off);

		off = nla_put_str(buf, off, sizeof(buf),
				  NFTA_CHAIN_TYPE, "filter");
		if (!off)
			return -EIO;
	}

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

/*
 * NFT_MSG_NEWRULE on (table, chain) carrying one immediate-verdict
 * expression that jumps/gotos to target_chain.  The expression list
 * layout is:
 *   NFTA_RULE_EXPRESSIONS (nested)
 *     NFTA_LIST_ELEM (nested)
 *       NFTA_EXPR_NAME = "immediate"
 *       NFTA_EXPR_DATA (nested)
 *         NFTA_IMMEDIATE_DREG = NFT_REG_VERDICT
 *         NFTA_IMMEDIATE_DATA (nested)
 *           NFTA_DATA_VERDICT (nested)
 *             NFTA_VERDICT_CODE = verdict_code
 *             NFTA_VERDICT_CHAIN = target_chain
 *
 * If position > 0, NFTA_RULE_POSITION carries it (insert-at-handle
 * semantics) and NLM_F_CREATE alone is used (no NLM_F_EXCL — the
 * existing rule referenced by the position keeps living after the
 * insert).  Otherwise the rule is appended to the chain.
 */
static int build_newrule(int fd, __u8 family, const char *table_name,
			 const char *chain_name, const char *target_chain,
			 __u32 verdict_code, __u64 position)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *exprs, *elem, *expr_data, *imm_data, *verdict;
	size_t off, exprs_off, elem_off, expr_data_off, imm_data_off, verdict_off;
	__u16 flags = NLM_F_CREATE;

	memset(buf, 0, sizeof(buf));
	if (position == 0)
		flags |= NLM_F_APPEND;
	off = nfnl_hdr(buf, NFT_MSG_NEWRULE, flags, family);

	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_TABLE, table_name);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_CHAIN, chain_name);
	if (!off)
		return -EIO;

	if (position > 0) {
		__u64 be_pos = ((__u64)htonl((__u32)(position >> 32))) |
			       (((__u64)htonl((__u32)position)) << 32);
		off = nla_put(buf, off, sizeof(buf), NFTA_RULE_POSITION,
			      &be_pos, sizeof(be_pos));
		if (!off)
			return -EIO;
	}

	exprs_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_RULE_EXPRESSIONS | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;

	elem_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf),
			  NFTA_EXPR_NAME, "immediate");
	if (!off)
		return -EIO;

	expr_data_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;

	off = nla_put_be32(buf, off, sizeof(buf),
			   NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
	if (!off)
		return -EIO;

	imm_data_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_IMMEDIATE_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;

	verdict_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_DATA_VERDICT | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;

	off = nla_put_be32(buf, off, sizeof(buf),
			   NFTA_VERDICT_CODE, verdict_code);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf),
			  NFTA_VERDICT_CHAIN, target_chain);
	if (!off)
		return -EIO;

	verdict = (struct nlattr *)(buf + verdict_off);
	verdict->nla_len = (unsigned short)(off - verdict_off);
	imm_data = (struct nlattr *)(buf + imm_data_off);
	imm_data->nla_len = (unsigned short)(off - imm_data_off);
	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	exprs = (struct nlattr *)(buf + exprs_off);
	exprs->nla_len = (unsigned short)(off - exprs_off);

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

/*
 * NFT_MSG_DELRULE on (table, chain) with no NFTA_RULE_HANDLE — the
 * kernel treats this as "delete every rule in chain".  Races any
 * in-flight skb still draining through the input hook.
 */
static int build_delrule(int fd, __u8 family, const char *table_name,
			 const char *chain_name)
{
	unsigned char buf[512];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_DELRULE, 0, family);

	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_TABLE, table_name);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_CHAIN, chain_name);
	if (!off)
		return -EIO;

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

/*
 * Pick a random nf_tables family per call.  inet (covers v4+v6),
 * bridge (link-layer), netdev (ingress).  Each family registers its
 * own afinfo and exercises a different commit-time path inside
 * nf_tables_api.
 */
static __u8 pick_family(void)
{
	static const __u8 families[] = {
		NFPROTO_INET, NFPROTO_BRIDGE, NFPROTO_NETDEV,
	};

	return families[rand32() % ARRAY_SIZE(families)];
}

bool nftables_churn(struct childdata *child)
{
	char table_name[32];
	char base_chain[32]  = "chain_in";
	char aux_chain[32]   = "chain_aux";
	char anon_set[32];
	int rtnl = -1;
	int nfnl = -1;
	int udp = -1;
	__u8 family;
	__u32 set_id;
	__u32 verdict;
	bool table_created = false;
	struct timespec t0;
	unsigned int iters;
	unsigned int i;
	int rc;

	(void)child;

	__atomic_add_fetch(&shm->stats.nftables_churn_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_setup_failed || ns_unsupported_nfnetlink ||
	    ns_unsupported_nf_tables)
		return true;

	if (!ns_unshared) {
		if (unshare(CLONE_NEWNET) < 0) {
			ns_setup_failed = true;
			__atomic_add_fetch(&shm->stats.nftables_churn_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		ns_unshared = true;
	}

	nfnl = nfnl_open();
	if (nfnl < 0) {
		/* EPROTONOSUPPORT here means CONFIG_NF_NETLINK is off
		 * — latch and stop trying.  Other errors (ENOMEM,
		 * EMFILE) are transient; fall through and re-try next
		 * invocation. */
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT)
			ns_unsupported_nfnetlink = true;
		__atomic_add_fetch(&shm->stats.nftables_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	rtnl = rtnl_open();
	if (rtnl < 0) {
		__atomic_add_fetch(&shm->stats.nftables_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	if (!lo_brought_up) {
		bring_lo_up(rtnl);
		lo_brought_up = true;
	}

	family = pick_family();
	snprintf(table_name, sizeof(table_name), "trnft%u",
		 (unsigned int)(rand32() & 0xffffu));
	snprintf(anon_set, sizeof(anon_set), "__set%u",
		 (unsigned int)(rand32() & 0xffffu));
	set_id = rand32();
	verdict = (rand32() & 1) ? NFT_JUMP : NFT_GOTO;

	rc = build_newtable(nfnl, family, table_name);
	if (rc != 0) {
		/* EAFNOSUPPORT / EOPNOTSUPP / EPROTONOSUPPORT all mean
		 * "this nf_tables family isn't registered" — most
		 * commonly because the nf_tables module itself is
		 * absent.  Latch the whole op off; nothing else here
		 * will work either. */
		if (rc == -EOPNOTSUPP || rc == -EPROTONOSUPPORT ||
		    rc == -EAFNOSUPPORT)
			ns_unsupported_nf_tables = true;
		goto out;
	}
	table_created = true;
	__atomic_add_fetch(&shm->stats.nftables_churn_table_create_ok,
			   1, __ATOMIC_RELAXED);

	if (build_newset(nfnl, family, table_name, anon_set, set_id) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn_set_create_ok,
				   1, __ATOMIC_RELAXED);

	/* aux first so the base-chain rule's NFT_JUMP/NFT_GOTO has a
	 * resolvable target on first commit. */
	if (build_newchain(nfnl, family, table_name, aux_chain, false) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn_chain_create_ok,
				   1, __ATOMIC_RELAXED);

	if (build_newchain(nfnl, family, table_name, base_chain, true) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn_chain_create_ok,
				   1, __ATOMIC_RELAXED);

	if (build_newrule(nfnl, family, table_name, base_chain,
			  aux_chain, verdict, 0) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn_rule_create_ok,
				   1, __ATOMIC_RELAXED);

	/*
	 * Drive the input hook with loopback UDP traffic.  Each send
	 * ingresses on lo, walks the freshly-installed chain_in ->
	 * chain_aux jump via nf_hook_slow, and exercises the verdict
	 * path that the CVE-2024-1086 lineage hangs off.
	 */
	if (!ns_unsupported_inet) {
		udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (udp < 0) {
			if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
				ns_unsupported_inet = true;
		}
	}

	if (udp >= 0) {
		struct sockaddr_in dst;

		memset(&dst, 0, sizeof(dst));
		dst.sin_family      = AF_INET;
		dst.sin_port        = htons(NFT_INNER_PORT);
		dst.sin_addr.s_addr = htonl(0x7f000001U);	/* 127.0.0.1 */

		(void)clock_gettime(CLOCK_MONOTONIC, &t0);
		iters = BUDGETED(CHILD_OP_NFTABLES_CHURN,
				 JITTER_RANGE(NFT_PACKET_BASE));
		if (iters < NFT_PACKET_FLOOR)
			iters = NFT_PACKET_FLOOR;
		if (iters > NFT_PACKET_CAP)
			iters = NFT_PACKET_CAP;

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
				__atomic_add_fetch(&shm->stats.nftables_churn_packet_sent_ok,
						   1, __ATOMIC_RELAXED);
		}
	}

	/*
	 * Mid-traffic insert: NEWRULE at NFTA_RULE_POSITION = 1.  The
	 * position-based insert path is a different commit-time codepath
	 * from the append-only path above; if no rule with handle 1
	 * exists the kernel rejects it cheaply, which is fine — the
	 * commit-time validation still ran.
	 */
	if (build_newrule(nfnl, family, table_name, base_chain,
			  aux_chain, verdict, 1) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn_rule_insert_ok,
				   1, __ATOMIC_RELAXED);

	/*
	 * Concurrent with whatever's still draining from the udp send
	 * loop: bulk-delete every rule in chain_in.  This is the
	 * targeted commit-vs-traffic teardown window — the same one the
	 * CVE-2024-1086 nft_verdict UAF exploited.
	 */
	if (build_delrule(nfnl, family, table_name, base_chain) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn_rule_del_ok,
				   1, __ATOMIC_RELAXED);

	(void)build_delset(nfnl, family, table_name, anon_set);

out:
	if (udp >= 0)
		close(udp);

	if (nfnl >= 0) {
		/* DELTABLE cascades cleanup of any chain/rule/set
		 * survivors via nf_tables_table_destroy, racing the
		 * same in-flight skbs as the explicit DELRULE above. */
		if (table_created) {
			if (build_deltable(nfnl, family, table_name) == 0)
				__atomic_add_fetch(&shm->stats.nftables_churn_table_del_ok,
						   1, __ATOMIC_RELAXED);
		}
		close(nfnl);
	}

	if (rtnl >= 0)
		close(rtnl);

	return true;
}
