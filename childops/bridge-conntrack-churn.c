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
 *   1. unshare(CLONE_NEWNET) once per child; bring lo up.
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
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
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

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#ifndef NFPROTO_BRIDGE
#define NFPROTO_BRIDGE			7
#endif
#ifndef NF_BR_PRE_ROUTING
#define NF_BR_PRE_ROUTING		0
#endif
#ifndef NF_BR_PRI_CT_PRE
#define NF_BR_PRI_CT_PRE		(-200)
#endif
#ifndef VETH_INFO_PEER
#define VETH_INFO_PEER			1
#endif

#ifndef NFNL_SUBSYS_CTNETLINK
#define NFNL_SUBSYS_CTNETLINK		1
#endif
#ifndef NFNL_SUBSYS_NFTABLES
#define NFNL_SUBSYS_NFTABLES		10
#endif
#ifndef NFNETLINK_V0
#define NFNETLINK_V0			0
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
#define BRCT_NFT_BUF_BYTES		1024

static bool ns_unshared;
static bool ns_setup_failed;
static bool lo_up_done;
static bool ns_unsupported_bridge;
static bool ns_unsupported_nf_tables;
static bool ns_unsupported_ctnetlink;

static __u32 g_seq;

static __u32 next_seq(void)
{
	return ++g_seq;
}

struct brct_nfgenmsg {
	__u8	nfgen_family;
	__u8	version;
	__u16	res_id;		/* network byte order */
};

static int nl_open(int proto)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, proto);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	tv.tv_sec  = 1;
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

static size_t nla_put_str(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, const char *s)
{
	return nla_put(buf, off, cap, type, s, strlen(s) + 1);
}

static size_t nla_put_u32(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, __u32 v)
{
	return nla_put(buf, off, cap, type, &v, sizeof(v));
}

static size_t nla_put_be32(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, __u32 v)
{
	__u32 be = htonl(v);

	return nla_put(buf, off, cap, type, &be, sizeof(be));
}

static int nl_send_recv(int fd, void *msg, size_t len)
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
	if (n < (ssize_t)NLMSG_HDRLEN)
		return -EIO;
	nlh = (struct nlmsghdr *)rbuf;
	if (nlh->nlmsg_type == NLMSG_ERROR)
		return ((struct nlmsgerr *)NLMSG_DATA(nlh))->error;
	return -EIO;
}

static void bring_lo_up(int rtnl)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	int idx = (int)if_nametoindex("lo");

	if (idx <= 0)
		return;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = idx;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;
	nlh->nlmsg_len = (__u32)(NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi)));
	(void)nl_send_recv(rtnl, buf, nlh->nlmsg_len);
}

static int rtnl_create_bridge(int fd, const char *name)
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
	nlh->nlmsg_seq   = next_seq();
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off)
		return -EIO;
	li_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_LINKINFO, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "bridge");
	if (!off)
		return -EIO;
	((struct nlattr *)(buf + li_off))->nla_len =
		(unsigned short)(off - li_off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(fd, buf, off);
}

static int rtnl_create_veth(int fd, const char *a, const char *b)
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
	nlh->nlmsg_seq   = next_seq();
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, a);
	if (!off)
		return -EIO;
	li_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_LINKINFO, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth");
	if (!off)
		return -EIO;
	id_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_INFO_DATA, NULL, 0);
	if (!off)
		return -EIO;
	peer_off = off;
	off = nla_put(buf, off, sizeof(buf), VETH_INFO_PEER, NULL, 0);
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
	((struct nlattr *)(buf + peer_off))->nla_len =
		(unsigned short)(off - peer_off);
	((struct nlattr *)(buf + id_off))->nla_len =
		(unsigned short)(off - id_off);
	((struct nlattr *)(buf + li_off))->nla_len =
		(unsigned short)(off - li_off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(fd, buf, off);
}

static int rtnl_setlink_master(int fd, int idx, int master)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = idx;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_MASTER, (__u32)master);
	if (!off)
		return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(fd, buf, off);
}

static int rtnl_setlink_up(int fd, int idx)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = idx;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(fd, buf, off);
}

static int rtnl_dellink(int fd, int idx)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = idx;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(fd, buf, off);
}

/* Append one nfnetlink sub-message into a batched buffer; returns new
 * offset.  Caller fills attributes after the returned position. */
static size_t nft_msg_begin(unsigned char *buf, size_t off, __u16 msg_id,
			    __u16 extra_flags, __u8 family)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)(buf + off);
	struct brct_nfgenmsg *nfg;

	nlh->nlmsg_type  = (NFNL_SUBSYS_NFTABLES << 8) | msg_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | extra_flags;
	nlh->nlmsg_seq   = next_seq();
	nfg = (struct brct_nfgenmsg *)NLMSG_DATA(nlh);
	nfg->nfgen_family = family;
	nfg->version      = NFNETLINK_V0;
	nfg->res_id       = htons(0);
	return off + NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*nfg));
}

static void nft_msg_end(unsigned char *buf, size_t msg_off, size_t off)
{
	((struct nlmsghdr *)(buf + msg_off))->nlmsg_len =
		(__u32)(off - msg_off);
}

/* Build the full NEWTABLE/NEWCHAIN/NEWRULE batch and send it as one
 * sendmsg().  Returns 0 on a clean end-of-batch, -errno on the first
 * rejection. */
static int nft_install_bridge_ct(int nfnl, const char *table,
				 const char *chain)
{
	unsigned char buf[BRCT_NFT_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct brct_nfgenmsg *nfg;
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	struct nlattr *hook_attr, *exprs, *elem, *expr_data;
	size_t off = 0, msg_off, hook_off, exprs_off, elem_off, expr_data_off;
	unsigned char rbuf[1024];
	__u8 family = NFPROTO_BRIDGE;
	__u32 prio = (__u32)(NF_BR_PRI_CT_PRE - 1);
	ssize_t s;
	int rc = 0;

	memset(buf, 0, sizeof(buf));

	/* BATCH_BEGIN */
	msg_off = off;
	nlh = (struct nlmsghdr *)(buf + off);
	nlh->nlmsg_type  = NFNL_MSG_BATCH_BEGIN;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq   = next_seq();
	nfg = (struct brct_nfgenmsg *)NLMSG_DATA(nlh);
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version      = NFNETLINK_V0;
	nfg->res_id       = htons(NFNL_SUBSYS_NFTABLES);
	off += NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*nfg));
	nft_msg_end(buf, msg_off, off);

	/* NEWTABLE */
	msg_off = off;
	off = nft_msg_begin(buf, off, BRCT_NFT_MSG_NEWTABLE,
			    NLM_F_CREATE, family);
	off = nla_put_str(buf, off, sizeof(buf), BRCT_NFTA_TABLE_NAME, table);
	if (!off)
		return -EIO;
	nft_msg_end(buf, msg_off, off);

	/* NEWCHAIN base, hook=PRE_ROUTING, priority=NF_BR_PRI_CT_PRE-1 */
	msg_off = off;
	off = nft_msg_begin(buf, off, BRCT_NFT_MSG_NEWCHAIN,
			    NLM_F_CREATE, family);
	off = nla_put_str(buf, off, sizeof(buf), BRCT_NFTA_CHAIN_TABLE, table);
	off = nla_put_str(buf, off, sizeof(buf), BRCT_NFTA_CHAIN_NAME, chain);
	if (!off)
		return -EIO;
	hook_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      BRCT_NFTA_CHAIN_HOOK | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf),
			   BRCT_NFTA_HOOK_HOOKNUM, NF_BR_PRE_ROUTING);
	off = nla_put_be32(buf, off, sizeof(buf),
			   BRCT_NFTA_HOOK_PRIORITY, prio);
	if (!off)
		return -EIO;
	hook_attr = (struct nlattr *)(buf + hook_off);
	hook_attr->nla_len = (unsigned short)(off - hook_off);
	off = nla_put_str(buf, off, sizeof(buf),
			  BRCT_NFTA_CHAIN_TYPE, "filter");
	if (!off)
		return -EIO;
	nft_msg_end(buf, msg_off, off);

	/* NEWRULE: one nft_ct expression — drives nf_conntrack registration
	 * on the bridge family even though the rule's verdict path is unused. */
	msg_off = off;
	off = nft_msg_begin(buf, off, BRCT_NFT_MSG_NEWRULE,
			    NLM_F_CREATE | NLM_F_APPEND, family);
	off = nla_put_str(buf, off, sizeof(buf), BRCT_NFTA_RULE_TABLE, table);
	off = nla_put_str(buf, off, sizeof(buf), BRCT_NFTA_RULE_CHAIN, chain);
	if (!off)
		return -EIO;
	exprs_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      BRCT_NFTA_RULE_EXPRESSIONS | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	elem_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      BRCT_NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	off = nla_put_str(buf, off, sizeof(buf), BRCT_NFTA_EXPR_NAME, "ct");
	expr_data_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      BRCT_NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	off = nla_put_be32(buf, off, sizeof(buf),
			   BRCT_NFTA_CT_KEY, BRCT_NFT_CT_STATE);
	off = nla_put_be32(buf, off, sizeof(buf),
			   BRCT_NFTA_CT_DREG, BRCT_NFT_REG_1);
	if (!off)
		return -EIO;
	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	exprs = (struct nlattr *)(buf + exprs_off);
	exprs->nla_len = (unsigned short)(off - exprs_off);
	nft_msg_end(buf, msg_off, off);

	/* BATCH_END */
	msg_off = off;
	nlh = (struct nlmsghdr *)(buf + off);
	nlh->nlmsg_type  = NFNL_MSG_BATCH_END;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq   = next_seq();
	nfg = (struct brct_nfgenmsg *)NLMSG_DATA(nlh);
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version      = NFNETLINK_V0;
	nfg->res_id       = htons(NFNL_SUBSYS_NFTABLES);
	off += NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*nfg));
	nft_msg_end(buf, msg_off, off);

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	iov.iov_base  = buf;
	iov.iov_len   = off;
	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;

	if (sendmsg(nfnl, &mh, 0) < 0)
		return -errno;

	/* One blocking recv to wait for the batch ack, then non-blocking
	 * drain of any coalesced replies. */
	s = recv(nfnl, rbuf, sizeof(rbuf), 0);
	if (s >= (ssize_t)NLMSG_HDRLEN) {
		struct nlmsghdr *r = (struct nlmsghdr *)rbuf;

		if (r->nlmsg_type == NLMSG_ERROR)
			rc = ((struct nlmsgerr *)NLMSG_DATA(r))->error;
	}
	while (recv(nfnl, rbuf, sizeof(rbuf), MSG_DONTWAIT) > 0)
		;
	return rc;
}

static int ctnetlink_flush(int nfnl)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct brct_nfgenmsg *nfg;
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_FLUSH;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();
	nfg = (struct brct_nfgenmsg *)NLMSG_DATA(nlh);
	nfg->nfgen_family = AF_INET;
	nfg->version      = NFNETLINK_V0;
	nfg->res_id       = htons(0);
	nlh->nlmsg_len = (__u32)(NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*nfg)));

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	iov.iov_base  = buf;
	iov.iov_len   = nlh->nlmsg_len;
	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;

	if (sendmsg(nfnl, &mh, MSG_DONTWAIT) < 0)
		return -errno;
	(void)recv(nfnl, buf, sizeof(buf), MSG_DONTWAIT);
	return 0;
}

struct sender_args {
	int		raw_fd;
	int		ifindex;
	unsigned char	dst_mac[6];
	struct timespec	t0;
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
		frame[28] = 0; frame[29] = (unsigned char)(i & 0xff);
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

		if (sendto(a->raw_fd, frame, sizeof(frame), MSG_DONTWAIT,
			   (struct sockaddr *)&sll, sizeof(sll)) > 0)
			__atomic_add_fetch(&shm->stats.bridge_ct_pkts_sent,
					   1, __ATOMIC_RELAXED);
	}
	return NULL;
}

bool bridge_conntrack_churn(struct childdata *child)
{
	char br_name[IFNAMSIZ];
	char veth_a[IFNAMSIZ], veth_b[IFNAMSIZ];
	const char *table = "br_ct";
	const char *chain = "in";
	struct sender_args sa;
	pthread_t tid = 0;
	bool sender_started = false;
	int rtnl = -1, nfnl_nft = -1, nfnl_ct = -1, raw = -1;
	int br_idx = 0, va_idx = 0, vb_idx = 0;
	bool bridge_added = false, veth_added = false;
	unsigned int rng, iters, i;
	int rc;

	(void)child;

	__atomic_add_fetch(&shm->stats.bridge_ct_runs, 1, __ATOMIC_RELAXED);

	if (ns_setup_failed || ns_unsupported_bridge ||
	    ns_unsupported_nf_tables || ns_unsupported_ctnetlink)
		return true;

	if (!ONE_IN(8))
		return true;

	if (!ns_unshared) {
		if (unshare(CLONE_NEWNET) < 0) {
			ns_setup_failed = true;
			return true;
		}
		ns_unshared = true;
	}

	rtnl = nl_open(NETLINK_ROUTE);
	if (rtnl < 0)
		return true;
	if (!lo_up_done) {
		bring_lo_up(rtnl);
		lo_up_done = true;
	}

	rng = (unsigned int)(rand32() & 0xffffu);
	snprintf(br_name, sizeof(br_name), "trbc%u", rng);
	snprintf(veth_a,  sizeof(veth_a),  "trbcv%ua", rng);
	snprintf(veth_b,  sizeof(veth_b),  "trbcv%ub", rng);

	rc = rtnl_create_bridge(rtnl, br_name);
	if (rc != 0) {
		if (rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -ENOTSUP || rc == -EPROTONOSUPPORT)
			ns_unsupported_bridge = true;
		goto out;
	}
	bridge_added = true;
	br_idx = (int)if_nametoindex(br_name);
	if (br_idx <= 0)
		goto out;

	if (rtnl_create_veth(rtnl, veth_a, veth_b) != 0)
		goto out;
	veth_added = true;
	va_idx = (int)if_nametoindex(veth_a);
	vb_idx = (int)if_nametoindex(veth_b);
	if (va_idx <= 0 || vb_idx <= 0)
		goto out;

	(void)rtnl_setlink_master(rtnl, va_idx, br_idx);
	(void)rtnl_setlink_up(rtnl, br_idx);
	(void)rtnl_setlink_up(rtnl, va_idx);
	(void)rtnl_setlink_up(rtnl, vb_idx);

	nfnl_nft = nl_open(NETLINK_NETFILTER);
	if (nfnl_nft < 0)
		goto out;
	rc = nft_install_bridge_ct(nfnl_nft, table, chain);
	if (rc == -EAFNOSUPPORT || rc == -EPROTONOSUPPORT ||
	    rc == -EOPNOTSUPP || rc == -ENOTSUP)
		ns_unsupported_nf_tables = true;

	raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (raw >= 0) {
		struct sockaddr_ll bind_sll;

		memset(&bind_sll, 0, sizeof(bind_sll));
		bind_sll.sll_family   = AF_PACKET;
		bind_sll.sll_protocol = htons(ETH_P_ALL);
		bind_sll.sll_ifindex  = vb_idx;
		(void)bind(raw, (struct sockaddr *)&bind_sll, sizeof(bind_sll));

		memset(&sa, 0, sizeof(sa));
		sa.raw_fd  = raw;
		sa.ifindex = vb_idx;
		/* Send to v0's MAC; we don't know it cheaply, so use the
		 * broadcast — bridge floods on unknown unicast / broadcast
		 * and the ct hook sees the frame either way. */
		memset(sa.dst_mac, 0xff, sizeof(sa.dst_mac));
		(void)clock_gettime(CLOCK_MONOTONIC, &sa.t0);
		if (pthread_create(&tid, NULL, brct_packet_sender, &sa) == 0)
			sender_started = true;
	}

	nfnl_ct = nl_open(NETLINK_NETFILTER);
	if (nfnl_ct >= 0) {
		struct timespec t0;

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
			rc = ctnetlink_flush(nfnl_ct);
			if (rc == -EAFNOSUPPORT || rc == -EPROTONOSUPPORT ||
			    rc == -EOPNOTSUPP || rc == -ENOTSUP) {
				ns_unsupported_ctnetlink = true;
				break;
			}
			__atomic_add_fetch(&shm->stats.bridge_ct_flushes,
					   1, __ATOMIC_RELAXED);
		}
	}

	if (sender_started)
		(void)pthread_join(tid, NULL);

out:
	if (raw >= 0) {
		unsigned char drain[256];

		while (recv(raw, drain, sizeof(drain), MSG_DONTWAIT) > 0)
			;
		close(raw);
	}
	if (nfnl_ct >= 0)
		close(nfnl_ct);
	if (nfnl_nft >= 0)
		close(nfnl_nft);
	if (rtnl >= 0) {
		if (bridge_added && br_idx > 0)
			(void)rtnl_dellink(rtnl, br_idx);
		if (veth_added && vb_idx > 0)
			(void)rtnl_dellink(rtnl, vb_idx);
		close(rtnl);
	}
	return true;
}
