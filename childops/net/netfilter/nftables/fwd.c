/*
 * fwd.c
 *
 * netdev fwd-neighbour loop sub-mode for nftables_churn.
 */

#include "internal.h"

/*
 * nft_fwd_netdev neigh-forward loop sub-mode (upstream 1d47b55b36d2,
 * 0a0b35f0bf10, 1049970d7583).  Brings up a single veth pair inside the
 * private netns, assigns /24 IPv4 addresses to each peer, installs a
 * netdev-family table with two ingress chains -- one on each end -- whose
 * only rule is "immediate -> NFT_REG_1 = peer-oif" + "fwd sreg_dev=NFT_REG_1".
 * A single ICMP echo on the raw socket then drives the cross-forward path
 * through nft_fwd_netdev_eval / nf_dup_netdev_egress, exercising the
 * recursion / skb headroom / writable-pull windows the upstream commits
 * harden.  Bounded by FWD_LOOP_BUDGET_NS wall-clock.  Latches
 * ns_unsupported_nft_fwd_netdev_loop on the first failure of veth create /
 * addr assign / netdev-table install so a kernel without CONFIG_VETH or
 * CONFIG_NFT_FWD_NETDEV pays the EFAIL once and stops trying.
 */
#define FWD_LOOP_BUDGET_NS	150000000L
#define FWD_LOOP_VP0_ADDR	0x0a7b0101U	/* 10.123.1.1 */
#define FWD_LOOP_VP1_ADDR	0x0a7b0102U	/* 10.123.1.2 */

static bool ns_unsupported_nft_fwd_netdev_loop;

bool nft_fwd_netdev_loop_unsupported(void)
{
	return ns_unsupported_nft_fwd_netdev_loop;
}

static int build_veth_pair_create(struct nl_ctx *rtnl, const char *a,
				  const char *b)
{
	unsigned char buf[1024];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi, *peer_ifi;
	struct nlattr *li, *id, *peer;
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
	peer = (struct nlattr *)(buf + peer_off);
	peer->nla_len = (unsigned short)(off - peer_off);
	id = (struct nlattr *)(buf + id_off);
	id->nla_len = (unsigned short)(off - id_off);
	li = (struct nlattr *)(buf + li_off);
	li->nla_len = (unsigned short)(off - li_off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

static int build_addr_assign(struct nl_ctx *rtnl, int idx, __u32 addr_be)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET;
	ifa->ifa_prefixlen = 24;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = 0;
	ifa->ifa_index     = (unsigned int)idx;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL, &addr_be,
		      sizeof(addr_be));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, &addr_be,
		      sizeof(addr_be));
	if (!off)
		return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

static int build_setlink_up_idx(struct nl_ctx *rtnl, int idx)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = idx;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

static int build_netdev_ingress_chain(struct nfnl_ctx *ctx, const char *table,
				      const char *chain, const char *dev)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *hook_attr;
	size_t off, hook_off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWCHAIN,
			   NLM_F_CREATE | NLM_F_EXCL, NFPROTO_NETDEV);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_TABLE, table);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_NAME, chain);
	if (!off)
		return -EIO;
	hook_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_CHAIN_HOOK | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_HOOK_HOOKNUM,
			   NF_NETDEV_INGRESS);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_HOOK_PRIORITY, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_HOOK_DEV, dev);
	if (!off)
		return -EIO;
	hook_attr = (struct nlattr *)(buf + hook_off);
	hook_attr->nla_len = (unsigned short)(off - hook_off);
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_TYPE, "filter");
	if (!off)
		return -EIO;
	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

static int build_fwd_loop_rule(struct nfnl_ctx *ctx, const char *table,
			       const char *chain, __u32 oif)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *exprs, *elem, *expr_data, *data_attr;
	size_t off, exprs_off, elem_off, expr_data_off, data_off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWRULE,
			   NLM_F_CREATE | NLM_F_APPEND, NFPROTO_NETDEV);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_TABLE, table);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_CHAIN, chain);
	if (!off)
		return -EIO;
	exprs_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_RULE_EXPRESSIONS | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;

	/* immediate: NFT_REG_1 <- oif (host-byte-order, register payload) */
	elem_off = off;
	off = nla_put(buf, off, sizeof(buf), NFTA_LIST_ELEM | NLA_F_NESTED,
		      NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_EXPR_NAME, "immediate");
	if (!off)
		return -EIO;
	expr_data_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_IMMEDIATE_DREG,
			   NFT_REG_1);
	if (!off)
		return -EIO;
	data_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_IMMEDIATE_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), NFTA_DATA_VALUE, &oif,
		      sizeof(oif));
	if (!off)
		return -EIO;
	data_attr = (struct nlattr *)(buf + data_off);
	data_attr->nla_len = (unsigned short)(off - data_off);
	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);

	/* fwd: sreg_dev = NFT_REG_1 -- nft_fwd_netdev_eval reads peer oif */
	elem_off = off;
	off = nla_put(buf, off, sizeof(buf), NFTA_LIST_ELEM | NLA_F_NESTED,
		      NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_EXPR_NAME, "fwd");
	if (!off)
		return -EIO;
	expr_data_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_FWD_SREG_DEV,
			   NFT_REG_1);
	if (!off)
		return -EIO;
	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);

	exprs = (struct nlattr *)(buf + exprs_off);
	exprs->nla_len = (unsigned short)(off - exprs_off);
	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

void nft_fwd_netdev_loop_sweep(struct nfnl_ctx *nfnl,
			       struct nl_ctx *rtnl)
{
	char table_name[32];
	char vp0[IFNAMSIZ], vp1[IFNAMSIZ];
	int vp0_idx, vp1_idx;
	int sk = -1;
	bool table_created = false;
	struct timespec t0;
	unsigned int rng = (unsigned int)(rand32() & 0xffffu);
	int rc = 0;

	__atomic_add_fetch(&shm->stats.nftables_churn.nft_fwd_loop_runs, 1,
			   __ATOMIC_RELAXED);
	(void)clock_gettime(CLOCK_MONOTONIC, &t0);

	snprintf(vp0, sizeof(vp0), "vp0_%u", rng);
	snprintf(vp1, sizeof(vp1), "vp1_%u", rng);

	rc = build_veth_pair_create(rtnl, vp0, vp1);
	if (rc != 0)
		goto fail;
	vp0_idx = (int)if_nametoindex(vp0);
	if (vp0_idx <= 0) {
		rc = -errno;
		goto fail;
	}
	vp1_idx = (int)if_nametoindex(vp1);
	if (vp1_idx <= 0) {
		rc = -errno;
		goto fail;
	}
	rc = build_addr_assign(rtnl, vp0_idx, htonl(FWD_LOOP_VP0_ADDR));
	if (rc != 0)
		goto fail;
	rc = build_addr_assign(rtnl, vp1_idx, htonl(FWD_LOOP_VP1_ADDR));
	if (rc != 0)
		goto fail;
	rc = build_setlink_up_idx(rtnl, vp0_idx);
	if (rc != 0)
		goto fail;
	rc = build_setlink_up_idx(rtnl, vp1_idx);
	if (rc != 0)
		goto fail;

	nft_fill_table_name(table_name, sizeof(table_name), "trfwdl");
	rc = nft_build_newtable(nfnl, NFPROTO_NETDEV, table_name);
	if (rc != 0)
		goto fail;
	table_created = true;

	if (build_netdev_ingress_chain(nfnl, table_name, "ing0", vp0) != 0 ||
	    build_netdev_ingress_chain(nfnl, table_name, "ing1", vp1) != 0)
		goto out;
	if (build_fwd_loop_rule(nfnl, table_name, "ing0",
				(__u32)vp1_idx) != 0 ||
	    build_fwd_loop_rule(nfnl, table_name, "ing1",
				(__u32)vp0_idx) != 0)
		goto out;

	if (ns_since(&t0) >= FWD_LOOP_BUDGET_NS)
		goto out;

	sk = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
	if (sk >= 0) {
		struct sockaddr_in dst;
		unsigned char icmp[16];

		memset(&dst, 0, sizeof(dst));
		dst.sin_family      = AF_INET;
		dst.sin_addr.s_addr = htonl(FWD_LOOP_VP1_ADDR);
		memset(icmp, 0, sizeof(icmp));
		icmp[0] = 8;	/* ICMP_ECHO */
		if (sendto(sk, icmp, sizeof(icmp), MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst)) > 0)
			__atomic_add_fetch(&shm->stats.nftables_churn.nft_fwd_loop_probe_sent_ok,
					   1, __ATOMIC_RELAXED);
	}

	__atomic_add_fetch(&shm->stats.nftables_churn.nft_fwd_loop_completed_ok, 1,
			   __ATOMIC_RELAXED);
	goto out;

fail:
	/* Only latch on errnos that mean the kernel will never support
	 * this sub-mode for the child's lifetime (CONFIG_VETH absent,
	 * CONFIG_NFT_FWD_NETDEV absent, NFPROTO_NETDEV family not
	 * registered).  EBUSY / EAGAIN / ENODEV here are transient
	 * (lock contention, slab pressure, veth racing teardown) and
	 * must not permanently disable the path. */
	if (rc == -EOPNOTSUPP || rc == -EPROTONOSUPPORT ||
	    rc == -EAFNOSUPPORT)
		ns_unsupported_nft_fwd_netdev_loop = true;
	__atomic_add_fetch(&shm->stats.nftables_churn.nft_fwd_loop_ns_setup_failed, 1,
			   __ATOMIC_RELAXED);
out:
	if (sk >= 0)
		close(sk);
	if (table_created)
		(void)nft_build_deltable(nfnl, NFPROTO_NETDEV, table_name);
}
