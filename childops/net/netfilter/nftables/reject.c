/*
 * reject.c
 *
 * inet-family NF_INET_INGRESS / nft_reject sub-mode for nftables_churn.
 *
 * Targets the stale-IPCB write in nf_send_unreach() (net/ipv4/netfilter/
 * nf_reject_ipv4.c): when an nft_reject expression fires from an
 * NF_INET_INGRESS hook the skb arrives before ip_rcv_core() has zeroed
 * IPCB, so icmp_send() and __ip_options_echo() consume uninitialised IPCB
 * content from the prior user of the skb_buff arena.  Random per-syscall
 * fuzzing never assembles a coherent inet-family ingress chain carrying a
 * reject expression, so the hook/expression intersection is never reached.
 *
 * nft_reject_inet_validate() accepts NF_INET_INGRESS; the hook fires from
 * nf_hook_ingress() inside __netif_receive_skb_core(), before ip_rcv() --
 * so the skb traverses nf_send_unreach() with stale IPCB.
 *
 * Per invocation: NEWTABLE NFPROTO_INET, NEWCHAIN "ingress_rej" hooked at
 * NF_INET_INGRESS on "lo" (type filter, priority 0), NEWRULE carrying a
 * single "reject" expression (NFT_REJECT_ICMPX_UNREACH, code PORT_UNREACH),
 * one UDP sendto 127.0.0.1 to walk the ingress hook, then DELTABLE.
 *
 * Latch: ns_unsupported_nft_inet_ingress_reject (process-local static,
 * same semantics as ns_unsupported_nft_fwd_netdev_loop in fwd.c) on
 * EOPNOTSUPP / EPROTONOSUPPORT / EAFNOSUPPORT from NEWTABLE
 * (CONFIG_NF_TABLES_INET absent) or EOPNOTSUPP / ENOENT from NEWRULE
 * (CONFIG_NFT_REJECT absent).
 */

#include "internal.h"

#define REJECT_BUDGET_NS	150000000L	/* 150 ms wall cap */
#define REJECT_INNER_PORT	34569		/* UDP dst port for the probe */

static bool ns_unsupported_nft_inet_ingress_reject;

bool nft_inet_ingress_reject_unsupported(void)
{
	return ns_unsupported_nft_inet_ingress_reject;
}

/*
 * Build an NFPROTO_INET base chain hooked at NF_INET_INGRESS on @dev,
 * type "filter", priority 0.  Emits NFTA_HOOK_DEV the same way
 * build_netdev_ingress_chain() does in fwd.c for NFPROTO_NETDEV.
 */
static int build_inet_ingress_chain(struct nfnl_ctx *ctx, const char *table,
				    const char *chain, const char *dev)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *hook_attr;
	size_t off, hook_off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWCHAIN,
			   NLM_F_CREATE | NLM_F_EXCL, NFPROTO_INET);
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
			   NF_INET_INGRESS);
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

/*
 * Build a rule carrying a single "reject" expression:
 *   reject with icmpx port-unreachable
 *   (NFT_REJECT_ICMPX_UNREACH, NFTA_REJECT_ICMP_CODE=NFT_REJECT_ICMPX_PORT_UNREACH)
 *
 * This is a terminating expression -- no verdict attribute is needed;
 * nf_tables treats the absent verdict as NF_DROP internally and the
 * "reject" expression installs its own evaluator that sends the ICMP
 * before consuming the packet.
 */
static int build_reject_rule(struct nfnl_ctx *ctx, const char *table,
			     const char *chain)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *exprs, *elem, *expr_data;
	size_t off, exprs_off, elem_off, expr_data_off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWRULE,
			   NLM_F_CREATE | NLM_F_APPEND, NFPROTO_INET);
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

	/* "reject" expression element */
	elem_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_EXPR_NAME, "reject");
	if (!off)
		return -EIO;
	expr_data_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_REJECT_TYPE,
			   NFT_REJECT_ICMPX_UNREACH);
	if (!off)
		return -EIO;
	off = nla_put_u8(buf, off, sizeof(buf), NFTA_REJECT_ICMP_CODE,
			 (__u8)NFT_REJECT_ICMPX_PORT_UNREACH);
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

/*
 * inet-family NF_INET_INGRESS / nft_reject sweep.  Invoked from
 * nftables_churn_iter_submode_dispatch() at ONE_IN(8) odds.  lo is
 * already up at this point (nftables_churn_iter_open_rtnl() raised it
 * before submode_dispatch runs) so only the nfnl handle is needed.
 * Latches ns_unsupported_nft_inet_ingress_reject on the first CONFIG-
 * absent failure so subsequent invocations skip the NEWTABLE round-trip.
 */
void nft_inet_ingress_reject_sweep(struct nfnl_ctx *nfnl)
{
	char table_name[32];
	bool table_created = false;
	struct timespec t0;
	int sk = -1;
	int rc;

	__atomic_add_fetch(&shm->stats.nftables_churn.nft_inet_ingress_reject_runs,
			   1, __ATOMIC_RELAXED);
	(void)clock_gettime(CLOCK_MONOTONIC, &t0);

	nft_fill_table_name(table_name, sizeof(table_name), "trinrej");

	rc = nft_build_newtable(nfnl, NFPROTO_INET, table_name);
	if (rc != 0)
		goto fail;
	table_created = true;

	rc = build_inet_ingress_chain(nfnl, table_name, "ingress_rej", "lo");
	if (rc != 0)
		goto fail;

	rc = build_reject_rule(nfnl, table_name, "ingress_rej");
	if (rc != 0)
		goto fail;

	if (ns_since(&t0) >= REJECT_BUDGET_NS)
		goto out;

	/*
	 * Drive one UDP packet at 127.0.0.1 so it traverses the ingress
	 * hook on lo, fires the reject expression, and reaches
	 * nf_send_unreach() -> icmp_send() with the stale-IPCB content.
	 */
	sk = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk >= 0) {
		struct sockaddr_in dst;
		unsigned char payload[32];

		memset(&dst, 0, sizeof(dst));
		dst.sin_family      = AF_INET;
		dst.sin_port        = htons(REJECT_INNER_PORT);
		dst.sin_addr.s_addr = htonl(0x7f000001U);	/* 127.0.0.1 */

		generate_rand_bytes(payload, sizeof(payload));
		if (sendto(sk, payload, sizeof(payload), MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst)) > 0)
			__atomic_add_fetch(&shm->stats.nftables_churn.nft_inet_ingress_reject_probe_sent_ok,
					   1, __ATOMIC_RELAXED);
	}

	__atomic_add_fetch(&shm->stats.nftables_churn.nft_inet_ingress_reject_completed_ok,
			   1, __ATOMIC_RELAXED);
	goto out;

fail:
	/*
	 * Latch on CONFIG-absent shapes only.  EOPNOTSUPP / EPROTONOSUPPORT /
	 * EAFNOSUPPORT from NEWTABLE mean CONFIG_NF_TABLES_INET=n.
	 * EOPNOTSUPP / ENOENT from NEWRULE mean CONFIG_NFT_REJECT=n.
	 * Transient errors (ENOMEM, EBUSY) must not permanently disable the
	 * path -- fall through to the failure counter without latching.
	 */
	if (rc == -EOPNOTSUPP || rc == -EPROTONOSUPPORT ||
	    rc == -EAFNOSUPPORT || rc == -ENOENT)
		ns_unsupported_nft_inet_ingress_reject = true;
	__atomic_add_fetch(&shm->stats.nftables_churn.nft_inet_ingress_reject_setup_failed,
			   1, __ATOMIC_RELAXED);
out:
	if (sk >= 0)
		close(sk);
	if (table_created)
		(void)nft_build_deltable(nfnl, NFPROTO_INET, table_name);
}
