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
 * udp-dport-34569 payload+cmp guard followed by a "reject" expression
 * (NFT_REJECT_ICMPX_UNREACH, code PORT_UNREACH), one UDP sendto 127.0.0.1
 * with a Record-Route option installed via setsockopt(IP_OPTIONS) to arm
 * IPCB(skb)->opt.optlen, then DELTABLE.
 *
 * IP_OPTIONS / setsockopt rationale and oracle re-scope
 * -----------------------------------------------------
 * __ip_options_echo() opens with:
 *   if (sopt->optlen == 0) return 0;
 * and takes that return every time on an option-less datagram -- so the
 * oracle target was unreachable by construction in the original probe.
 *
 * A Record-Route setsockopt routes the TX path through ip_options_build()
 * which writes a populated struct ip_options into IPCB(skb)->opt before
 * loopback_xmit() enqueues the skb.  IPCB(skb)->opt.optlen is now
 * non-zero and __ip_options_echo() proceeds past the early-return.
 *
 * TX-built IPCB is self-consistent: ip_options_build() writes
 * header-relative byte offsets (opt->rr, opt->ts) that match the actual
 * IP header it also wrote.  __ip_options_echo() reads those offsets,
 * finds a valid RR option with pointer pointing to an empty slot, and
 * completes cleanly -- the bug target (stale foreign offsets pointing into
 * arbitrary skb data) is NOT triggered by this TX path.
 *
 * Re-scope: the stale-IPCB class requires a path that delivers genuinely
 * foreign IPCB content.  The natural reach is tunnel ingress (GRE/IPIP)
 * or GRO, where the outer packet's IPCB survives into the inner packet's
 * receive path without ip_rcv_core() zeroing it.  This probe now
 * exercises the code path reliably (opt.optlen != 0, __ip_options_echo()
 * fully executes), and nft_inet_ingress_reject_ipcb_opt_armed tracks
 * whether setsockopt succeeded.  Reaching the genuine stale-data variant
 * of the bug requires a follow-up that delivers the skb via a tunnel or
 * GRO path rather than plain loopback sendto.
 *
 * Port guard
 * ----------
 * The rule carries a payload+cmp guard for UDP dport == REJECT_INNER_PORT
 * (34569) so the chain does not reject arbitrary loopback traffic from
 * other trinity children during the 150 ms REJECT_BUDGET_NS window.
 *
 * Direct-syscall accounting
 * -------------------------
 * socket() / setsockopt() / sendto() / close() in this sweep are outside
 * the nfnl transport that nl_close() credits automatically.  They are
 * accumulated into a local tally and published via childop_direct_syscalls_add()
 * at sweep exit, so they no longer require an UNCOUNTED baseline entry.
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
 * Build a rule with three expressions in sequence:
 *
 *   1. payload: load UDP destination port (transport header, offset 2,
 *      length 2) into NFT_REG_1.  Guards the reject expression so only
 *      the probe's own datagram (dport == REJECT_INNER_PORT) is rejected;
 *      other loopback traffic from sibling children passes through.
 *
 *   2. cmp: compare NFT_REG_1 == htons(REJECT_INNER_PORT).  Non-matching
 *      packets short-circuit here and do not reach the reject expression.
 *
 *   3. reject: NFT_REJECT_ICMPX_UNREACH / NFT_REJECT_ICMPX_PORT_UNREACH.
 *      Terminating -- no verdict attribute needed.
 */
static int build_reject_rule(struct nfnl_ctx *ctx, const char *table,
			     const char *chain)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *exprs, *elem, *expr_data, *value;
	size_t off, exprs_off, elem_off, expr_data_off, value_off;
	__u16 inner_port_be = htons(REJECT_INNER_PORT);

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

	/* Expression 1: payload — load UDP dport (transport offset 2, len 2)
	 * into NFT_REG_1.  The dport field is at offset 2 in the UDP header
	 * (after src port), two bytes wide, big-endian. */
	elem_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_EXPR_NAME, "payload");
	if (!off)
		return -EIO;
	expr_data_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_PAYLOAD_DREG,
			   NFT_REG_1);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_PAYLOAD_BASE,
			   NFT_PAYLOAD_TRANSPORT_HEADER);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_PAYLOAD_OFFSET, 2);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_PAYLOAD_LEN, 2);
	if (!off)
		return -EIO;
	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);

	/* Expression 2: cmp eq — compare NFT_REG_1 == htons(REJECT_INNER_PORT).
	 * Packets that do not match short-circuit here without hitting the
	 * reject expression, preventing cross-childop interference. */
	elem_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_EXPR_NAME, "cmp");
	if (!off)
		return -EIO;
	expr_data_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_CMP_SREG, NFT_REG_1);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_CMP_OP, NFT_CMP_EQ);
	if (!off)
		return -EIO;
	value_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_CMP_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), NFTA_DATA_VALUE,
		      &inner_port_be, sizeof(inner_port_be));
	if (!off)
		return -EIO;
	value = (struct nlattr *)(buf + value_off);
	value->nla_len = (unsigned short)(off - value_off);
	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);

	/* Expression 3: reject with icmpx port-unreachable.
	 * Terminating -- no verdict attribute; nf_tables installs the reject
	 * evaluator which sends ICMP before consuming the packet. */
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
	/*
	 * A minimal IPv4 Record-Route option (IPOPT_RR, len=7, ptr=4 + one
	 * empty 4-byte recording slot) plus an IPOPT_NOP byte to pad the
	 * option block to a 4-byte boundary (required by ip_options_get()).
	 * Passing this to setsockopt(IPPROTO_IP, IP_OPTIONS) routes the
	 * sendto() through ip_options_build(), which writes a populated
	 * struct ip_options into IPCB(skb)->opt.  This bypasses the
	 *   if (sopt->optlen == 0) return 0;
	 * early-return in __ip_options_echo() so the full ingress-ICMP path
	 * is exercised.
	 *
	 * The resulting IPCB is TX-built and self-consistent: ip_options_build()
	 * writes header-relative offsets (opt->rr = 20 for a 20-byte base
	 * header, opt->rr_needaddr = 1) that match the actual IP header.
	 * __ip_options_echo() therefore executes cleanly -- the genuine
	 * stale-IPCB bug (foreign offsets pointing into arbitrary arena data)
	 * requires a tunnel/GRO path delivering a skb whose IPCB was set by
	 * a prior user of the arena without ip_rcv_core() zeroing it.  See
	 * "Re-scope" note in the file header.
	 */
	static const unsigned char rr_opt[8] = {
		IPOPT_RR, 7, 4,         /* type, len=7, ptr=4 (next slot) */
		0, 0, 0, 0,             /* one empty 4-byte recording slot */
		IPOPT_NOP,              /* padding to 4-byte boundary */
	};
	char table_name[32];
	bool table_created = false;
	struct timespec t0;
	unsigned long dc = 0;	/* direct-syscall tally for this sweep */
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
	 * nf_send_unreach() -> icmp_send() -> __ip_options_echo() with
	 * a non-zero opt.optlen so the full code path executes.
	 *
	 * setsockopt(IP_OPTIONS) arms the TX path through ip_options_build(),
	 * which writes a valid IPCB(skb)->opt block before the skb enters lo.
	 * See rr_opt above for the TX-built IPCB / re-scope discussion.
	 */
	sk = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	dc++;	/* socket() */
	if (sk >= 0) {
		struct sockaddr_in dst;
		unsigned char payload[32];

		if (setsockopt(sk, IPPROTO_IP, IP_OPTIONS,
			       rr_opt, sizeof(rr_opt)) == 0)
			__atomic_add_fetch(
				&shm->stats.nftables_churn.nft_inet_ingress_reject_ipcb_opt_armed,
				1, __ATOMIC_RELAXED);
		dc++;	/* setsockopt() */

		memset(&dst, 0, sizeof(dst));
		dst.sin_family      = AF_INET;
		dst.sin_port        = htons(REJECT_INNER_PORT);
		dst.sin_addr.s_addr = htonl(0x7f000001U);	/* 127.0.0.1 */

		generate_rand_bytes(payload, sizeof(payload));
		if (sendto(sk, payload, sizeof(payload), MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst)) > 0)
			__atomic_add_fetch(&shm->stats.nftables_churn.nft_inet_ingress_reject_probe_sent_ok,
					   1, __ATOMIC_RELAXED);
		dc++;	/* sendto() */
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
	if (sk >= 0) {
		close(sk);
		dc++;	/* close() */
	}
	if (table_created)
		(void)nft_build_deltable(nfnl, NFPROTO_INET, table_name);

	/*
	 * Publish the direct-syscall tally (socket + setsockopt + sendto +
	 * close) accumulated above.  These calls are outside the nfnl
	 * transport that nl_close() credits automatically; childop_direct_
	 * syscalls_add() here ensures they reach the per-op accounting.
	 */
	if (dc > 0) {
		struct childdata *tc = this_child();
		const enum child_op_type op_tc = tc ? tc->op_type
						    : NR_CHILD_OP_TYPES;

		if ((int)op_tc >= 0 && op_tc < NR_CHILD_OP_TYPES)
			childop_direct_syscalls_add(op_tc, dc);
	}
}
