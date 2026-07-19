/*
 * l4frag.c
 *
 * L4-aware-on-fragment sub-mode for nftables_churn.
 */

#include "internal.h"

/*
 * L4-aware-on-fragment sub-mode (upstream 952e121c9613, 009d203e56db,
 * 0bf00859d7a5).  These commits hardened nf_socket_lookup, nf_tproxy_*,
 * nf_osf_match and the SCTP exthdr expression after they were observed
 * dereferencing a fragment's truncated transport header on packets that
 * traverse a netfilter chain registered ahead of NF_IP_PRI_CONNTRACK_DEFRAG
 * (-400) -- ip_defrag has not run yet, so the skb still carries an IP
 * fragment whose transport header is either short or absent on the
 * non-first frag.  Reaching the bug requires both:
 *   (a) an nft chain hooked at NF_IP_PRI_RAW_BEFORE_DEFRAG (-450) carrying
 *       at least one of those L4-aware expressions, and
 *   (b) raw IP fragments (MF=1 with payload, then MF=0 with fragoff>0)
 *       hitting that chain before defrag completes.
 * Random per-syscall fuzzing never lines those two up: nft chains it
 * synthesises pick priority 0 / NF_INET_LOCAL_IN, and nothing emits raw
 * fragments into the local hook path.
 *
 * Per invocation: NEWTABLE NFPROTO_IPV4, NEWSET (anonymous, ipv4_addr key
 * for the lookup expression to bind), NEWCHAIN aux (no hook, jump target),
 * NEWCHAIN base hooked at NF_INET_PRE_ROUTING priority -450, NEWRULE on
 * base carrying socket+tproxy+exthdr(SCTP)+osf, then a raw IPv4 fragment
 * pair (MF=1/off=0 then MF=0/off=2) sent into 127.0.0.1 over a SOCK_RAW
 * IPPROTO_RAW socket so the kernel transmits the iphdr verbatim.  Cleanup
 * deletes rule/set/table.  Protocol on the fragments is rolled per call
 * between UDP and SCTP so the SCTP exthdr eval is reached when the SCTP
 * module is loaded; rule install can EOPNOTSUPP-latch silently if SCTP is
 * absent and the per-expression validator rejects the exthdr binding.
 */
#define L4FRAG_FRAG1_PAYLOAD	16U
#define L4FRAG_FRAG2_PAYLOAD	8U
#define L4FRAG_PRIO_PRE_DEFRAG	((__u32)(__s32)-450)

#ifndef IP_MF
#define IP_MF			0x2000
#endif
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP		132
#endif

static int build_l4frag_chain(struct nfnl_ctx *ctx, const char *table,
			      const char *chain)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *hook_attr;
	size_t off, hook_off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWCHAIN,
			   NLM_F_CREATE | NLM_F_EXCL, NFPROTO_IPV4);
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
			   NF_INET_PRE_ROUTING);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_HOOK_PRIORITY,
			   L4FRAG_PRIO_PRE_DEFRAG);
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

static void l4frag_send_pair(__u8 protocol)
{
	int s = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	unsigned char pkt1[sizeof(struct iphdr) + L4FRAG_FRAG1_PAYLOAD];
	unsigned char pkt2[sizeof(struct iphdr) + L4FRAG_FRAG2_PAYLOAD];
	struct sockaddr_in dst;
	struct iphdr *ip;
	__u16 id_he = (__u16)(rand32() & 0xffffu);
	int i;

	if (s < 0) {
		__atomic_add_fetch(&shm->stats.nftables_churn.nft_l4frag_send_failed, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	memset(pkt1, 0, sizeof(pkt1));
	memset(pkt2, 0, sizeof(pkt2));
	memset(pkt1 + sizeof(struct iphdr), 0xa5, L4FRAG_FRAG1_PAYLOAD);
	memset(pkt2 + sizeof(struct iphdr), 0x5a, L4FRAG_FRAG2_PAYLOAD);

	for (i = 0; i < 2; i++) {
		ip = (struct iphdr *)(i ? pkt2 : pkt1);
		ip->version  = 4;
		ip->ihl      = 5;
		ip->tot_len  = htons((__u16)(i ? sizeof(pkt2) : sizeof(pkt1)));
		ip->id       = htons(id_he);
		/* first frag: IP_MF set, fragoff 0; second: MF clear,
		 * fragoff = first-frag payload / 8 (== 2). */
		ip->frag_off = htons((__u16)(i ? (L4FRAG_FRAG1_PAYLOAD / 8U)
						: IP_MF));
		ip->ttl      = 64;
		ip->protocol = protocol;
		ip->saddr    = htonl(0x7f000002U);
		ip->daddr    = htonl(0x7f000001U);
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_addr.s_addr = htonl(0x7f000001U);

	if (sendto(s, pkt1, sizeof(pkt1), MSG_DONTWAIT,
		   (struct sockaddr *)&dst, sizeof(dst)) > 0)
		__atomic_add_fetch(&shm->stats.nftables_churn.nft_l4frag_send_ok, 1,
				   __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.nftables_churn.nft_l4frag_send_failed, 1,
				   __ATOMIC_RELAXED);
	if (sendto(s, pkt2, sizeof(pkt2), MSG_DONTWAIT,
		   (struct sockaddr *)&dst, sizeof(dst)) > 0)
		__atomic_add_fetch(&shm->stats.nftables_churn.nft_l4frag_send_ok, 1,
				   __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.nftables_churn.nft_l4frag_send_failed, 1,
				   __ATOMIC_RELAXED);
	close(s);
}

void nft_l4_aware_frag_sweep(struct nfnl_ctx *nfnl)
{
	char table[32], anon_set[32];
	const char *base = "l4base";
	const char *aux  = "l4aux";
	__u32 set_id = rand32();
	__u8 proto = (rand32() & 1) ? IPPROTO_UDP : IPPROTO_SCTP;
	bool table_created = false;

	__atomic_add_fetch(&shm->stats.nftables_churn.nft_l4frag_iters, 1, __ATOMIC_RELAXED);

	snprintf(table, sizeof(table), "trl4f%u",
		 (unsigned int)(rand32() & 0xffffu));
	snprintf(anon_set, sizeof(anon_set), "__set%u",
		 (unsigned int)(rand32() & 0xffffu));

	if (nft_build_newtable(nfnl, NFPROTO_IPV4, table) != 0)
		return;
	table_created = true;

	(void)nft_build_newset(nfnl, NFPROTO_IPV4, table, anon_set, set_id);
	(void)nft_build_newchain(nfnl, NFPROTO_IPV4, table, aux, false);

	if (build_l4frag_chain(nfnl, table, base) != 0)
		goto out;
	__atomic_add_fetch(&shm->stats.nftables_churn.nft_l4frag_install_ok, 1,
			   __ATOMIC_RELAXED);

	/* with_socket, with_tproxy, with_exthdr (SCTP path), with_osf — every
	 * other expression slot disabled so the rule body is exclusively the
	 * L4-aware quartet under test.  No call to nft_expr_plan_record_stats
	 * here: this sweep tracks success via its own nft_l4frag_rule_ok and
	 * does not feed the per-expression churn counters. */
	{
		struct nft_expr_plan plan = {
			.with_socket = true,
			.with_tproxy = true,
			.with_exthdr = true,
			.with_osf    = true,
		};

		if (nft_build_newrule(nfnl, NFPROTO_IPV4, table, base, aux,
				  NFT_JUMP, 0, &plan, anon_set, set_id) == 0)
			__atomic_add_fetch(&shm->stats.nftables_churn.nft_l4frag_rule_ok, 1,
					   __ATOMIC_RELAXED);
	}

	l4frag_send_pair(proto);

	(void)nft_build_delrule(nfnl, NFPROTO_IPV4, table, base);
	(void)nft_build_delset(nfnl, NFPROTO_IPV4, table, anon_set);
out:
	if (table_created)
		(void)nft_build_deltable(nfnl, NFPROTO_IPV4, table);
}
