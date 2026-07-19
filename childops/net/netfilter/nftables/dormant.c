/*
 * dormant.c
 *
 * Dormant-table abort sub-mode for nftables_churn.
 */

#include "internal.h"

/*
 * Dormant-table abort sub-mode.  Drives the abort path the upstream
 * commit 63bac02786030 ("nf_tables: drop releases of nft_hook from
 * dormant tables on abort") repaired.  Single netlink batch:
 *   BATCH_BEGIN
 *   NEWTABLE flags=NFT_TABLE_F_DORMANT
 *   NEWCHAIN base chain attached to NF_INET_LOCAL_OUT (allocates the
 *     first nft_hook even though dormant tables don't register hooks)
 *   NEWCHAIN NLM_F_REPLACE on the same chain with a different
 *     hooknum/priority -- kernel allocates a fresh nft_hook and queues
 *     the prior one for release on commit
 *   NEWCHAIN NLM_F_REPLACE referencing a bogus NFTA_CHAIN_HANDLE --
 *     kernel rejects -ENOENT, the batch transitions to the abort path
 *   BATCH_END
 * Cleanup: NFT_MSG_DELTABLE outside the batch.
 */
void nft_dormant_abort_sweep(struct nfnl_ctx *ctx)
{
	static const __u32 hooks[] = {
		NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING,
		NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD,
	};
	unsigned char buf[2048];
	struct nlattr *hook_attr;
	char table_name[32];
	const char *chain_name = "dhkc";
	__u8 family = NFPROTO_INET;
	__u32 hk_a = RAND_ARRAY(hooks);
	__u32 hk_b = RAND_ARRAY(hooks);
	__u64 bogus_handle;
	size_t off = 0, msg_off, hook_off;
	__u16 chain_flags[] = { NLM_F_CREATE, NLM_F_REPLACE };
	__u32 chain_hook[]  = { hk_a, hk_b == hk_a ? (hk_a + 1) % 5 : hk_b };
	int i, rc;

	__atomic_add_fetch(&shm->stats.nftables_churn.nft_dormant_abort_iters,
			   1, __ATOMIC_RELAXED);

	nft_fill_table_name(table_name, sizeof(table_name), "trdorm");
	memset(buf, 0, sizeof(buf));

	/* BATCH_BEGIN with res_id steering the batch at the nftables subsys */
	off = nfnl_batch_begin(buf, off, sizeof(buf), nl_seq_next(&ctx->nl),
			       NFNL_SUBSYS_NFTABLES);
	if (!off)
		return;

	/* (a) NEWTABLE flags=NFT_TABLE_F_DORMANT */
	msg_off = off;
	off = nfnl_msg_put(buf, off, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWTABLE,
			   NLM_F_CREATE, family);
	if (!off)
		return;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_TABLE_NAME, table_name);
	if (!off)
		return;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_TABLE_FLAGS,
			   NFT_TABLE_F_DORMANT);
	if (!off)
		return;
	((struct nlmsghdr *)(buf + msg_off))->nlmsg_len = (__u32)(off - msg_off);

	/* (b) + (c): two NEWCHAINs on the same name, second is REPLACE with
	 * a different hook so the kernel allocates a fresh nft_hook and
	 * detaches the original. */
	for (i = 0; i < 2; i++) {
		msg_off = off;
		off = nfnl_msg_put(buf, off, sizeof(buf),
				   nl_seq_next(&ctx->nl),
				   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWCHAIN,
				   chain_flags[i], family);
		if (!off)
			return;
		off = nla_put_str(buf, off, sizeof(buf),
				  NFTA_CHAIN_TABLE, table_name);
		if (!off)
			return;
		off = nla_put_str(buf, off, sizeof(buf),
				  NFTA_CHAIN_NAME, chain_name);
		if (!off)
			return;
		hook_off = off;
		off = nla_put(buf, off, sizeof(buf),
			      NFTA_CHAIN_HOOK | NLA_F_NESTED, NULL, 0);
		if (!off)
			return;
		off = nla_put_be32(buf, off, sizeof(buf),
				   NFTA_HOOK_HOOKNUM, chain_hook[i]);
		if (!off)
			return;
		off = nla_put_be32(buf, off, sizeof(buf),
				   NFTA_HOOK_PRIORITY, (__u32)(i ? 10 : 0));
		if (!off)
			return;
		hook_attr = (struct nlattr *)(buf + hook_off);
		hook_attr->nla_len = (unsigned short)(off - hook_off);
		off = nla_put_str(buf, off, sizeof(buf),
				  NFTA_CHAIN_TYPE, "filter");
		if (!off)
			return;
		((struct nlmsghdr *)(buf + msg_off))->nlmsg_len =
			(__u32)(off - msg_off);
	}

	/* (d) NEWCHAIN NLM_F_REPLACE on a bogus NFTA_CHAIN_HANDLE.  Kernel
	 * walks lookup, fails -ENOENT, batch enters the abort path. */
	msg_off = off;
	off = nfnl_msg_put(buf, off, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWCHAIN,
			   NLM_F_REPLACE, family);
	if (!off)
		return;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_TABLE, table_name);
	if (!off)
		return;
	bogus_handle = ((__u64)htonl(0xdeadbeefU) << 32) |
		       (__u64)htonl(0xcafebabeU);
	off = nla_put(buf, off, sizeof(buf), NFTA_CHAIN_HANDLE,
		      &bogus_handle, sizeof(bogus_handle));
	if (!off)
		return;
	((struct nlmsghdr *)(buf + msg_off))->nlmsg_len = (__u32)(off - msg_off);

	/* (e) BATCH_END */
	off = nfnl_batch_end(buf, off, sizeof(buf), nl_seq_next(&ctx->nl),
			     NFNL_SUBSYS_NFTABLES);
	if (!off)
		return;

	/* Coalesced send + drain.  NLMSG_ERROR replies are expected (the
	 * bogus REPLACE intentionally fails to drive the abort path), so
	 * any negated-errno return is treated as success — the kernel
	 * walking the batch and rejecting it is exactly the path we are
	 * exercising.  Only -EIO (local send/recv failure inside
	 * nfnl_send_recv_batched) is a hard error; structural latches
	 * like ns_unsupported_nf_tables are left to per-op callers that
	 * can disambiguate a real EPERM/EOPNOTSUPP from the deliberate
	 * abort-path rejection. */
	rc = nfnl_send_recv_batched(ctx, buf, off);
	if (rc == -EIO) {
		__atomic_add_fetch(&shm->stats.nftables_churn.nft_dormant_abort_emsg,
				   1, __ATOMIC_RELAXED);
		return;
	}
	if (rc == -EPERM) {
		__atomic_add_fetch(&shm->stats.nftables_churn.nft_dormant_abort_eperm,
				   1, __ATOMIC_RELAXED);
		return;
	}

	__atomic_add_fetch(&shm->stats.nftables_churn.nft_dormant_abort_ok,
			   1, __ATOMIC_RELAXED);

	(void)nft_build_deltable(ctx, family, table_name);
}
