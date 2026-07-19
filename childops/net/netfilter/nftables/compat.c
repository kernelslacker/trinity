/*
 * compat.c
 *
 * nft_compat per-hook validation sweep for nftables_churn.
 */

#include "internal.h"

static bool ns_unsupported_nft_compat_validate;

bool nft_compat_validate_unsupported(void)
{
	return ns_unsupported_nft_compat_validate;
}

/*
 * Drive the per-hook .validate path on xt-compat targets translated
 * through nft_compat.  Build a base chain at HOOKNUM and append a rule
 * carrying an NFTA_EXPR "target" wrapping TARGET_NAME with a zeroed
 * info blob.  Many (target, hook) combinations are per-target invalid:
 * pre-fix, the kernel translated the xt target without invoking the
 * per-hook .validate the native expression path runs, so a mismatched
 * pair could be accepted at commit and crash on first packet.  Upstream
 * 2f768d638d97 ("netfilter: nft_compat: enforce per-hook .validate on
 * xt-compat targets") closes that.  Returns the kernel reply code.
 */
static int nft_compat_pair_install(struct nfnl_ctx *ctx, __u8 family,
				   const char *table, const char *chain_name,
				   __u32 hooknum, const char *target_name)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *hook_attr, *exprs, *elem, *expr_data;
	size_t off, hook_off, exprs_off, elem_off, expr_data_off;
	unsigned char info[64];
	int rc;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWCHAIN,
			   NLM_F_CREATE | NLM_F_EXCL, family);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_TABLE, table);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_NAME, chain_name);
	if (!off)
		return -EIO;
	hook_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_CHAIN_HOOK | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_HOOK_HOOKNUM, hooknum);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_HOOK_PRIORITY, 0);
	if (!off)
		return -EIO;
	hook_attr = (struct nlattr *)(buf + hook_off);
	hook_attr->nla_len = (unsigned short)(off - hook_off);
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_TYPE, "filter");
	if (!off)
		return -EIO;
	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	rc = nfnl_send_recv(ctx, buf, off);
	if (rc != 0)
		return rc;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWRULE,
			   NLM_F_CREATE | NLM_F_APPEND, family);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_TABLE, table);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_CHAIN, chain_name);
	if (!off)
		return -EIO;
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
	off = nla_put_str(buf, off, sizeof(buf), NFTA_EXPR_NAME, "target");
	if (!off)
		return -EIO;
	expr_data_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf),
			  NFTA_TARGET_NAME, target_name);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_TARGET_REV, 0);
	if (!off)
		return -EIO;
	memset(info, 0, sizeof(info));
	off = nla_put(buf, off, sizeof(buf), NFTA_TARGET_INFO,
		      info, sizeof(info));
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
 * Sweep every (xt-compat target, NF_INET_* hook) pair against a fresh
 * IPv4 table, latching ns_unsupported_nft_compat_validate on the first
 * EOPNOTSUPP/EPROTONOSUPPORT (compat module absent or family not
 * registered) so sibling probes stop cheaply.
 */
void nft_compat_validate_sweep(struct nfnl_ctx *ctx)
{
	static const char * const targets[] = {
		"MASQUERADE", "SNAT", "DNAT", "TPROXY", "LOG", "MARK",
	};
	static const __u32 hooks[] = {
		NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD,
		NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING,
	};
	char table_name[32];
	char chain_name[32];
	size_t ti, hi;
	int rc;

	nft_fill_table_name(table_name, sizeof(table_name), "trcompat");
	rc = nft_build_newtable(ctx, NFPROTO_IPV4, table_name);
	if (rc != 0) {
		if (rc == -EOPNOTSUPP || rc == -EPROTONOSUPPORT ||
		    rc == -EAFNOSUPPORT)
			ns_unsupported_nft_compat_validate = true;
		return;
	}

	for (ti = 0; ti < ARRAY_SIZE(targets); ti++) {
		for (hi = 0; hi < ARRAY_SIZE(hooks); hi++) {
			snprintf(chain_name, sizeof(chain_name),
				 "cc_%zu_%zu", ti, hi);
			rc = nft_compat_pair_install(ctx, NFPROTO_IPV4,
						     table_name, chain_name,
						     hooks[hi], targets[ti]);
			__atomic_add_fetch(&shm->stats.nftables_churn.nft_compat_validate_per_hook_pairs,
					   1, __ATOMIC_RELAXED);
			if (rc == 0) {
				__atomic_add_fetch(&shm->stats.nftables_churn.nft_compat_validate_install_ok,
						   1, __ATOMIC_RELAXED);
			} else if (rc == -EOPNOTSUPP ||
				   rc == -EPROTONOSUPPORT) {
				__atomic_add_fetch(&shm->stats.nftables_churn.nft_compat_validate_unsupported,
						   1, __ATOMIC_RELAXED);
				ns_unsupported_nft_compat_validate = true;
				goto done;
			} else {
				__atomic_add_fetch(&shm->stats.nftables_churn.nft_compat_validate_install_fail,
						   1, __ATOMIC_RELAXED);
			}
		}
	}
done:
	(void)nft_build_deltable(ctx, NFPROTO_IPV4, table_name);
}
