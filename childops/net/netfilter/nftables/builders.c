/*
 * builders.c
 *
 * Core nf_tables table/set/chain/rule builders and expression-plan plumbing
 * for nftables_churn.  The dispatched entry point lives in
 * churn.c.
 */

#include "internal.h"
#include "name-pool.h"

/*
 * NFT_MSG_NEWTABLE.  Family is randomised per call; flags=0.
 * NLM_F_CREATE | NLM_F_EXCL fails if the name already exists, which
 * is what we want — the caller rolls a fresh suffix per iteration.
 */
int nft_build_newtable(struct nfnl_ctx *ctx, __u8 family,
		   const char *table_name)
{
	unsigned char buf[NFNL_BUF_BYTES];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWTABLE,
			   NLM_F_CREATE | NLM_F_EXCL, family);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), NFTA_TABLE_NAME, table_name);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_TABLE_FLAGS, 0);
	if (!off)
		return -EIO;

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

int nft_build_deltable(struct nfnl_ctx *ctx, __u8 family,
		   const char *table_name)
{
	unsigned char buf[256];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_DELTABLE, 0, family);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), NFTA_TABLE_NAME, table_name);
	if (!off)
		return -EIO;

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

/*
 * NFT_MSG_NEWSET, anonymous, keyed on ipv4_addr (key_len 4).
 * NFTA_SET_ID is a userspace-assigned cookie so subsequent in-batch
 * commands could reference the set; we don't reference it but the
 * kernel still expects the attr present for newer set-create paths.
 *
 * Only NFT_SET_ANONYMOUS is set in NFTA_SET_FLAGS.  Combining
 * ANONYMOUS with any flag outside the {ANONYMOUS, CONSTANT, INTERVAL}
 * triple is rejected by nf_tables_newset() with -EOPNOTSUPP, which
 * silently disabled the entire NEWSET path for the lifetime of this
 * childop -- the set never committed, the nftables_churn_set_create_ok
 * stat never advanced, and every rule that bound a NFTA_LOOKUP_SET or
 * NFTA_DYNSET_SET_NAME to this name failed at commit because the set
 * did not exist.
 */
int nft_build_newset(struct nfnl_ctx *ctx, __u8 family,
		 const char *table_name, const char *set_name,
		 __u32 set_id)
{
	unsigned char buf[NFNL_BUF_BYTES];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWSET,
			   NLM_F_CREATE | NLM_F_EXCL, family);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), NFTA_SET_TABLE, table_name);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_SET_NAME, set_name);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_SET_FLAGS,
			   NFT_SET_ANONYMOUS);
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

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

int nft_build_delset(struct nfnl_ctx *ctx, __u8 family,
		 const char *table_name, const char *set_name)
{
	unsigned char buf[512];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_DELSET, 0, family);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), NFTA_SET_TABLE, table_name);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_SET_NAME, set_name);
	if (!off)
		return -EIO;

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

/*
 * NFT_MSG_NEWCHAIN.  When hook_present is true, emits NFTA_CHAIN_HOOK
 * (HOOKNUM=NF_INET_LOCAL_IN, PRIORITY=0) + NFTA_CHAIN_TYPE="filter"
 * — that's a base chain attached to the input hook.  Otherwise emits
 * a regular (no-hook) chain usable as a jump target.
 */
int nft_build_newchain(struct nfnl_ctx *ctx, __u8 family,
		   const char *table_name, const char *chain_name,
		   bool hook_present)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *hook_attr;
	size_t off, hook_off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWCHAIN,
			   NLM_F_CREATE | NLM_F_EXCL, family);
	if (!off)
		return -EIO;

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

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

typedef size_t (*nft_expr_builder_fn)(unsigned char *buf, size_t off,
				      size_t cap);
typedef size_t (*nft_expr_set_builder_fn)(unsigned char *buf, size_t off,
					  size_t cap, const char *set_name,
					  __u32 set_id);

/*
 * Per-expression descriptor.  Exactly one of build / build_set is
 * non-NULL; build_set is for expressions that need the (set_name,
 * set_id) pair (lookup, dynset).  odds_one_in is the ONE_IN(N) value
 * used by nft_expr_plan_randomize(): log/bitwise are picked with 1/4
 * odds, the rest with 1/3.  Table order is the wire-emission order:
 * nf_tables validates the expression sequence at commit time.
 */
struct nft_expr_desc {
	const char			*name;
	size_t				 plan_offset;
	size_t				 stat_offset;
	unsigned int			 odds_one_in;
	nft_expr_builder_fn		 build;
	nft_expr_set_builder_fn		 build_set;
};

#define NFT_EXPR_PLAN_OFF(field)	offsetof(struct nft_expr_plan, with_##field)
#define NFT_EXPR_STAT_OFF(field) \
	offsetof(struct stats_s, nftables_churn.field##_expr_emit)

static const struct nft_expr_desc nft_expr_table[] = {
	{ "payload",    NFT_EXPR_PLAN_OFF(payload),    NFT_EXPR_STAT_OFF(payload),    3, build_nft_payload_expr,    NULL },
	{ "meta",       NFT_EXPR_PLAN_OFF(meta),       NFT_EXPR_STAT_OFF(meta),       3, build_nft_meta_expr,       NULL },
	{ "lookup",     NFT_EXPR_PLAN_OFF(lookup),     NFT_EXPR_STAT_OFF(lookup),     3, NULL,                      build_nft_lookup_expr },
	{ "log",        NFT_EXPR_PLAN_OFF(log),        NFT_EXPR_STAT_OFF(log),        4, build_nft_log_expr,        NULL },
	{ "bitwise",    NFT_EXPR_PLAN_OFF(bitwise),    NFT_EXPR_STAT_OFF(bitwise),    4, build_nft_bitwise_expr,    NULL },
	{ "cmp",        NFT_EXPR_PLAN_OFF(cmp),        NFT_EXPR_STAT_OFF(cmp),        3, build_nft_cmp_expr,        NULL },
	{ "range",      NFT_EXPR_PLAN_OFF(range),      NFT_EXPR_STAT_OFF(range),      3, build_nft_range_expr,      NULL },
	{ "byteorder",  NFT_EXPR_PLAN_OFF(byteorder),  NFT_EXPR_STAT_OFF(byteorder),  3, build_nft_byteorder_expr,  NULL },
	{ "socket",     NFT_EXPR_PLAN_OFF(socket),     NFT_EXPR_STAT_OFF(socket),     3, build_nft_socket_expr,     NULL },
	{ "quota",      NFT_EXPR_PLAN_OFF(quota),      NFT_EXPR_STAT_OFF(quota),      3, build_nft_quota_expr,      NULL },
	{ "limit",      NFT_EXPR_PLAN_OFF(limit),      NFT_EXPR_STAT_OFF(limit),      3, build_nft_limit_expr,      NULL },
	{ "numgen",     NFT_EXPR_PLAN_OFF(numgen),     NFT_EXPR_STAT_OFF(numgen),     3, build_nft_numgen_expr,     NULL },
	{ "hash",       NFT_EXPR_PLAN_OFF(hash),       NFT_EXPR_STAT_OFF(hash),       3, build_nft_hash_expr,       NULL },
	{ "synproxy",   NFT_EXPR_PLAN_OFF(synproxy),   NFT_EXPR_STAT_OFF(synproxy),   3, build_nft_synproxy_expr,   NULL },
	{ "counter",    NFT_EXPR_PLAN_OFF(counter),    NFT_EXPR_STAT_OFF(counter),    3, build_nft_counter_expr,    NULL },
	{ "connlimit",  NFT_EXPR_PLAN_OFF(connlimit),  NFT_EXPR_STAT_OFF(connlimit),  3, build_nft_connlimit_expr,  NULL },
	{ "masq",       NFT_EXPR_PLAN_OFF(masq),       NFT_EXPR_STAT_OFF(masq),       3, build_nft_masq_expr,       NULL },
	{ "redir",      NFT_EXPR_PLAN_OFF(redir),      NFT_EXPR_STAT_OFF(redir),      3, build_nft_redir_expr,      NULL },
	{ "tproxy",     NFT_EXPR_PLAN_OFF(tproxy),     NFT_EXPR_STAT_OFF(tproxy),     3, build_nft_tproxy_expr,     NULL },
	{ "xfrm",       NFT_EXPR_PLAN_OFF(xfrm),       NFT_EXPR_STAT_OFF(xfrm),       3, build_nft_xfrm_expr,       NULL },
	{ "dup_netdev", NFT_EXPR_PLAN_OFF(dup_netdev), NFT_EXPR_STAT_OFF(dup_netdev), 3, build_nft_dup_netdev_expr, NULL },
	{ "dup_ipv4",   NFT_EXPR_PLAN_OFF(dup_ipv4),   NFT_EXPR_STAT_OFF(dup_ipv4),   3, build_nft_dup_ipv4_expr,   NULL },
	{ "dup_ipv6",   NFT_EXPR_PLAN_OFF(dup_ipv6),   NFT_EXPR_STAT_OFF(dup_ipv6),   3, build_nft_dup_ipv6_expr,   NULL },
	{ "fwd_netdev", NFT_EXPR_PLAN_OFF(fwd_netdev), NFT_EXPR_STAT_OFF(fwd_netdev), 3, build_nft_fwd_netdev_expr, NULL },
	{ "last",       NFT_EXPR_PLAN_OFF(last),       NFT_EXPR_STAT_OFF(last),       3, build_nft_last_expr,       NULL },
	{ "rt",         NFT_EXPR_PLAN_OFF(rt),         NFT_EXPR_STAT_OFF(rt),         3, build_nft_rt_expr,         NULL },
	{ "fib",        NFT_EXPR_PLAN_OFF(fib),        NFT_EXPR_STAT_OFF(fib),        3, build_nft_fib_expr,        NULL },
	{ "exthdr",     NFT_EXPR_PLAN_OFF(exthdr),     NFT_EXPR_STAT_OFF(exthdr),     3, build_nft_exthdr_expr,     NULL },
	{ "osf",        NFT_EXPR_PLAN_OFF(osf),        NFT_EXPR_STAT_OFF(osf),        3, build_nft_osf_expr,        NULL },
	{ "queue",      NFT_EXPR_PLAN_OFF(queue),      NFT_EXPR_STAT_OFF(queue),      3, build_nft_queue_expr,      NULL },
	{ "immediate",  NFT_EXPR_PLAN_OFF(immediate),  NFT_EXPR_STAT_OFF(immediate),  3, build_nft_immediate_expr,  NULL },
	{ "dynset",     NFT_EXPR_PLAN_OFF(dynset),     NFT_EXPR_STAT_OFF(dynset),     3, NULL,                      build_nft_dynset_expr },
	{ "ct",         NFT_EXPR_PLAN_OFF(ct),         NFT_EXPR_STAT_OFF(ct),         3, build_nft_ct_expr,         NULL },
	{ "objref",     NFT_EXPR_PLAN_OFF(objref),     NFT_EXPR_STAT_OFF(objref),     3, build_nft_objref_expr,     NULL },
};

#define NFT_EXPR_TABLE_LEN	(sizeof(nft_expr_table) / sizeof(nft_expr_table[0]))

static inline bool *plan_field(struct nft_expr_plan *plan, size_t off)
{
	return (bool *)((char *)plan + off);
}

static inline const bool *plan_field_const(const struct nft_expr_plan *plan,
					   size_t off)
{
	return (const bool *)((const char *)plan + off);
}

/* Roll one ONE_IN(d->odds_one_in) per descriptor to populate the plan. */
void nft_expr_plan_randomize(struct nft_expr_plan *plan)
{
	size_t i;

	memset(plan, 0, sizeof(*plan));
	for (i = 0; i < NFT_EXPR_TABLE_LEN; i++) {
		const struct nft_expr_desc *d = &nft_expr_table[i];

		if (d->odds_one_in && ONE_IN(d->odds_one_in))
			*plan_field(plan, d->plan_offset) = true;
	}
}

/*
 * Bump every per-expression stat counter whose plan flag is set.  Only
 * the random-plan callers invoke this — fixed-plan callers (e.g. the
 * L4-aware sweep) intentionally skip it to keep their own dedicated
 * rule_ok counter the only signal they emit.
 */
void nft_expr_plan_record_stats(const struct nft_expr_plan *plan)
{
	size_t i;

	for (i = 0; i < NFT_EXPR_TABLE_LEN; i++) {
		const struct nft_expr_desc *d = &nft_expr_table[i];
		unsigned long *counter;

		if (!*plan_field_const(plan, d->plan_offset))
			continue;
		counter = (unsigned long *)((char *)&shm->stats +
					    d->stat_offset);
		__atomic_add_fetch(counter, 1, __ATOMIC_RELAXED);
	}
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
 *
 * The optional expressions emitted before the trailing immediate
 * verdict are described by *plan, which is walked against
 * nft_expr_table[] in declared order.
 */
int nft_build_newrule(struct nfnl_ctx *ctx, __u8 family,
		  const char *table_name, const char *chain_name,
		  const char *target_chain, __u32 verdict_code,
		  __u64 position, const struct nft_expr_plan *plan,
		  const char *set_name, __u32 set_id)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *exprs, *elem, *expr_data, *imm_data, *verdict;
	size_t off, exprs_off, elem_off, expr_data_off, imm_data_off, verdict_off;
	size_t i;
	__u16 flags = NLM_F_CREATE;

	memset(buf, 0, sizeof(buf));
	if (position == 0)
		flags |= NLM_F_APPEND;
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWRULE, flags, family);
	if (!off)
		return -EIO;

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

	for (i = 0; i < NFT_EXPR_TABLE_LEN; i++) {
		const struct nft_expr_desc *d = &nft_expr_table[i];

		if (!*plan_field_const(plan, d->plan_offset))
			continue;
		if (d->build_set)
			off = d->build_set(buf, off, sizeof(buf),
					   set_name, set_id);
		else
			off = d->build(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

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

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

/*
 * NFT_MSG_DELRULE on (table, chain) with no NFTA_RULE_HANDLE — the
 * kernel treats this as "delete every rule in chain".  Races any
 * in-flight skb still draining through the input hook.
 */
int nft_build_delrule(struct nfnl_ctx *ctx, __u8 family,
		  const char *table_name, const char *chain_name)
{
	unsigned char buf[512];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_DELRULE, 0, family);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_TABLE, table_name);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_CHAIN, chain_name);
	if (!off)
		return -EIO;

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

/*
 * Pick a random nf_tables family per call.  inet (covers v4+v6),
 * bridge (link-layer), netdev (ingress).  Each family registers its
 * own afinfo and exercises a different commit-time path inside
 * nf_tables_api.
 */
__u8 nft_pick_family(void)
{
	static const __u8 families[] = {
		NFPROTO_INET, NFPROTO_BRIDGE, NFPROTO_NETDEV,
	};

	return RAND_ARRAY(families);
}

/*
 * Fill @out (capacity @cap) with a table name for the next netlink
 * batch.  Minority arm (ONE_IN(4)) draws a previously-recorded name
 * from the per-kind NAME_KIND_NETLINK_TABLE pool, optionally mutated
 * (1-byte flip / truncate / case-flip / suffix-near-max) so a later
 * netlink op can collide with an earlier op's NFTA_TABLE_NAME and
 * reach past the kernel's "no such table" reject into the real
 * commit/lookup handler path.  Majority arm generates a fresh
 * "<prefix><16-bit-hex>" -- preserving fresh-random diversity is
 * the dominant arm; over-narrowing to all-pool would delete the
 * reject-path warmth this generator already produces.  Either way
 * the chosen name is recorded into the pool so a sibling iteration
 * (or a per-syscall fuzzer drawing the same kind) can collide with
 * it.  The buffer is always NUL-terminated.
 */
void nft_fill_table_name(char *out, size_t cap, const char *prefix)
{
	int wrote;
	size_t len;

	if (cap < 2) {
		if (cap > 0)
			out[0] = '\0';
		return;
	}

	if (ONE_IN(4)) {
		size_t got = name_pool_draw_mutated(NAME_KIND_NETLINK_TABLE,
						    out, cap);

		if (got > 0) {
			if (got >= cap)
				got = cap - 1;
			out[got] = '\0';
			name_pool_record(NAME_KIND_NETLINK_TABLE, out, got);
			return;
		}
		/* empty pool -- fall through to fresh generation */
	}

	wrote = snprintf(out, cap, "%s%u", prefix,
			 (unsigned int)(rand32() & 0xffffu));
	if (wrote <= 0) {
		out[0] = '\0';
		return;
	}
	len = (size_t)wrote;
	if (len >= cap)
		len = cap - 1;
	name_pool_record(NAME_KIND_NETLINK_TABLE, out, len);
}
