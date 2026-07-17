/*
 * nftables_churn - nftables table/chain/set/rule churn racing live traffic.
 *
 * Targets the transaction-commit teardown in net/netfilter/nf_tables_api.c
 * (nf_tables_commit / nft_chain_commit_drop_policy / nft_rule_destroy /
 * nft_set_destroy) against an in-flight skb traversing the hook -- the
 * commit-vs-softirq-walk window behind the recent nftables CVE lineage
 * (nft_verdict UAF, anonymous-set double-free, nft_setelem/rbtree/chain
 * reference races).  Flat per-syscall fuzz never assembles a coherent
 * table -> chain -> rule tree plus traffic into the registered hook, so
 * the commit machinery never engages.
 *
 * Sequence per invocation inside a userns_run_in_ns grandchild (identity
 * userns + CLONE_NEWNET, _exit reaps): NEWTABLE with family rotated across
 * {NFPROTO_INET, NFPROTO_BRIDGE, NFPROTO_NETDEV} per iter so each per-family
 * afinfo registration commits; NEWSET anonymous (NFT_SET_ANONYMOUS,
 * key_len=4, ipv4_addr); NEWCHAIN "chain_aux" (regular, no hook) before
 * NEWCHAIN "chain_in" (NF_INET_LOCAL_IN, prio 0, "filter") so the base
 * chain's NFT_JUMP/NFT_GOTO to chain_aux binds on first commit; NEWRULE on
 * chain_in with an immediate verdict (NFT_JUMP or NFT_GOTO) arming the
 * verdict-UAF window; AF_INET SOCK_DGRAM burst to 127.0.0.1 walks
 * nf_hook_slow across the fresh chain; mid-traffic NEWRULE at
 * NFTA_RULE_POSITION=1 (position-insert has its own commit codepath); then
 * DELRULE (no handle -> flush all rules) and DELSET/DELTABLE racing the
 * still-draining skbs.
 *
 * Brick-safety: private netns only, loopback only, no host ruleset ever
 * touched; burst BUDGETED+JITTER around base 3 with STORM_BUDGET_NS 200 ms
 * wall cap and 64-frame ceiling; all I/O MSG_DONTWAIT with SO_RCVTIMEO=1s
 * on the nfnetlink socket.
 *
 * Latches: userns -EPERM latches the op off for the child's life.  Inside
 * the grandchild: ns_unsupported_nfnetlink on NETLINK_NETFILTER socket
 * EPROTONOSUPPORT (CONFIG_NF_NETLINK=n); ns_unsupported_nf_tables on
 * NEWTABLE EOPNOTSUPP/EAFNOSUPPORT/EPROTONOSUPPORT.
 */

#include "nftables-churn-internal.h"
#include "name-pool.h"

#include "kernel/socket.h"
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

/* Per-grandchild latched gates.  Inherited as false at grandchild
 * fork time (the persistent child never writes them -- the in-ns
 * callback runs exclusively in transient grandchildren) and flipped
 * on the first config-absent rejection from the corresponding
 * subsystem.  Die with the grandchild on _exit(); each subsequent
 * grandchild re-discovers the latch in its own fresh netns.  The
 * EPROTONOSUPPORT / EAFNOSUPPORT / EOPNOTSUPP detection arms are
 * preserved because a fresh user namespace cannot manufacture an
 * absent kernel CONFIG -- the gate still short-circuits the rest of
 * the grandchild's iteration once it fires. */
static bool ns_unsupported_nfnetlink;
static bool ns_unsupported_nf_tables;
static bool ns_unsupported_inet;
static bool ns_unsupported_nft_compat_validate;
static bool ns_unsupported_xt_ct;
static bool ns_unsupported_nft_fwd_netdev_loop;

static bool lo_brought_up;

/* Master gate: persistent across iterations in the persistent child.
 * Set when userns_run_in_ns returns -EPERM (hardened userns policy
 * refused CLONE_NEWUSER -- typically user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  The per-grandchild gates
 * above die with the grandchild; helper-EPERM is the only signal
 * that survives long enough to short-circuit subsequent invocations. */
static bool ns_unsupported_nftables;

static void warn_once_unsupported_nftables(const char *reason, int err)
{
	if (ns_unsupported_nftables)
		return;
	ns_unsupported_nftables = true;
	outputerr("nftables_churn: %s failed (errno=%d), latching unsupported_nftables\n",
		  reason, err);
}

/*
 * Bring lo up inside the private netns.  A freshly-unshared netns
 * has lo present but DOWN; the loopback sendto in step 9 silently
 * drops if lo is down, and without the rx-side completion the input
 * hook never runs and the rule's verdict path stays cold.  Setlink
 * errors are ignored — a kernel that refuses lo up is also one where
 * the rest of the sequence will fail visibly.
 */
/*
 * NFT_MSG_NEWTABLE.  Family is randomised per call; flags=0.
 * NLM_F_CREATE | NLM_F_EXCL fails if the name already exists, which
 * is what we want — the caller rolls a fresh suffix per iteration.
 */
static int build_newtable(struct nfnl_ctx *ctx, __u8 family,
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

static int build_deltable(struct nfnl_ctx *ctx, __u8 family,
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
static int build_newset(struct nfnl_ctx *ctx, __u8 family,
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

static int build_delset(struct nfnl_ctx *ctx, __u8 family,
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
static int build_newchain(struct nfnl_ctx *ctx, __u8 family,
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



/*
 * Plan describing which optional expressions a NEWRULE message should
 * carry.  Replaces a 34-bool argument list to build_newrule().  Named
 * fields (rather than a flag array) keep designated-initialiser call
 * sites and debugger inspection legible.
 */
struct nft_expr_plan {
	bool with_payload;
	bool with_meta;
	bool with_lookup;
	bool with_log;
	bool with_bitwise;
	bool with_cmp;
	bool with_range;
	bool with_byteorder;
	bool with_socket;
	bool with_quota;
	bool with_limit;
	bool with_numgen;
	bool with_hash;
	bool with_synproxy;
	bool with_counter;
	bool with_connlimit;
	bool with_masq;
	bool with_redir;
	bool with_tproxy;
	bool with_xfrm;
	bool with_dup_netdev;
	bool with_dup_ipv4;
	bool with_dup_ipv6;
	bool with_fwd_netdev;
	bool with_last;
	bool with_rt;
	bool with_fib;
	bool with_exthdr;
	bool with_osf;
	bool with_queue;
	bool with_immediate;
	bool with_dynset;
	bool with_ct;
	bool with_objref;
};

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
	offsetof(struct stats_s, nftables_churn_##field##_expr_emit)

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
static void nft_expr_plan_randomize(struct nft_expr_plan *plan)
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
static void nft_expr_plan_record_stats(const struct nft_expr_plan *plan)
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
static int build_newrule(struct nfnl_ctx *ctx, __u8 family,
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
static int build_delrule(struct nfnl_ctx *ctx, __u8 family,
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
static __u8 pick_family(void)
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
static void nft_fill_table_name(char *out, size_t cap, const char *prefix)
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
static void nft_compat_validate_sweep(struct nfnl_ctx *ctx)
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
	rc = build_newtable(ctx, NFPROTO_IPV4, table_name);
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
			__atomic_add_fetch(&shm->stats.nft_compat_validate_per_hook_pairs,
					   1, __ATOMIC_RELAXED);
			if (rc == 0) {
				__atomic_add_fetch(&shm->stats.nft_compat_validate_install_ok,
						   1, __ATOMIC_RELAXED);
			} else if (rc == -EOPNOTSUPP ||
				   rc == -EPROTONOSUPPORT) {
				__atomic_add_fetch(&shm->stats.nft_compat_validate_unsupported,
						   1, __ATOMIC_RELAXED);
				ns_unsupported_nft_compat_validate = true;
				goto done;
			} else {
				__atomic_add_fetch(&shm->stats.nft_compat_validate_install_fail,
						   1, __ATOMIC_RELAXED);
			}
		}
	}
done:
	(void)build_deltable(ctx, NFPROTO_IPV4, table_name);
}

/*
 * xt_CT v1+v2 usersize sub-mode (upstream 8bedb6c46945 "netfilter: xt_CT:
 * fix kernel infoleak via xt_get_target").  Drives the iptables sockopt
 * reply path -- IPT/IP6T_SO_GET_ENTRIES -> xt_target_to_user -- where a
 * usersize/targetsize mismatch historically leaked the trailing
 * kernel-internal "struct nf_conn *ct" (and timeout pointer at revision 2)
 * into the userspace reply.  Each iteration installs a "raw" table with
 * one PRE_ROUTING rule whose target is xt_CT (revision selectable), then
 * walks GET_INFO -> GET_ENTRIES, then drops in an empty replace and
 * closes.  Independent latch (ns_unsupported_xt_ct) so a kernel without
 * xt_CT or CAP_NET_ADMIN pays the EFAIL once.
 *
 * Layouts come from local-named mirrors -- including <linux/netfilter_ipv4
 * /ip_tables.h> here would clash with this TU's pre-existing <net/if.h>
 * via <linux/in.h> / <linux/if.h>.  The mirrors track the stable kernel
 * UAPI for ip_tables / ip6_tables / x_tables.
 */
#ifndef IPT_SO_SET_REPLACE
#define IPT_SO_SET_REPLACE	64
#endif
#ifndef IPT_SO_GET_INFO
#define IPT_SO_GET_INFO		64
#endif
#ifndef IPT_SO_GET_ENTRIES
#define IPT_SO_GET_ENTRIES	65
#endif
#ifndef IP6T_SO_SET_REPLACE
#define IP6T_SO_SET_REPLACE	64
#endif
#ifndef IP6T_SO_GET_INFO
#define IP6T_SO_GET_INFO	64
#endif
#ifndef IP6T_SO_GET_ENTRIES
#define IP6T_SO_GET_ENTRIES	65
#endif
#ifndef IPPROTO_RAW
#define IPPROTO_RAW		255
#endif
#ifndef XT_CT_NOTRACK
#define XT_CT_NOTRACK		(1U << 0)
#endif
#define XT_LC_TABLE_MAXNAMELEN	32
#define XT_LC_EXT_MAXNAMELEN	29
#define XT_LC_FUNC_MAXNAMELEN	30
#define XT_LC_NUMHOOKS		5
#define XT_LC_ALIGN8(x)		(((x) + 7U) & ~7U)

/* Locally-named struct mirrors.  Layouts mirror linux/netfilter/x_tables.h
 * and linux/netfilter_ipv{4,6}/ip{,6}_tables.h as of upstream 6.x. */
struct xt_lc_counters {
	__u64	pcnt, bcnt;
};

struct xt_lc_entry_target_hdr {
	__u16	target_size;
	char	name[XT_LC_EXT_MAXNAMELEN];
	__u8	revision;
};	/* 32 bytes; layout matches xt_entry_target.u.user */

struct xt_lc_ip4 {
	__u32	src, dst;
	__u32	smsk, dmsk;
	char	iniface[16], outiface[16];
	unsigned char iniface_mask[16], outiface_mask[16];
	__u16	proto;
	__u8	flags, invflags;
};

struct xt_lc_ip6 {
	__u32	src[4], dst[4];
	__u32	smsk[4], dmsk[4];
	char	iniface[16], outiface[16];
	unsigned char iniface_mask[16], outiface_mask[16];
	__u16	proto;
	__u8	tos;
	__u8	flags, invflags;
};

struct xt_lc_ipt_entry {
	struct xt_lc_ip4		ip;
	unsigned int			nfcache;
	__u16				target_offset, next_offset;
	unsigned int			comefrom;
	struct xt_lc_counters		counters;
};

struct xt_lc_ip6t_entry {
	struct xt_lc_ip6		ipv6;
	unsigned int			nfcache;
	__u16				target_offset, next_offset;
	unsigned int			comefrom;
	struct xt_lc_counters		counters;
};

struct xt_lc_ipt_replace {
	char				name[XT_LC_TABLE_MAXNAMELEN];
	unsigned int			valid_hooks;
	unsigned int			num_entries;
	unsigned int			size;
	unsigned int			hook_entry[XT_LC_NUMHOOKS];
	unsigned int			underflow[XT_LC_NUMHOOKS];
	unsigned int			num_counters;
	struct xt_lc_counters		*counters;
};

struct xt_lc_getinfo {
	char				name[XT_LC_TABLE_MAXNAMELEN];
	unsigned int			valid_hooks;
	unsigned int			hook_entry[XT_LC_NUMHOOKS];
	unsigned int			underflow[XT_LC_NUMHOOKS];
	unsigned int			num_entries;
	unsigned int			size;
};

struct xt_lc_get_entries_hdr {
	char				name[XT_LC_TABLE_MAXNAMELEN];
	unsigned int			size;
};

/* xt_CT target_info mirrors.  Sysroot's xt_ct_target_info_v1 may or may
 * not be present; local naming avoids any collision and pins the trailing
 * kernel-pointer slot count per revision (the slot xt_target_to_user
 * historically copied back without trimming via usersize). */
struct xtct_lc_v1 {
	__u16	flags;
	__u16	zone;
	__u32	ct_events;
	__u32	exp_events;
	char	helper[16];
	char	timeout[32];
	__u64	_kpad_ct;	/* mirrors kernel's trailing nf_conn *ct */
} __attribute__((aligned(8)));

struct xtct_lc_v2 {
	__u16	flags;
	__u16	zone;
	__u32	ct_events;
	__u32	exp_events;
	char	helper[16];
	char	timeout[32];
	__u64	_kpad_ct;
	__u64	_kpad_to;	/* extra trailing timeout pointer at v2 */
} __attribute__((aligned(8)));

static void xt_ct_emit_target(unsigned char *t_off, const char *name,
			      __u8 revision, __u16 target_size_total)
{
	struct xt_lc_entry_target_hdr *th = (struct xt_lc_entry_target_hdr *)t_off;

	th->target_size = target_size_total;
	th->revision    = revision;
	strncpy(th->name, name, XT_LC_EXT_MAXNAMELEN - 1);
}

static void xt_ct_emit_std_policy(unsigned char *e_off, unsigned int entry_hdr_sz,
				  unsigned int policy_sz, unsigned int std_total,
				  bool ipv6)
{
	int *verdict;

	if (ipv6) {
		struct xt_lc_ip6t_entry *e = (struct xt_lc_ip6t_entry *)e_off;

		e->target_offset = (__u16)entry_hdr_sz;
		e->next_offset   = (__u16)policy_sz;
	} else {
		struct xt_lc_ipt_entry *e = (struct xt_lc_ipt_entry *)e_off;

		e->target_offset = (__u16)entry_hdr_sz;
		e->next_offset   = (__u16)policy_sz;
	}
	xt_ct_emit_target(e_off + entry_hdr_sz, "", 0, (__u16)std_total);
	verdict = (int *)(e_off + entry_hdr_sz +
			  XT_LC_ALIGN8(sizeof(struct xt_lc_entry_target_hdr)));
	*verdict = -NF_ACCEPT - 1;
}

static void xt_ct_emit_error(unsigned char *e_off, unsigned int entry_hdr_sz,
			     unsigned int error_sz, unsigned int err_total,
			     bool ipv6)
{
	unsigned char *errname;

	if (ipv6) {
		struct xt_lc_ip6t_entry *e = (struct xt_lc_ip6t_entry *)e_off;

		e->target_offset = (__u16)entry_hdr_sz;
		e->next_offset   = (__u16)error_sz;
	} else {
		struct xt_lc_ipt_entry *e = (struct xt_lc_ipt_entry *)e_off;

		e->target_offset = (__u16)entry_hdr_sz;
		e->next_offset   = (__u16)error_sz;
	}
	xt_ct_emit_target(e_off + entry_hdr_sz, "ERROR", 0, (__u16)err_total);
	errname = e_off + entry_hdr_sz +
		  XT_LC_ALIGN8(sizeof(struct xt_lc_entry_target_hdr));
	memcpy(errname, "ERROR", 5);
}

static void xt_ct_fill_replace_hdr(unsigned char *buf, unsigned int rule_sz,
				   unsigned int policy_sz, unsigned int total_sz,
				   struct xt_lc_counters *counters_scratch,
				   unsigned int num_entries)
{
	struct xt_lc_ipt_replace *r = (struct xt_lc_ipt_replace *)buf;

	memcpy(r->name, "raw", 4);
	r->valid_hooks  = (1U << NF_INET_PRE_ROUTING) | (1U << NF_INET_LOCAL_OUT);
	r->num_entries  = num_entries;
	r->size         = total_sz;
	r->hook_entry[NF_INET_PRE_ROUTING] = 0;
	r->underflow[NF_INET_PRE_ROUTING]  = rule_sz;
	r->hook_entry[NF_INET_LOCAL_OUT]   = rule_sz + policy_sz;
	r->underflow[NF_INET_LOCAL_OUT]    = rule_sz + policy_sz;
	r->num_counters = num_entries;
	r->counters     = counters_scratch;
}

static void xt_ct_probe_one(bool ipv6, __u8 revision)
{
	unsigned char buf[1536];
	unsigned char get_buf[1536];
	struct xt_lc_counters counters_scratch[8];
	unsigned int hdr_sz, entry_hdr_sz;
	unsigned int target_hdr_sz, target_data_sz;
	unsigned int std_total, err_total;
	unsigned int rule_sz, policy_sz, error_sz, total_sz;
	unsigned int off, t_data_off;
	int fd, level, sockopt_set, sockopt_get_info, sockopt_get_entries;

	__atomic_add_fetch(&shm->stats.xt_ct_iters, 1, __ATOMIC_RELAXED);

	if (ipv6) {
		level                = IPPROTO_IPV6;
		sockopt_set          = IP6T_SO_SET_REPLACE;
		sockopt_get_info     = IP6T_SO_GET_INFO;
		sockopt_get_entries  = IP6T_SO_GET_ENTRIES;
		entry_hdr_sz         = (unsigned int)sizeof(struct xt_lc_ip6t_entry);
		fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	} else {
		level                = IPPROTO_IP;
		sockopt_set          = IPT_SO_SET_REPLACE;
		sockopt_get_info     = IPT_SO_GET_INFO;
		sockopt_get_entries  = IPT_SO_GET_ENTRIES;
		entry_hdr_sz         = (unsigned int)sizeof(struct xt_lc_ipt_entry);
		fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	}
	hdr_sz = (unsigned int)sizeof(struct xt_lc_ipt_replace);
	if (fd < 0) {
		if (errno == EPERM) {
			ns_unsupported_xt_ct = true;
			__atomic_add_fetch(&shm->stats.xt_ct_eperm,
					   1, __ATOMIC_RELAXED);
		} else if (errno == EAFNOSUPPORT ||
			   errno == EPROTONOSUPPORT) {
			ns_unsupported_xt_ct = true;
			__atomic_add_fetch(&shm->stats.xt_ct_unsupported,
					   1, __ATOMIC_RELAXED);
		}
		return;
	}

	target_hdr_sz  = (unsigned int)XT_LC_ALIGN8(sizeof(struct xt_lc_entry_target_hdr));
	target_data_sz = (revision == 2)
		? (unsigned int)XT_LC_ALIGN8(sizeof(struct xtct_lc_v2))
		: (unsigned int)XT_LC_ALIGN8(sizeof(struct xtct_lc_v1));
	std_total      = target_hdr_sz + (unsigned int)XT_LC_ALIGN8(sizeof(int));
	err_total      = target_hdr_sz +
			 (unsigned int)XT_LC_ALIGN8(XT_LC_FUNC_MAXNAMELEN);

	rule_sz   = entry_hdr_sz + target_hdr_sz + target_data_sz;
	policy_sz = entry_hdr_sz + std_total;
	error_sz  = entry_hdr_sz + err_total;
	total_sz  = rule_sz + 2 * policy_sz + error_sz;

	if (hdr_sz + total_sz > sizeof(buf))
		goto out;

	memset(buf, 0, sizeof(buf));
	memset(counters_scratch, 0, sizeof(counters_scratch));
	xt_ct_fill_replace_hdr(buf, rule_sz, policy_sz, total_sz,
			       counters_scratch, 4);

	off = hdr_sz;

	/* Entry 1: PRE_ROUTING rule -- xt_CT target, no match. */
	if (ipv6) {
		struct xt_lc_ip6t_entry *e = (struct xt_lc_ip6t_entry *)(buf + off);

		e->target_offset = (__u16)entry_hdr_sz;
		e->next_offset   = (__u16)rule_sz;
	} else {
		struct xt_lc_ipt_entry *e = (struct xt_lc_ipt_entry *)(buf + off);

		e->target_offset = (__u16)entry_hdr_sz;
		e->next_offset   = (__u16)rule_sz;
	}
	xt_ct_emit_target(buf + off + entry_hdr_sz, "CT", revision,
			  (__u16)(target_hdr_sz + target_data_sz));
	t_data_off = off + entry_hdr_sz + target_hdr_sz;
	if (revision == 2) {
		struct xtct_lc_v2 *info = (struct xtct_lc_v2 *)(buf + t_data_off);

		info->flags      = XT_CT_NOTRACK;
		info->zone       = (__u16)(rand32() & 0xffff);
		info->ct_events  = rand32();
		info->exp_events = rand32();
		generate_rand_bytes((unsigned char *)info->helper,
				    sizeof(info->helper));
		generate_rand_bytes((unsigned char *)info->timeout,
				    sizeof(info->timeout));
	} else {
		struct xtct_lc_v1 *info = (struct xtct_lc_v1 *)(buf + t_data_off);

		info->flags      = XT_CT_NOTRACK;
		info->zone       = (__u16)(rand32() & 0xffff);
		info->ct_events  = rand32();
		info->exp_events = rand32();
		generate_rand_bytes((unsigned char *)info->helper,
				    sizeof(info->helper));
		generate_rand_bytes((unsigned char *)info->timeout,
				    sizeof(info->timeout));
	}
	off += rule_sz;

	/* Entries 2 + 3: PRE_ROUTING policy + LOCAL_OUT policy (std ACCEPT). */
	xt_ct_emit_std_policy(buf + off, entry_hdr_sz, policy_sz, std_total, ipv6);
	off += policy_sz;
	xt_ct_emit_std_policy(buf + off, entry_hdr_sz, policy_sz, std_total, ipv6);
	off += policy_sz;

	/* Entry 4: error sentinel. */
	xt_ct_emit_error(buf + off, entry_hdr_sz, error_sz, err_total, ipv6);

	if (setsockopt(fd, level, sockopt_set, buf,
		       (socklen_t)(hdr_sz + total_sz)) < 0) {
		if (errno == EPERM) {
			ns_unsupported_xt_ct = true;
			__atomic_add_fetch(&shm->stats.xt_ct_eperm,
					   1, __ATOMIC_RELAXED);
		} else if (errno == ENOENT || errno == EOPNOTSUPP ||
			   errno == ENOPROTOOPT) {
			ns_unsupported_xt_ct = true;
			__atomic_add_fetch(&shm->stats.xt_ct_unsupported,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}
	__atomic_add_fetch(&shm->stats.xt_ct_set_ok, 1, __ATOMIC_RELAXED);
	if (revision == 2)
		__atomic_add_fetch(&shm->stats.xt_ct_v2_seen,
				   1, __ATOMIC_RELAXED);

	/* GET_INFO -> GET_ENTRIES.  The historical leak window is the
	 * second sockopt: xt_target_to_user copies the kernel's full
	 * targetsize tail into the userspace reply. */
	{
		struct xt_lc_getinfo gi;
		socklen_t gi_len = (socklen_t)sizeof(gi);

		memset(&gi, 0, sizeof(gi));
		memcpy(gi.name, "raw", 4);
		if (getsockopt(fd, level, sockopt_get_info,
			       &gi, &gi_len) == 0 && gi.size > 0 &&
		    sizeof(struct xt_lc_get_entries_hdr) + gi.size <=
		    sizeof(get_buf)) {
			socklen_t ge_len = (socklen_t)
				(sizeof(struct xt_lc_get_entries_hdr) + gi.size);

			memset(get_buf, 0, sizeof(get_buf));
			memcpy(get_buf, "raw", 4);
			((struct xt_lc_get_entries_hdr *)get_buf)->size = gi.size;
			if (getsockopt(fd, level, sockopt_get_entries,
				       get_buf, &ge_len) == 0)
				__atomic_add_fetch(&shm->stats.xt_ct_get_ok,
						   1, __ATOMIC_RELAXED);
		}
	}

	/* Cleanup: empty replace (only policy + error entries, no xt_CT
	 * rule).  Reuses buf with rule entry stripped. */
	{
		unsigned int empty_total = 2 * policy_sz + error_sz;
		unsigned int empty_off;

		memset(buf, 0, sizeof(buf));
		xt_ct_fill_replace_hdr(buf, 0, policy_sz, empty_total,
				       counters_scratch, 3);
		empty_off = hdr_sz;
		xt_ct_emit_std_policy(buf + empty_off, entry_hdr_sz,
				      policy_sz, std_total, ipv6);
		empty_off += policy_sz;
		xt_ct_emit_std_policy(buf + empty_off, entry_hdr_sz,
				      policy_sz, std_total, ipv6);
		empty_off += policy_sz;
		xt_ct_emit_error(buf + empty_off, entry_hdr_sz,
				 error_sz, err_total, ipv6);
		(void)setsockopt(fd, level, sockopt_set, buf,
				 (socklen_t)(hdr_sz + empty_total));
	}
out:
	close(fd);
}

static void nft_xt_ct_usersize_sweep(void)
{
	if (ns_unsupported_xt_ct)
		return;
	xt_ct_probe_one(false, 1);
	if (!ns_unsupported_xt_ct)
		xt_ct_probe_one(false, 2);
	if (!ns_unsupported_xt_ct)
		xt_ct_probe_one(true, 1);
	if (!ns_unsupported_xt_ct)
		xt_ct_probe_one(true, 2);
}

/*
 * xt_IDLETIMER grammar sub-mode.  Extends the iptables blob builder
 * above to install an IDLETIMER target so trinity can exercise the
 * module's setsockopt validation, label/timeout churn, and the v1
 * timer_type field (XT_IDLETIMER_ALARM).  Layout mirrors
 * xt_ct_probe_one and shares the same struct xt_lc_ipt_* /
 * xt_ct_emit_target helpers so the wire format stays byte-identical
 * with the CT path -- only the target name and info-blob layout
 * differ.
 *
 * Config: CONFIG_NETFILTER_XT_TARGET_IDLETIMER (module).  When the
 * module isn't present, setsockopt fails cleanly with ENOENT /
 * EOPNOTSUPP / ENOPROTOOPT (no hard dependency on the target) and
 * the ns_unsupported_xt_idletimer latch short-circuits sibling
 * probes for the child's lifetime.
 *
 * Local mirrors track the stable kernel UAPI in
 * <linux/netfilter/xt_IDLETIMER.h>; XT_IDLETIMER_ALARM and
 * idletimer_tg_info_v1 aren't guaranteed in the build sysroot's
 * headers so both are #ifndef-shimmed.  The trailing __u64 slot
 * mirrors the kernel's internal "struct idletimer_tg *timer" tail
 * (aligned(8) in the uapi) -- keeps setsockopt's targetsize check
 * happy without depending on the kernel-internal pointer type.
 */
#ifndef XT_IDLETIMER_LABEL_MAX
#define XT_IDLETIMER_LABEL_MAX	28
#endif
#ifndef XT_IDLETIMER_ALARM
#define XT_IDLETIMER_ALARM	0x01
#endif

struct xtidle_lc_v0 {
	__u32	timeout;
	char	label[XT_IDLETIMER_LABEL_MAX];
	__u64	_kpad_timer;	/* mirrors kernel's trailing idletimer_tg * */
} __attribute__((aligned(8)));

struct xtidle_lc_v1 {
	__u32	timeout;
	char	label[XT_IDLETIMER_LABEL_MAX];
	__u8	timer_type;	/* v1: XT_IDLETIMER_ALARM or 0 */
	__u64	_kpad_timer;
} __attribute__((aligned(8)));

static bool ns_unsupported_xt_idletimer;

static void xt_idletimer_probe_one(bool ipv6, __u8 revision)
{
	unsigned char buf[1536];
	struct xt_lc_counters counters_scratch[8];
	unsigned int hdr_sz, entry_hdr_sz;
	unsigned int target_hdr_sz, target_data_sz;
	unsigned int std_total, err_total;
	unsigned int rule_sz, policy_sz, error_sz, total_sz;
	unsigned int off, t_data_off;
	int fd, level, sockopt_set;

	if (ipv6) {
		level        = IPPROTO_IPV6;
		sockopt_set  = IP6T_SO_SET_REPLACE;
		entry_hdr_sz = (unsigned int)sizeof(struct xt_lc_ip6t_entry);
		fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	} else {
		level        = IPPROTO_IP;
		sockopt_set  = IPT_SO_SET_REPLACE;
		entry_hdr_sz = (unsigned int)sizeof(struct xt_lc_ipt_entry);
		fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	}
	hdr_sz = (unsigned int)sizeof(struct xt_lc_ipt_replace);
	if (fd < 0) {
		if (errno == EPERM || errno == EAFNOSUPPORT ||
		    errno == EPROTONOSUPPORT)
			ns_unsupported_xt_idletimer = true;
		return;
	}

	target_hdr_sz  = (unsigned int)XT_LC_ALIGN8(sizeof(struct xt_lc_entry_target_hdr));
	target_data_sz = (revision == 1)
		? (unsigned int)XT_LC_ALIGN8(sizeof(struct xtidle_lc_v1))
		: (unsigned int)XT_LC_ALIGN8(sizeof(struct xtidle_lc_v0));
	std_total      = target_hdr_sz + (unsigned int)XT_LC_ALIGN8(sizeof(int));
	err_total      = target_hdr_sz +
			 (unsigned int)XT_LC_ALIGN8(XT_LC_FUNC_MAXNAMELEN);

	rule_sz   = entry_hdr_sz + target_hdr_sz + target_data_sz;
	policy_sz = entry_hdr_sz + std_total;
	error_sz  = entry_hdr_sz + err_total;
	total_sz  = rule_sz + 2 * policy_sz + error_sz;

	if (hdr_sz + total_sz > sizeof(buf))
		goto out;

	memset(buf, 0, sizeof(buf));
	memset(counters_scratch, 0, sizeof(counters_scratch));
	xt_ct_fill_replace_hdr(buf, rule_sz, policy_sz, total_sz,
			       counters_scratch, 4);

	off = hdr_sz;

	/* Entry 1: PRE_ROUTING rule -- IDLETIMER target, no match. */
	if (ipv6) {
		struct xt_lc_ip6t_entry *e = (struct xt_lc_ip6t_entry *)(buf + off);

		e->target_offset = (__u16)entry_hdr_sz;
		e->next_offset   = (__u16)rule_sz;
	} else {
		struct xt_lc_ipt_entry *e = (struct xt_lc_ipt_entry *)(buf + off);

		e->target_offset = (__u16)entry_hdr_sz;
		e->next_offset   = (__u16)rule_sz;
	}
	xt_ct_emit_target(buf + off + entry_hdr_sz, "IDLETIMER", revision,
			  (__u16)(target_hdr_sz + target_data_sz));
	t_data_off = off + entry_hdr_sz + target_hdr_sz;
	if (revision == 1) {
		struct xtidle_lc_v1 *info = (struct xtidle_lc_v1 *)(buf + t_data_off);

		info->timeout = rand32();
		snprintf(info->label, sizeof(info->label), "trlbl_%u",
			 (unsigned int)(rand32() & 0xffffu));
		info->timer_type = (rand32() & 1) ? XT_IDLETIMER_ALARM : 0;
	} else {
		struct xtidle_lc_v0 *info = (struct xtidle_lc_v0 *)(buf + t_data_off);

		info->timeout = rand32();
		snprintf(info->label, sizeof(info->label), "trlbl_%u",
			 (unsigned int)(rand32() & 0xffffu));
	}
	off += rule_sz;

	/* Entries 2 + 3: PRE_ROUTING policy + LOCAL_OUT policy (std ACCEPT). */
	xt_ct_emit_std_policy(buf + off, entry_hdr_sz, policy_sz, std_total, ipv6);
	off += policy_sz;
	xt_ct_emit_std_policy(buf + off, entry_hdr_sz, policy_sz, std_total, ipv6);
	off += policy_sz;

	/* Entry 4: error sentinel. */
	xt_ct_emit_error(buf + off, entry_hdr_sz, error_sz, err_total, ipv6);

	if (setsockopt(fd, level, sockopt_set, buf,
		       (socklen_t)(hdr_sz + total_sz)) < 0) {
		if (errno == EPERM || errno == ENOENT ||
		    errno == EOPNOTSUPP || errno == ENOPROTOOPT)
			ns_unsupported_xt_idletimer = true;
		goto out;
	}

	/* Cleanup: empty replace (only policy + error entries, no IDLETIMER
	 * rule).  Reuses buf with rule entry stripped. */
	{
		unsigned int empty_total = 2 * policy_sz + error_sz;
		unsigned int empty_off;

		memset(buf, 0, sizeof(buf));
		xt_ct_fill_replace_hdr(buf, 0, policy_sz, empty_total,
				       counters_scratch, 3);
		empty_off = hdr_sz;
		xt_ct_emit_std_policy(buf + empty_off, entry_hdr_sz,
				      policy_sz, std_total, ipv6);
		empty_off += policy_sz;
		xt_ct_emit_std_policy(buf + empty_off, entry_hdr_sz,
				      policy_sz, std_total, ipv6);
		empty_off += policy_sz;
		xt_ct_emit_error(buf + empty_off, entry_hdr_sz,
				 error_sz, err_total, ipv6);
		(void)setsockopt(fd, level, sockopt_set, buf,
				 (socklen_t)(hdr_sz + empty_total));
	}
out:
	close(fd);
}

static void nft_xt_idletimer_sweep(void)
{
	if (ns_unsupported_xt_idletimer)
		return;
	xt_idletimer_probe_one(false, 0);
	if (!ns_unsupported_xt_idletimer)
		xt_idletimer_probe_one(false, 1);
	if (!ns_unsupported_xt_idletimer)
		xt_idletimer_probe_one(true, 0);
	if (!ns_unsupported_xt_idletimer)
		xt_idletimer_probe_one(true, 1);
}

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
static void nft_dormant_abort_sweep(struct nfnl_ctx *ctx)
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

	__atomic_add_fetch(&shm->stats.nft_dormant_abort_iters,
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
		__atomic_add_fetch(&shm->stats.nft_dormant_abort_emsg,
				   1, __ATOMIC_RELAXED);
		return;
	}
	if (rc == -EPERM) {
		__atomic_add_fetch(&shm->stats.nft_dormant_abort_eperm,
				   1, __ATOMIC_RELAXED);
		return;
	}

	__atomic_add_fetch(&shm->stats.nft_dormant_abort_ok,
			   1, __ATOMIC_RELAXED);

	(void)build_deltable(ctx, family, table_name);
}

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

static void nft_fwd_netdev_loop_sweep(struct nfnl_ctx *nfnl,
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

	__atomic_add_fetch(&shm->stats.nft_fwd_loop_runs, 1,
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
	rc = build_newtable(nfnl, NFPROTO_NETDEV, table_name);
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
			__atomic_add_fetch(&shm->stats.nft_fwd_loop_probe_sent_ok,
					   1, __ATOMIC_RELAXED);
	}

	__atomic_add_fetch(&shm->stats.nft_fwd_loop_completed_ok, 1,
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
	__atomic_add_fetch(&shm->stats.nft_fwd_loop_ns_setup_failed, 1,
			   __ATOMIC_RELAXED);
out:
	if (sk >= 0)
		close(sk);
	if (table_created)
		(void)build_deltable(nfnl, NFPROTO_NETDEV, table_name);
}

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
		__atomic_add_fetch(&shm->stats.nft_l4frag_send_failed, 1,
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
		__atomic_add_fetch(&shm->stats.nft_l4frag_send_ok, 1,
				   __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.nft_l4frag_send_failed, 1,
				   __ATOMIC_RELAXED);
	if (sendto(s, pkt2, sizeof(pkt2), MSG_DONTWAIT,
		   (struct sockaddr *)&dst, sizeof(dst)) > 0)
		__atomic_add_fetch(&shm->stats.nft_l4frag_send_ok, 1,
				   __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.nft_l4frag_send_failed, 1,
				   __ATOMIC_RELAXED);
	close(s);
}

static void nft_l4_aware_frag_sweep(struct nfnl_ctx *nfnl)
{
	char table[32], anon_set[32];
	const char *base = "l4base";
	const char *aux  = "l4aux";
	__u32 set_id = rand32();
	__u8 proto = (rand32() & 1) ? IPPROTO_UDP : IPPROTO_SCTP;
	bool table_created = false;

	__atomic_add_fetch(&shm->stats.nft_l4frag_iters, 1, __ATOMIC_RELAXED);

	snprintf(table, sizeof(table), "trl4f%u",
		 (unsigned int)(rand32() & 0xffffu));
	snprintf(anon_set, sizeof(anon_set), "__set%u",
		 (unsigned int)(rand32() & 0xffffu));

	if (build_newtable(nfnl, NFPROTO_IPV4, table) != 0)
		return;
	table_created = true;

	(void)build_newset(nfnl, NFPROTO_IPV4, table, anon_set, set_id);
	(void)build_newchain(nfnl, NFPROTO_IPV4, table, aux, false);

	if (build_l4frag_chain(nfnl, table, base) != 0)
		goto out;
	__atomic_add_fetch(&shm->stats.nft_l4frag_install_ok, 1,
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

		if (build_newrule(nfnl, NFPROTO_IPV4, table, base, aux,
				  NFT_JUMP, 0, &plan, anon_set, set_id) == 0)
			__atomic_add_fetch(&shm->stats.nft_l4frag_rule_ok, 1,
					   __ATOMIC_RELAXED);
	}

	l4frag_send_pair(proto);

	(void)build_delrule(nfnl, NFPROTO_IPV4, table, base);
	(void)build_delset(nfnl, NFPROTO_IPV4, table, anon_set);
out:
	if (table_created)
		(void)build_deltable(nfnl, NFPROTO_IPV4, table);
}

/* Per-invocation state shared across the extracted phase helpers.  Fd
 * fields default to -1 via the orchestrator's designated initialiser
 * so the teardown helper can close them unconditionally regardless of
 * which earlier phase bailed.  base_chain / aux_chain carry the
 * compile-time defaults the rule-build phases reference every
 * iteration; table_name / anon_set / family / set_id / verdict are
 * filled in by build_table; table_created flips true once NEWTABLE
 * commits so the teardown helper knows to DELTABLE on the way out. */
struct nftables_churn_iter_ctx {
	struct nl_ctx		rtnl;
	struct nfnl_ctx		nfnl;
	int			udp;
	char			table_name[32];
	char			base_chain[32];
	char			aux_chain[32];
	char			anon_set[32];
	__u8			family;
	__u32			set_id;
	__u32			verdict;
	bool			table_created;
	struct childdata	*child;
};

/*
 * Phase: NETLINK_NETFILTER socket open inside the grandchild's
 * private netns.  The netns itself is set up by userns_run_in_ns()
 * before the in-ns callback runs, so this helper only has to bring
 * up the nfnetlink fd that every later phase batches commits over
 * (latched off via ns_unsupported_nfnetlink on the EPROTONOSUPPORT /
 * EAFNOSUPPORT CONFIG_NF_NETLINK-absent shape).  Returns 0 on
 * success; -1 means caller should return immediately -- no other fd
 * was opened so the out: cleanup path has nothing useful to run.
 */
static int nftables_churn_iter_setup_netns(struct nftables_churn_iter_ctx *ctx)
{
	struct nfnl_open_opts nfnl_opts = {
		.recv_timeo_s  = NFNL_RECV_TIMEO_S,
	};
	/* Snapshot ctx->child->op_type once and bounds-check before
	 * indexing the per-op stats arrays.  The field lives in shared
	 * memory and can be scribbled by a poisoned-arena write from a
	 * sibling; the child.c dispatch loop already gates its dispatch
	 * + alt-op accounting on the same valid_op snapshot.  Skip the
	 * latch-reason writes entirely when the snapshot is out of
	 * range. */
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (nfnl_open(&ctx->nfnl, &nfnl_opts) < 0) {
		/* EPROTONOSUPPORT here means CONFIG_NF_NETLINK is off
		 * — latch and stop trying.  Other errors (ENOMEM,
		 * EMFILE) are transient; fall through and re-try next
		 * invocation. */
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT) {
			ns_unsupported_nfnetlink = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop_latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.nftables_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	return 0;
}

/*
 * Phase: NETLINK_ROUTE socket open + one-time lo bring-up inside the
 * fresh netns.  Splits out from setup_netns because the nfnl fd is
 * already live by the time we get here, so a failure must funnel
 * through the out: cleanup path to close it (whereas
 * setup_netns failures had nothing yet to clean).  The lo bring-up is
 * gated by the process-wide lo_brought_up latch so subsequent
 * invocations skip the RTM_NEWLINK round trip.  Returns 0 on success;
 * -1 means caller should goto out -- nfnl needs closing.
 */
static int nftables_churn_iter_open_rtnl(struct nftables_churn_iter_ctx *ctx)
{
	struct nl_open_opts rtnl_opts = {
		.proto         = NETLINK_ROUTE,
		.recv_timeo_s  = NFNL_RECV_TIMEO_S,
	};

	if (nl_open(&ctx->rtnl, &rtnl_opts) < 0) {
		__atomic_add_fetch(&shm->stats.nftables_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	if (!lo_brought_up) {
		rtnl_bring_lo_up(&ctx->rtnl);
		lo_brought_up = true;
	}

	return 0;
}

/*
 * Phase: rare-gate dispatch into the five sub-mode sweeps.  Each gate
 * is independent and short-circuits the dominant expression-fuzz path
 * for the rest of this invocation, so the helper just rolls each in
 * turn and bails as soon as one fires.  Latches
 * (ns_unsupported_xt_ct, ns_unsupported_nft_compat_validate,
 * ns_unsupported_nft_fwd_netdev_loop) gate the sub-modes whose
 * upstream commits don't share ns_unsupported_nf_tables.  Returns 0
 * if no sub-mode fired (caller continues into the main flow); 1 if
 * one fired and caller should goto out -- nfnl/rtnl are already open
 * and need teardown.
 */
static int nftables_churn_iter_submode_dispatch(struct nftables_churn_iter_ctx *ctx)
{
	/* Dormant-table abort sub-mode (upstream 63bac02786030) -- rare gate
	 * so the expression-fuzz path below stays the dominant workload.
	 * Reuses ns_unsupported_nf_tables as the latch on EPERM/EOPNOTSUPP. */
	if (ONE_IN(8)) {
		nft_dormant_abort_sweep(&ctx->nfnl);
		return 1;
	}

	/* xt_CT v1+v2 usersize sub-mode (upstream 8bedb6c46945) -- rare gate
	 * so the expression-fuzz path below stays the dominant workload.
	 * Independent latch (ns_unsupported_xt_ct) so a missing xt_CT module
	 * doesn't cascade into nf_tables disablement. */
	if (ONE_IN(8) && !ns_unsupported_xt_ct) {
		nft_xt_ct_usersize_sweep();
		return 1;
	}

	/* xt_IDLETIMER grammar sub-mode.  Rare gate so the dominant
	 * expression-fuzz path stays the primary workload.  Independent
	 * latch (ns_unsupported_xt_idletimer) so a kernel without
	 * CONFIG_NETFILTER_XT_TARGET_IDLETIMER pays the EFAIL once and the
	 * rest of the child's iterations skip the socket() + setsockopt
	 * roundtrip. */
	if (ONE_IN(8) && !ns_unsupported_xt_idletimer) {
		nft_xt_idletimer_sweep();
		return 1;
	}

	/* Per-hook .validate sweep on xt-compat targets, gated separately
	 * so the legacy expression-fuzz path above is undisturbed. */
	if (ONE_IN(2) && !ns_unsupported_nft_compat_validate) {
		nft_compat_validate_sweep(&ctx->nfnl);
		return 1;
	}

	/* nft_fwd_netdev neigh-forward loop sub-mode (upstream 1d47b55b36d2,
	 * 0a0b35f0bf10, 1049970d7583).  Rare gate so the dominant
	 * expression-fuzz path above stays the primary workload.  Independent
	 * latch (ns_unsupported_nft_fwd_netdev_loop) so a kernel without
	 * CONFIG_VETH or CONFIG_NFT_FWD_NETDEV pays the EFAIL once. */
	if (ONE_IN(8) && !ns_unsupported_nft_fwd_netdev_loop) {
		nft_fwd_netdev_loop_sweep(&ctx->nfnl, &ctx->rtnl);
		return 1;
	}

	/* L4-aware-on-fragment sub-mode (upstream 952e121c9613, 009d203e56db,
	 * 0bf00859d7a5).  Rare gate so the dominant expression-fuzz path
	 * above stays the primary workload.  No dedicated latch -- a kernel
	 * without CONFIG_NF_TABLES is already gated by ns_unsupported_nf_tables
	 * upstream; per-expression validators that EOPNOTSUPP just skip the
	 * rule install and the cleanup still drains. */
	if (ONE_IN(8)) {
		nft_l4_aware_frag_sweep(&ctx->nfnl);
		return 1;
	}

	return 0;
}

/*
 * Phase: roll the per-iteration family / table / set / verdict
 * identifiers, commit NEWTABLE, and stack the dependent NEWSET, two
 * NEWCHAIN, and the append-only NEWRULE on top.  aux_chain is created
 * before base_chain so the base-chain rule's NFT_JUMP/NFT_GOTO has a
 * resolvable target on first commit.  Latches ns_unsupported_nf_tables
 * on the EAFNOSUPPORT / EOPNOTSUPP / EPROTONOSUPPORT family-not-
 * registered shape of NEWTABLE failure so siblings stop probing.
 * Returns 0 on success (ctx.table_created flipped, ready for traffic
 * + teardown phases); -1 means NEWTABLE failed and caller should goto
 * out -- there is nothing for the set/chain/rule phases to anchor on.
 */
static int nftables_churn_iter_build_table(struct nftables_churn_iter_ctx *ctx)
{
	struct nft_expr_plan plan;
	int rc;

	ctx->family = pick_family();
	nft_fill_table_name(ctx->table_name, sizeof(ctx->table_name), "trnft");
	snprintf(ctx->anon_set, sizeof(ctx->anon_set), "__set%u",
		 (unsigned int)(rand32() & 0xffffu));
	ctx->set_id = rand32();
	ctx->verdict = (rand32() & 1) ? NFT_JUMP : NFT_GOTO;

	rc = build_newtable(&ctx->nfnl, ctx->family, ctx->table_name);
	if (rc != 0) {
		/* EAFNOSUPPORT / EOPNOTSUPP / EPROTONOSUPPORT all mean
		 * "this nf_tables family isn't registered" — most
		 * commonly because the nf_tables module itself is
		 * absent.  Latch the whole op off; nothing else here
		 * will work either. */
		if (rc == -EOPNOTSUPP || rc == -EPROTONOSUPPORT ||
		    rc == -EAFNOSUPPORT) {
			ns_unsupported_nf_tables = true;
			/* ctx->child->op_type lives in shared memory and
			 * can be scribbled by a poisoned-arena write from
			 * a sibling; bounds-check the snapshot before
			 * indexing the NR_CHILD_OP_TYPES-sized stats
			 * array, same pattern the child.c dispatch loop
			 * uses for the unguarded write that motivated
			 * this guard. */
			{
				const enum child_op_type op = ctx->child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop_latch_reason[op],
							 CHILDOP_LATCH_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
		}
		return -1;
	}
	ctx->table_created = true;
	__atomic_add_fetch(&shm->stats.nftables_churn_table_create_ok,
			   1, __ATOMIC_RELAXED);

	if (build_newset(&ctx->nfnl, ctx->family, ctx->table_name,
			 ctx->anon_set, ctx->set_id) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn_set_create_ok,
				   1, __ATOMIC_RELAXED);

	/* aux first so the base-chain rule's NFT_JUMP/NFT_GOTO has a
	 * resolvable target on first commit. */
	if (build_newchain(&ctx->nfnl, ctx->family, ctx->table_name,
			   ctx->aux_chain, false) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn_chain_create_ok,
				   1, __ATOMIC_RELAXED);

	if (build_newchain(&ctx->nfnl, ctx->family, ctx->table_name,
			   ctx->base_chain, true) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn_chain_create_ok,
				   1, __ATOMIC_RELAXED);

	nft_expr_plan_randomize(&plan);
	if (build_newrule(&ctx->nfnl, ctx->family, ctx->table_name,
			  ctx->base_chain, ctx->aux_chain, ctx->verdict,
			  0, &plan, ctx->anon_set, ctx->set_id) == 0) {
		__atomic_add_fetch(&shm->stats.nftables_churn_rule_create_ok,
				   1, __ATOMIC_RELAXED);
		nft_expr_plan_record_stats(&plan);
	}

	return 0;
}

/*
 * Phase: open the loopback UDP socket and drive a bounded sendto
 * burst at 127.0.0.1:NFT_INNER_PORT.  Each send ingresses on lo,
 * walks the freshly-installed chain_in -> chain_aux jump via
 * nf_hook_slow, and exercises the verdict path the CVE-2024-1086
 * lineage hangs off.  The local STORM_BUDGET_NS wall-cap kept the
 * loop inline in the original; it stays self-contained here so the
 * caller doesn't have to thread a timespec into the helper.  Latches
 * ns_unsupported_inet on EAFNOSUPPORT / EPROTONOSUPPORT so the rest
 * of the child's lifetime skips the socket() syscall.
 */
static void nftables_churn_iter_drive_traffic(struct nftables_churn_iter_ctx *ctx)
{
	struct sockaddr_in dst;
	struct timespec t0;
	unsigned int iters;
	unsigned int i;

	if (!ns_unsupported_inet) {
		ctx->udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (ctx->udp < 0) {
			if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
				ns_unsupported_inet = true;
		}
	}

	if (ctx->udp < 0)
		return;

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
		n = sendto(ctx->udp, payload, sizeof(payload),
			   MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst));
		if (n > 0)
			__atomic_add_fetch(&shm->stats.nftables_churn_packet_sent_ok,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * Phase: mid-flow position-1 insert + bulk DELRULE + DELSET racing
 * the still-draining UDP burst.  The position-based NEWRULE walks a
 * different commit-time codepath from the append-only path in
 * build_table; if no rule with handle 1 exists the kernel rejects it
 * cheaply, which is fine -- the commit-time validation still ran.
 * The bulk DELRULE (no NFTA_RULE_HANDLE) is the targeted
 * commit-vs-traffic teardown window -- the same one CVE-2024-1086
 * exploited.  DELSET retires the anonymous set the rule above bound
 * to before the orchestrator's DELTABLE cascades the rest at out:.
 */
static void nftables_churn_iter_mid_churn(struct nftables_churn_iter_ctx *ctx)
{
	struct nft_expr_plan plan;

	nft_expr_plan_randomize(&plan);
	if (build_newrule(&ctx->nfnl, ctx->family, ctx->table_name,
			  ctx->base_chain, ctx->aux_chain, ctx->verdict,
			  1, &plan, ctx->anon_set, ctx->set_id) == 0) {
		__atomic_add_fetch(&shm->stats.nftables_churn_rule_insert_ok,
				   1, __ATOMIC_RELAXED);
		nft_expr_plan_record_stats(&plan);
	}

	if (build_delrule(&ctx->nfnl, ctx->family, ctx->table_name,
			  ctx->base_chain) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn_rule_del_ok,
				   1, __ATOMIC_RELAXED);

	(void)build_delset(&ctx->nfnl, ctx->family, ctx->table_name,
			   ctx->anon_set);
}

/*
 * Phase: close whichever resources we managed to open.  Runs on
 * every exit path -- both the success path after mid_churn returns
 * and any early-bail goto out from an earlier phase.  Order matches
 * the original out: cleanup: close udp first, then DELTABLE (gated
 * on table_created so an aborted build_table doesn't issue a NEWTABLE
 * we never sent), then nfnl close so the DELTABLE batch has somewhere
 * to land, then rtnl.  All fd fields default to -1 via the
 * orchestrator's designated initialiser so the guards skip work that
 * was never set up.
 */
static void nftables_churn_iter_teardown(struct nftables_churn_iter_ctx *ctx)
{
	if (ctx->udp >= 0)
		close(ctx->udp);

	if (ctx->nfnl.nl.fd >= 0) {
		/* DELTABLE cascades cleanup of any chain/rule/set
		 * survivors via nf_tables_table_destroy, racing the
		 * same in-flight skbs as the explicit DELRULE above. */
		if (ctx->table_created) {
			if (build_deltable(&ctx->nfnl, ctx->family,
					   ctx->table_name) == 0)
				__atomic_add_fetch(&shm->stats.nftables_churn_table_del_ok,
						   1, __ATOMIC_RELAXED);
		}
		nfnl_close(&ctx->nfnl);
	}

	nl_close(&ctx->rtnl);
}

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any table,
 * chain, rule, set, dummy / veth link and socket left behind is reaped
 * along with the namespace.  Explicit DELTABLE / close() calls are
 * still issued so the in-ns stats counters (table_del_ok etc.) move on
 * the success path; correctness does not depend on them.  Per-grand-
 * child latches set inside this callback die with the grandchild and
 * the per-grandchild gates above are re-discovered on the next
 * invocation -- helper-EPERM in the wrapper is the only signal that
 * survives across iterations.  Return value is ignored by the helper.
 */
static int nftables_churn_in_ns(void *arg)
{
	struct nftables_churn_iter_ctx *ctx = (struct nftables_churn_iter_ctx *)arg;
	struct childdata *child = ctx->child;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unsupported_nfnetlink || ns_unsupported_nf_tables)
		return 0;

	if (nftables_churn_iter_setup_netns(ctx) != 0)
		return 0;

	if (nftables_churn_iter_open_rtnl(ctx) != 0)
		goto out;

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop_setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop_data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	if (nftables_churn_iter_submode_dispatch(ctx) != 0)
		goto out;

	if (nftables_churn_iter_build_table(ctx) != 0)
		goto out;

	nftables_churn_iter_drive_traffic(ctx);
	nftables_churn_iter_mid_churn(ctx);

out:
	nftables_churn_iter_teardown(ctx);
	return 0;
}

bool nftables_churn(struct childdata *child)
{
	struct nftables_churn_iter_ctx ctx = {
		.rtnl       = { .fd = -1 },
		.nfnl       = { .nl = { .fd = -1 } },
		.udp        = -1,
		.base_chain = "chain_in",
		.aux_chain  = "chain_aux",
		.child      = child,
	};
	int rc;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op latch slot.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the latch
	 * store entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.nftables_churn_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_nftables)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, nftables_churn_in_ns, &ctx);
	if (rc == -EPERM) {
		if (valid_op)
			__atomic_store_n(&shm->stats.childop_latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		warn_once_unsupported_nftables("userns_run_in_ns(CLONE_NEWNET)",
					       EPERM);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without
		 * latching -- the failure is not policy and may not
		 * recur. */
		__atomic_add_fetch(&shm->stats.nftables_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
