/*
 * nftables-churn-exprs.c
 *
 * The build_nft_*_expr family extracted from nftables-churn.c so the
 * two halves of the module can compile in parallel.  Each builder
 * emits one NFTA_LIST_ELEM containing a structurally-valid
 * nf_tables expression and is independent of the rest of the
 * orchestrator (no module-scope state references, no callbacks);
 * its only inputs are the caller's buffer and the netlink helpers
 * declared in nftables-churn-internal.h.
 *
 * Each function was file-static in the original TU; linkage is
 * widened to external here so the nft_expr_table dispatch array in
 * nftables-churn.c can resolve them across the TU split.
 */

#include "nftables-churn-internal.h"

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_payload
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  All field values are picked from kernel-accepted ranges
 * so the message reaches the per-expression parser surface in
 * net/netfilter/nft_payload.c instead of bouncing off NFTA_EXPR_DATA
 * validation in nf_tables_newexpr.  Two variants are emitted, rolled
 * per call:
 *   - read path  (DREG set):  load LEN bytes from base+offset into a
 *     general-purpose register.  Reaches nft_payload_init.
 *   - write path (SREG set):  write LEN bytes from a register back
 *     into the packet at base+offset, optionally with a checksum
 *     fixup.  Reaches nft_payload_set_init plus the csum-helper path.
 */
size_t build_nft_payload_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 bases[] = {
		NFT_PAYLOAD_LL_HEADER, NFT_PAYLOAD_NETWORK_HEADER,
		NFT_PAYLOAD_TRANSPORT_HEADER, NFT_PAYLOAD_INNER_HEADER,
	};
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
		NFT_REG32_00, NFT_REG32_00 + 1, NFT_REG32_00 + 2,
		NFT_REG32_00 + 3, NFT_REG32_00 + 7,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 base = bases[rand32() % ARRAY_SIZE(bases)];
	__u32 reg  = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 offset_v = rand32() % 64;
	__u32 len_v    = (rand32() % 16) + 1;
	bool write_path = ONE_IN(4);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "payload");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_PAYLOAD_BASE, base);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_PAYLOAD_OFFSET, offset_v);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_PAYLOAD_LEN, len_v);
	if (!off)
		return 0;

	if (write_path) {
		off = nla_put_be32(buf, off, cap, NFTA_PAYLOAD_SREG, reg);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_PAYLOAD_CSUM_TYPE,
				   rand32() % 3);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_PAYLOAD_CSUM_OFFSET,
				   rand32() % 64);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_PAYLOAD_CSUM_FLAGS,
				   rand32() & 0x1);
		if (!off)
			return 0;
	} else {
		off = nla_put_be32(buf, off, cap, NFTA_PAYLOAD_DREG, reg);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_meta
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the per-key validator + register check in
 * net/netfilter/nft_meta.c (nft_meta_get_init / nft_meta_set_init)
 * instead of bouncing off NFTA_EXPR_DATA validation in
 * nf_tables_newexpr.  Two variants, rolled per call:
 *   - read path  (DREG, 3-in-4): load the metadata field named by
 *     NFTA_META_KEY into a general-purpose register.  Key is rolled
 *     across the full read-allowed set.
 *   - write path (SREG, 1-in-4): write a register value back into a
 *     writable metadata field.  The kernel rejects SREG on read-only
 *     keys before any register validation runs, so the key is rolled
 *     over a conservative writable subset (MARK, PRIORITY, NFTRACE,
 *     PKTTYPE) — widening it would just pre-empt coverage of
 *     nft_meta_set_init.
 */
size_t build_nft_meta_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 read_keys[] = {
		NFT_META_LEN, NFT_META_PROTOCOL, NFT_META_PRIORITY,
		NFT_META_MARK, NFT_META_IIF, NFT_META_OIF,
		NFT_META_IIFNAME, NFT_META_OIFNAME,
		NFT_META_IIFTYPE, NFT_META_OIFTYPE,
		NFT_META_SKUID, NFT_META_SKGID, NFT_META_NFTRACE,
		NFT_META_RTCLASSID, NFT_META_SECMARK,
		NFT_META_NFPROTO, NFT_META_L4PROTO,
		NFT_META_BRI_IIFNAME, NFT_META_BRI_OIFNAME,
		NFT_META_PKTTYPE, NFT_META_CPU,
		NFT_META_IIFGROUP, NFT_META_OIFGROUP,
		NFT_META_CGROUP, NFT_META_PRANDOM,
		NFT_META_IIFKIND, NFT_META_OIFKIND,
		NFT_META_BRI_IIFPVID, NFT_META_BRI_IIFVPROTO,
		NFT_META_TIME_NS, NFT_META_TIME_DAY, NFT_META_TIME_HOUR,
		NFT_META_SDIF, NFT_META_SDIFNAME,
	};
	static const __u32 write_keys[] = {
		NFT_META_MARK, NFT_META_PRIORITY,
		NFT_META_NFTRACE, NFT_META_PKTTYPE,
	};
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
		NFT_REG32_00, NFT_REG32_00 + 1, NFT_REG32_00 + 2,
		NFT_REG32_00 + 3, NFT_REG32_00 + 7,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool write_path = ONE_IN(4);
	__u32 reg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 key = write_path
		? write_keys[rand32() % ARRAY_SIZE(write_keys)]
		: read_keys[rand32() % ARRAY_SIZE(read_keys)];

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "meta");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_META_KEY, key);
	if (!off)
		return 0;

	if (write_path)
		off = nla_put_be32(buf, off, cap, NFTA_META_SREG, reg);
	else
		off = nla_put_be32(buf, off, cap, NFTA_META_DREG, reg);
	if (!off)
		return 0;

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_lookup
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the per-expression validator in
 * net/netfilter/nft_lookup.c (nft_lookup_init) — set-binding,
 * sreg/dreg validation, and the map-vs-plain set type check.  Refers
 * to the in-transaction anonymous set already created by build_newset
 * via NFTA_LOOKUP_SET (name) + NFTA_LOOKUP_SET_ID (cookie); the kernel
 * resolves the binding inside the same commit.
 *
 * Roll variants per call:
 *   - SREG always present (key register, NFT_REG32_00..15).
 *   - DREG present 1-in-2 (NFT_REG32_00..15).  DREG is only valid on
 *     map-typed sets — the kernel returns -EOPNOTSUPP for plain sets,
 *     which is exactly the validator path we're trying to cover.
 *   - FLAGS = 0 by default, NFT_LOOKUP_F_INV 1-in-4 (negated lookup).
 */
size_t build_nft_lookup_expr(unsigned char *buf, size_t off,
				    size_t cap, const char *set_name,
				    __u32 set_id)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 sreg = NFT_REG32_00 + (rand32() % 16);
	__u32 dreg = NFT_REG32_00 + (rand32() % 16);
	__u32 flags = ONE_IN(4) ? NFT_LOOKUP_F_INV : 0;
	bool with_dreg = ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "lookup");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_LOOKUP_SET, set_name);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_LOOKUP_SREG, sreg);
	if (!off)
		return 0;
	if (with_dreg) {
		off = nla_put_be32(buf, off, cap, NFTA_LOOKUP_DREG, dreg);
		if (!off)
			return 0;
	}
	off = nla_put_be32(buf, off, cap, NFTA_LOOKUP_SET_ID, set_id);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_LOOKUP_FLAGS, flags);
	if (!off)
		return 0;

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_log
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the per-attribute validator in
 * net/netfilter/nft_log.c (nft_log_init) — nf_log binding, group /
 * snaplen / qthreshold range checks, and the prefix-string parser.
 *
 * Each optional attribute is coin-flipped in independently so the
 * emitted shape varies per call.  If every coin came up false a
 * single attribute is forced in so the expression is never
 * degenerate-empty (which the kernel would happily accept but which
 * would waste an iteration).
 */
size_t build_nft_log_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_prefix    = ONE_IN(2);
	bool with_group     = ONE_IN(3);
	bool with_snaplen   = ONE_IN(3);
	bool with_qthresh   = ONE_IN(3);
	bool with_level     = ONE_IN(2);
	bool with_flags     = ONE_IN(3);

	if (!with_prefix && !with_group && !with_snaplen &&
	    !with_qthresh && !with_level && !with_flags) {
		switch (rand32() % 6) {
		case 0: with_prefix  = true; break;
		case 1: with_group   = true; break;
		case 2: with_snaplen = true; break;
		case 3: with_qthresh = true; break;
		case 4: with_level   = true; break;
		default: with_flags  = true; break;
		}
	}

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "log");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (with_prefix) {
		char prefix[9];
		unsigned int len = (rand32() % 8) + 1;
		unsigned int i;

		for (i = 0; i < len; i++)
			prefix[i] = 'a' + (rand32() % 26);
		prefix[len] = '\0';
		off = nla_put_str(buf, off, cap, NFTA_LOG_PREFIX, prefix);
		if (!off)
			return 0;
	}

	if (with_group) {
		off = nla_put_be16(buf, off, cap, NFTA_LOG_GROUP,
				   (__u16)rand32());
		if (!off)
			return 0;
	}

	if (with_snaplen) {
		off = nla_put_be32(buf, off, cap, NFTA_LOG_SNAPLEN,
				   rand32() % 0x10000);
		if (!off)
			return 0;
	}

	if (with_qthresh) {
		off = nla_put_be16(buf, off, cap, NFTA_LOG_QTHRESHOLD,
				   (__u16)rand32());
		if (!off)
			return 0;
	}

	if (with_level) {
		off = nla_put_be32(buf, off, cap, NFTA_LOG_LEVEL,
				   rand32() % 8);
		if (!off)
			return 0;
	}

	if (with_flags) {
		__u32 flags = ONE_IN(2)
			? NF_LOG_DEFAULT_MASK
			: (rand32() & NF_LOG_DEFAULT_MASK);
		off = nla_put_be32(buf, off, cap, NFTA_LOG_FLAGS, flags);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_bitwise
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the per-op validator + register check in
 * net/netfilter/nft_bitwise.c (nft_bitwise_init) — the policy table
 * nft_bitwise_policy[] gates SREG/DREG/LEN/OP and then the op-specific
 * payload (MASK+XOR for BOOL, DATA shift count for LSHIFT/RSHIFT) is
 * parsed by the per-branch helper.
 *
 * Roll variants per call:
 *   - LEN coin-flips across {1, 2, 4, 8, 16} bytes — the validator
 *     accepts any length up to NFT_REG_SIZE, and each width hits a
 *     different memcpy / register-fold path.
 *   - OP picks NFT_BITWISE_BOOL (mask+xor) ONE_IN(2), else
 *     NFT_BITWISE_LSHIFT or NFT_BITWISE_RSHIFT.
 *   - For BOOL: MASK and XOR are each a nested NFTA_DATA_VALUE of LEN
 *     bytes filled with random data.
 *   - For LSHIFT/RSHIFT: NFTA_BITWISE_DATA is a nested NFTA_DATA_VALUE
 *     carrying a __be32 shift count in 0..31, the range the kernel
 *     accepts before nft_bitwise_init returns -EINVAL.
 */
size_t build_nft_bitwise_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 lens[] = { 1, 2, 4, 8, 16 };
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	struct nlattr *elem, *expr_data, *value;
	size_t elem_off, expr_data_off, value_off;
	__u32 sreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 dreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 len_v = lens[rand32() % ARRAY_SIZE(lens)];
	bool boolean_op = ONE_IN(2);
	__u32 op = boolean_op
		? NFT_BITWISE_BOOL
		: ((rand32() & 1) ? NFT_BITWISE_LSHIFT : NFT_BITWISE_RSHIFT);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "bitwise");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_BITWISE_SREG, sreg);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_BITWISE_DREG, dreg);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_BITWISE_LEN, len_v);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_BITWISE_OP, op);
	if (!off)
		return 0;

	if (boolean_op) {
		unsigned char bytes[16];

		/* MASK = nested NFTA_DATA_VALUE = LEN random bytes */
		value_off = off;
		off = nla_put(buf, off, cap,
			      NFTA_BITWISE_MASK | NLA_F_NESTED, NULL, 0);
		if (!off)
			return 0;
		generate_rand_bytes(bytes, len_v);
		off = nla_put(buf, off, cap, NFTA_DATA_VALUE, bytes, len_v);
		if (!off)
			return 0;
		value = (struct nlattr *)(buf + value_off);
		value->nla_len = (unsigned short)(off - value_off);

		/* XOR = nested NFTA_DATA_VALUE = LEN random bytes */
		value_off = off;
		off = nla_put(buf, off, cap,
			      NFTA_BITWISE_XOR | NLA_F_NESTED, NULL, 0);
		if (!off)
			return 0;
		generate_rand_bytes(bytes, len_v);
		off = nla_put(buf, off, cap, NFTA_DATA_VALUE, bytes, len_v);
		if (!off)
			return 0;
		value = (struct nlattr *)(buf + value_off);
		value->nla_len = (unsigned short)(off - value_off);
	} else {
		__u32 shift = rand32() % 32;

		value_off = off;
		off = nla_put(buf, off, cap,
			      NFTA_BITWISE_DATA | NLA_F_NESTED, NULL, 0);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_DATA_VALUE, shift);
		if (!off)
			return 0;
		value = (struct nlattr *)(buf + value_off);
		value->nla_len = (unsigned short)(off - value_off);
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_cmp
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_cmp.c
 * (nft_cmp_init) — the policy table nft_cmp_policy[] gates SREG/OP/DATA
 * and then nft_data_init parses the nested NFTA_DATA_VALUE payload.
 *
 * cmp is the most fundamental nftables expression: every realistic rule
 * compares a freshly-loaded register against a literal.  Roll variants
 * per call:
 *   - SREG picks one of NFT_REG_1..NFT_REG_4 uniformly so cmp consumes
 *     whatever a preceding payload/meta/bitwise emit just stored.
 *   - OP picks NFT_CMP_EQ ONE_IN(2) (matches the dominant real-world
 *     shape), else uniform across NEQ/LT/LTE/GT/GTE so the ordered
 *     comparators get exercised too.
 *   - DATA length coin-flips across {1, 2, 4, 8, 16} bytes — the
 *     validator accepts any length up to NFT_REG_SIZE, and each width
 *     hits a different memcmp / register-fold path.
 *   - DATA bytes are random; the rule will almost never match traffic,
 *     but commit-time validation (the codepath we care about for churn)
 *     runs regardless.
 */
size_t build_nft_cmp_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 lens[] = { 1, 2, 4, 8, 16 };
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	static const __u32 ordered_ops[] = {
		NFT_CMP_NEQ, NFT_CMP_LT, NFT_CMP_LTE,
		NFT_CMP_GT, NFT_CMP_GTE,
	};
	struct nlattr *elem, *expr_data, *value;
	size_t elem_off, expr_data_off, value_off;
	__u32 sreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 len_v = lens[rand32() % ARRAY_SIZE(lens)];
	__u32 op = ONE_IN(2)
		? NFT_CMP_EQ
		: ordered_ops[rand32() % ARRAY_SIZE(ordered_ops)];
	unsigned char bytes[16];

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "cmp");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_CMP_SREG, sreg);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_CMP_OP, op);
	if (!off)
		return 0;

	value_off = off;
	off = nla_put(buf, off, cap, NFTA_CMP_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;
	generate_rand_bytes(bytes, len_v);
	off = nla_put(buf, off, cap, NFTA_DATA_VALUE, bytes, len_v);
	if (!off)
		return 0;
	value = (struct nlattr *)(buf + value_off);
	value->nla_len = (unsigned short)(off - value_off);

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_range
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_range.c
 * (nft_range_init) — the policy table nft_range_policy[] gates
 * SREG/OP/FROM_DATA/TO_DATA and then nft_data_init parses each nested
 * NFTA_DATA_VALUE bound.  The kernel rejects reversed bounds via
 * memcmp(from, to) > 0 before any register check runs, so FROM is
 * rolled and TO is rolled strictly above it.
 *
 * range is the structural cousin of cmp — same SREG-vs-literal model,
 * but takes a [FROM, TO] interval and returns match/no-match per OP.
 * Roll variants per call:
 *   - SREG picks one of NFT_REG_1..NFT_REG_4 uniformly so range consumes
 *     whatever a preceding payload/meta/bitwise emit just stored.
 *   - OP picks NFT_RANGE_EQ ONE_IN(2), else NFT_RANGE_NEQ — the only
 *     two values the kernel enum exposes.
 *   - FROM is a 31-bit random; TO = FROM + 1 + small-random, capped so
 *     the addition can't wrap.  Both bounds are emitted in network
 *     byte order via nla_put_be32(NFTA_DATA_VALUE), which preserves
 *     numeric ordering under the kernel's byte-wise memcmp.
 *
 * LOAD-only: range only reads SREG and the immediate FROM/TO bounds —
 * no DREG, no register write, no datapath state mutation.  Heavier
 * than cmp at commit time (two NFTA_DATA_VALUE parses + a bound-
 * ordering memcmp) but cheap on the runtime side.
 */
size_t build_nft_range_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	struct nlattr *elem, *expr_data, *value;
	size_t elem_off, expr_data_off, value_off;
	__u32 sreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 op = ONE_IN(2) ? NFT_RANGE_EQ : NFT_RANGE_NEQ;
	__u32 from_v = rand32() & 0x7fffffffU;
	__u32 to_v = from_v + 1 + (rand32() % 0x10000);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "range");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_RANGE_OP, op);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_RANGE_SREG, sreg);
	if (!off)
		return 0;

	value_off = off;
	off = nla_put(buf, off, cap,
		      NFTA_RANGE_FROM_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_DATA_VALUE, from_v);
	if (!off)
		return 0;
	value = (struct nlattr *)(buf + value_off);
	value->nla_len = (unsigned short)(off - value_off);

	value_off = off;
	off = nla_put(buf, off, cap,
		      NFTA_RANGE_TO_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_DATA_VALUE, to_v);
	if (!off)
		return 0;
	value = (struct nlattr *)(buf + value_off);
	value->nla_len = (unsigned short)(off - value_off);

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_byteorder
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_byteorder.c
 * (nft_byteorder_init) — the policy table nft_byteorder_policy[] gates
 * SREG/DREG/OP/LEN/SIZE and every attribute is mandatory (no
 * NLA_F_OPTIONAL on any slot).  After parsing the kernel further
 * enforces SIZE in {2, 4, 8} and LEN a non-zero multiple of SIZE,
 * with LEN capped at FIELD_SIZEOF(struct nft_data, data) == 16.
 *
 * byteorder is a load/store register reformatter — it reads LEN bytes
 * from SREG, byte-swaps each SIZE-wide element through ntoh/hton, and
 * writes the result to DREG.  Roll variants per call:
 *   - SREG and DREG independently pick from NFT_REG_1..NFT_REG_4 so
 *     byteorder consumes whatever a preceding payload/meta/bitwise
 *     emit just stored, and so DREG races other expressions writing
 *     the same register inside one rule.
 *   - OP picks NTOH ONE_IN(2) else HTON — the only two values the
 *     kernel enum exposes.
 *   - SIZE is rolled first from {2, 4, 8}, then LEN is picked as a
 *     multiple of SIZE bounded by 16, so every emit sits inside the
 *     validator's accept range and exercises the per-element swap
 *     loop rather than the EINVAL early-return.
 *
 * LOAD-and-STORE: byteorder writes the destination register, so it
 * also exercises the nft_data store path that purely-readonly
 * expressions like cmp/range never touch.
 */
size_t build_nft_byteorder_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	static const __u32 sizes[] = { 2, 4, 8 };
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 sreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 dreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 op = ONE_IN(2) ? NFT_BYTEORDER_NTOH : NFT_BYTEORDER_HTON;
	__u32 size = sizes[rand32() % ARRAY_SIZE(sizes)];
	__u32 max_mult = 16 / size;
	__u32 mult = 1 + (rand32() % max_mult);
	__u32 len = mult * size;

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "byteorder");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_BYTEORDER_SREG, sreg);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_BYTEORDER_DREG, dreg);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_BYTEORDER_OP, op);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_BYTEORDER_LEN, len);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_BYTEORDER_SIZE, size);
	if (!off)
		return 0;

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_socket
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_socket.c
 * (nft_socket_init) — the policy table nft_socket_policy[] gates
 * KEY/DREG/LEVEL, and the init handler enforces a KEY-conditional rule:
 * NFTA_SOCKET_LEVEL is mandatory iff KEY == NFT_SOCKET_CGROUPV2 and
 * rejected for any other KEY.
 *
 * socket reaches into the per-skb socket lookup path: nft_socket_eval
 * resolves the socket via skb->sk (falling back to nf_sk_lookup_slow
 * when missing), normalises through sk_to_full_sk, and then the per-key
 * dispatch reads IP(V6)_TRANSPARENT, sk->sk_mark, the wildcard-bind
 * test or sock_cgroup_ancestor at the requested cgroupv2 level — all
 * load paths that purely-on-skb expressions like payload/byteorder
 * never touch.  Roll variants per call:
 *   - KEY picks uniformly from
 *     {TRANSPARENT, MARK, WILDCARD, CGROUPV2} so each emit lands on a
 *     different per-key load helper.
 *   - DREG picks one of NFT_REG_1..NFT_REG_4 uniformly so the lookup
 *     result lands in whatever register a following cmp/range/bitwise
 *     emit will read.
 *   - LEVEL is rolled in 0..255 (the kernel-accepted range) and is
 *     emitted ONLY when KEY == NFT_SOCKET_CGROUPV2; on any other KEY
 *     LEVEL is omitted so nft_socket_init's "LEVEL with non-CGROUPV2
 *     KEY" early-EINVAL is not the dominant outcome.
 */
size_t build_nft_socket_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	static const __u32 keys[] = {
		NFT_SOCKET_TRANSPARENT, NFT_SOCKET_MARK,
		NFT_SOCKET_WILDCARD, NFT_SOCKET_CGROUPV2,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 key = keys[rand32() % ARRAY_SIZE(keys)];
	__u32 dreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 level = rand32() & 0xff;

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "socket");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_SOCKET_KEY, key);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_SOCKET_DREG, dreg);
	if (!off)
		return 0;
	if (key == NFT_SOCKET_CGROUPV2) {
		off = nla_put_be32(buf, off, cap, NFTA_SOCKET_LEVEL, level);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_quota
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_quota.c
 * (nft_quota_init): NFTA_QUOTA_BYTES is mandatory (the cap), FLAGS is
 * optional and only NFT_QUOTA_F_INV is accepted, CONSUMED is optional
 * and pre-seeds the per-rule counter.  All three values are u64/u32 in
 * network byte order.
 *
 * Variants per call:
 *   - BYTES rolls uniformly across orders of magnitude
 *     {tiny, typical, huge} so each emit lands somewhere different on
 *     the cap-not-yet-hit vs cap-immediately-exceeded axis the eval
 *     comparator dispatches on.
 *   - FLAGS is a coin-flip on NFT_QUOTA_F_INV and otherwise omitted, so
 *     the inversion branch in nft_quota_eval gets exercised half the
 *     time without ever feeding an unknown bit (which the parser
 *     rejects with -EOPNOTSUPP before init returns).
 *   - CONSUMED is rolled ONE_IN(2); when present its value sits below
 *     BYTES half the time and above BYTES the other half so the
 *     consumed-vs-cap comparison in nft_quota_eval sees both sides on
 *     the very first packet.
 */
size_t build_nft_quota_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u64 byte_caps[] = {
		1ULL,			/* tiny: cap-immediately-hit */
		4096ULL,		/* small */
		1ULL << 20,		/* typical (~1 MiB) */
		1ULL << 32,		/* huge (~4 GiB) */
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u64 bytes = byte_caps[rand32() % ARRAY_SIZE(byte_caps)];
	bool with_flags = ONE_IN(2);
	bool with_consumed = ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "quota");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be64(buf, off, cap, NFTA_QUOTA_BYTES, bytes);
	if (!off)
		return 0;

	if (with_flags) {
		off = nla_put_be32(buf, off, cap, NFTA_QUOTA_FLAGS,
				   NFT_QUOTA_F_INV);
		if (!off)
			return 0;
	}

	if (with_consumed) {
		__u64 consumed;

		if (ONE_IN(2)) {
			consumed = bytes ? (rand64() % (bytes + 1)) : 0;
		} else {
			consumed = bytes + 1 + (rand64() & 0xffff);
		}
		off = nla_put_be64(buf, off, cap, NFTA_QUOTA_CONSUMED,
				   consumed);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_objref
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  nft_objref references a previously-registered named
 * object (counter, quota, ct helper, ...) and the expression has two
 * operating modes selected by net/netfilter/nft_objref.c
 * (nft_objref_select_ops): IMM mode dispatches to nft_objref_init,
 * SET mode dispatches to nft_objref_map_init.
 *
 * IMM mode emits NFTA_OBJREF_IMM_NAME (NLA_STRING, bounded by
 * NFT_OBJ_MAXNAMELEN-1) and NFTA_OBJREF_IMM_TYPE (NLA_U32, must match a
 * registered NFT_OBJECT_* family).  The kernel's nft_objref_init runs
 * the policy check first, then calls nft_obj_lookup() — names that
 * miss the lookup return -ENOENT but the NLA validation path
 * (string-length bound, type range) has already executed end-to-end.
 *
 * SET mode emits NFTA_OBJREF_SET_SREG (NLA_U32, validated by
 * nft_parse_register_load against the bound set's klen) plus
 * NFTA_OBJREF_SET_NAME and/or NFTA_OBJREF_SET_ID — the kernel accepts
 * either or both, the lookup uses NAME-then-ID resolution.  Garbage
 * names hit nft_set_lookup_global and bounce out cheaply, again after
 * the policy check has run.  Reaches both nft_objref_init and
 * nft_objref_map_init parser paths under random rolls.
 *
 * Variants per call:
 *   - IMM-vs-SET coin-flip so each emit splits roughly 50/50 between
 *     the two select_ops branches.
 *   - IMM-mode TYPE rolls uniformly across the 9 in-tree NFT_OBJECT_*
 *     constants {COUNTER, QUOTA, CT_HELPER, LIMIT, CONNLIMIT, TUNNEL,
 *     CT_TIMEOUT, SECMARK, CT_EXPECT, SYNPROXY} so the type-range
 *     validation in nft_objref_init sees the full accepted range
 *     (and SYNPROXY exercises the family/hooks gate in
 *     nft_objref_validate_obj_type).
 *   - IMM-mode NAME picks from a small short-name pool — names will
 *     usually miss nft_obj_lookup but the pool keeps the bounded
 *     NLA_STRING test working at expected lengths.
 *   - SET-mode SREG picks NFT_REG_1..NFT_REG_4.
 *   - SET-mode emits NAME and/or ID under coin flips so all three
 *     legal {NAME-only, ID-only, NAME+ID} combinations are reached.
 */
size_t build_nft_objref_expr(unsigned char *buf, size_t off,
				    size_t cap)
{
	static const __u32 obj_types[] = {
		NFT_OBJECT_COUNTER,	NFT_OBJECT_QUOTA,
		NFT_OBJECT_CT_HELPER,	NFT_OBJECT_LIMIT,
		NFT_OBJECT_CONNLIMIT,	NFT_OBJECT_TUNNEL,
		NFT_OBJECT_CT_TIMEOUT,	NFT_OBJECT_SECMARK,
		NFT_OBJECT_CT_EXPECT,	NFT_OBJECT_SYNPROXY,
	};
	static const char * const obj_names[] = {
		"c1", "q1", "l1", "h1", "ct1", "tun1", "sm1", "sp1",
	};
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool set_mode = ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "objref");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (set_mode) {
		__u32 sreg = regs[rand32() % ARRAY_SIZE(regs)];
		bool with_name = ONE_IN(2);
		bool with_id = with_name ? ONE_IN(2) : true;

		off = nla_put_be32(buf, off, cap,
				   NFTA_OBJREF_SET_SREG, sreg);
		if (!off)
			return 0;
		if (with_name) {
			const char *nm =
				obj_names[rand32() % ARRAY_SIZE(obj_names)];

			off = nla_put_str(buf, off, cap,
					  NFTA_OBJREF_SET_NAME, nm);
			if (!off)
				return 0;
		}
		if (with_id) {
			off = nla_put_be32(buf, off, cap,
					   NFTA_OBJREF_SET_ID, rand32());
			if (!off)
				return 0;
		}
	} else {
		const char *nm =
			obj_names[rand32() % ARRAY_SIZE(obj_names)];
		__u32 type = obj_types[rand32() % ARRAY_SIZE(obj_types)];

		off = nla_put_str(buf, off, cap,
				  NFTA_OBJREF_IMM_NAME, nm);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap,
				   NFTA_OBJREF_IMM_TYPE, type);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_limit
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_limit.c
 * (nft_limit_init): NFTA_LIMIT_RATE and NFTA_LIMIT_UNIT are mandatory,
 * BURST/TYPE/FLAGS are optional.  TYPE picks between
 * NFT_LIMIT_PKTS (default) and NFT_LIMIT_PKT_BYTES which dispatches to
 * nft_limit_pkts_init vs nft_limit_bytes_init for token-bucket setup.
 * RATE == 0 is rejected outright; unknown TYPE / unknown FLAGS bits are
 * rejected with -EOPNOTSUPP.  All values go on the wire u64/u32 in
 * network byte order.
 *
 * Variants per call:
 *   - RATE rolls uniformly across orders of magnitude
 *     {small, typical, huge} so the token-bucket arithmetic in
 *     nft_limit_eval (nfs / rate, with the divide_s64 in
 *     nft_limit_init) sees both fast-refill and slow-refill regimes.
 *     RATE is forced non-zero so init does not bail at the rate==0
 *     guard before the bucket math runs.
 *   - UNIT picks one of {1, 60, 3600} seconds — the per-second,
 *     per-minute, and per-hour windows real rulesets use — so the
 *     unit*NSEC_PER_SEC multiplication in nft_limit_init exercises a
 *     spread of nfs values feeding the credit/refill divide.
 *   - BURST is coin-flipped present, value rolled small/medium/large so
 *     the optional widening of the bucket capacity is hit half the time
 *     without ever omitting the more interesting refill path.
 *   - TYPE is coin-flipped between PKTS and PKT_BYTES so both
 *     dispatch arms (per-packet credit decrement vs per-skb-len credit
 *     decrement in nft_limit_eval) see traffic.
 *   - FLAGS is a coin-flip on NFT_LIMIT_F_INV and otherwise omitted, so
 *     the inverted-budget branch in nft_limit_eval gets exercised half
 *     the time without ever feeding an unknown bit (which the parser
 *     rejects with -EOPNOTSUPP before init returns).
 */
size_t build_nft_limit_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u64 rates[] = {
		1ULL,			/* small: bucket immediately drained */
		1024ULL,		/* typical */
		1ULL << 20,		/* huge */
	};
	static const __u64 units[] = {
		1ULL,			/* per-second */
		60ULL,			/* per-minute */
		3600ULL,		/* per-hour */
	};
	static const __u32 bursts[] = {
		0U,			/* small */
		128U,			/* medium */
		65535U,			/* large */
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u64 rate = rates[rand32() % ARRAY_SIZE(rates)];
	__u64 unit = units[rand32() % ARRAY_SIZE(units)];
	bool with_burst = ONE_IN(2);
	bool with_type = ONE_IN(2);
	bool with_flags = ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "limit");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be64(buf, off, cap, NFTA_LIMIT_RATE, rate);
	if (!off)
		return 0;
	off = nla_put_be64(buf, off, cap, NFTA_LIMIT_UNIT, unit);
	if (!off)
		return 0;

	if (with_burst) {
		__u32 burst = bursts[rand32() % ARRAY_SIZE(bursts)];

		off = nla_put_be32(buf, off, cap, NFTA_LIMIT_BURST, burst);
		if (!off)
			return 0;
	}

	if (with_type) {
		__u32 type = ONE_IN(2) ? NFT_LIMIT_PKTS : NFT_LIMIT_PKT_BYTES;

		off = nla_put_be32(buf, off, cap, NFTA_LIMIT_TYPE, type);
		if (!off)
			return 0;
	}

	if (with_flags) {
		off = nla_put_be32(buf, off, cap, NFTA_LIMIT_FLAGS,
				   NFT_LIMIT_F_INV);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_numgen
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_numgen.c via
 * the nft_ng_policy[] parser: NFTA_NG_DREG, NFTA_NG_MODULUS and
 * NFTA_NG_TYPE are mandatory, NFTA_NG_OFFSET is optional.  The TYPE
 * value dispatches to nft_ng_inc_init (NFT_NG_INCREMENTAL: atomic
 * counter mod modulus) or nft_ng_random_init (NFT_NG_RANDOM: PRNG mod
 * modulus); both reject modulus == 0 with -ERANGE, and any TYPE outside
 * {INCREMENTAL, RANDOM} is rejected with -EOPNOTSUPP before the
 * type-specific init runs.  The deprecated NFTA_NG_SET_NAME /
 * NFTA_NG_SET_ID anonymous-set variants are intentionally not emitted
 * here — they need their own slice with care around the .set policy
 * gate.
 *
 * Variants per call:
 *   - DREG uniform across NFT_REG_1..NFT_REG_4 so the destination
 *     register validation in nft_parse_register_store sees the full
 *     legacy-register spread.
 *   - MODULUS rolls uniformly across {2, 16, 256, 65536} so both the
 *     small-modulus per-byte fan-out (the natural per-byte hash spread)
 *     and the wide-modulus per-port-style fan-out land on the eval-time
 *     reciprocal_scale path.  All four values are > 0 so the
 *     -ERANGE guard in both init helpers never fires before the
 *     type-specific init runs.
 *   - TYPE is coin-flipped between NFT_NG_INCREMENTAL and
 *     NFT_NG_RANDOM so both dispatch arms (atomic counter increment vs
 *     prandom_u32_state in nft_ng_random_eval) see traffic.
 *   - OFFSET is coin-flipped present, value uniform over
 *     {0, 1, 0x100, 0xffff}; when present the eval-time u32 add of
 *     (counter % modulus) + offset exercises the offset-fold path
 *     including the wrap that 0xffff + small-modulus produces.
 */
size_t build_nft_numgen_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	static const __u32 moduli[] = {
		2U,			/* small: per-byte fan-out */
		16U,
		256U,
		65536U,			/* wide: per-port-style fan-out */
	};
	static const __u32 offsets[] = {
		0U, 1U, 0x100U, 0xffffU,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 dreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 modulus = moduli[rand32() % ARRAY_SIZE(moduli)];
	__u32 type = ONE_IN(2) ? NFT_NG_INCREMENTAL : NFT_NG_RANDOM;
	bool with_offset = ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "numgen");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_NG_DREG, dreg);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_NG_MODULUS, modulus);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_NG_TYPE, type);
	if (!off)
		return 0;

	if (with_offset) {
		__u32 offset = offsets[rand32() % ARRAY_SIZE(offsets)];

		off = nla_put_be32(buf, off, cap, NFTA_NG_OFFSET, offset);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_hash
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_hash.c via the
 * nft_hash_policy[] parser, which dispatches on NFTA_HASH_TYPE:
 * NFT_HASH_JENKINS (nft_jhash_init) consumes a contiguous LEN-byte
 * window starting at SREG, jhashes it with SEED and reduces mod MODULUS
 * (plus OFFSET if present); NFT_HASH_SYM (nft_symhash_init) reduces the
 * skb hash mod MODULUS and stores at DREG, ignoring SREG/LEN/SEED — the
 * parser actively rejects those attributes on the symhash path with
 * -EINVAL.  Both inits reject MODULUS == 0 with -ERANGE and any TYPE
 * outside {JENKINS, SYM} with -EOPNOTSUPP before the type-specific init
 * runs.  TYPE is emitted explicitly even though absent defaults to
 * JENKINS, so the on-wire shape is unambiguous regardless of which arm
 * we picked.  The deprecated NFTA_HASH_SET_NAME / NFTA_HASH_SET_ID
 * map-lookup variants are intentionally not emitted here — they need
 * their own slice with care around the .set policy gate.
 *
 * Variants per call:
 *   - TYPE coin-flips between NFT_HASH_JENKINS and NFT_HASH_SYM so both
 *     dispatch arms (per-packet jhash of an SREG window vs the precomputed
 *     skb->hash reduction) see traffic.  Per-arm attribute sets are
 *     emitted strictly: jhash carries SREG + LEN + optional SEED, symhash
 *     carries neither so the -EINVAL guard never fires before init.
 *   - DREG uniform across NFT_REG_1..NFT_REG_4 so the destination
 *     register validation in nft_parse_register_store sees the full
 *     legacy-register spread.
 *   - SREG (jhash only) uniform across NFT_REG_1..NFT_REG_4 so the
 *     source register validation in nft_parse_register_load lands on
 *     each of the legacy registers.
 *   - LEN (jhash only) rolls uniformly across {1, 4, 8, 16, 32}, all
 *     within the 1..NFT_REG_SIZE*4 == 1..64 range the parser enforces;
 *     the spread covers both single-byte and multi-register windows.
 *   - MODULUS rolls uniformly across {2, 16, 256, 65536} so both the
 *     small-modulus per-byte fan-out and the wide-modulus per-port-style
 *     fan-out land on the eval-time reciprocal_scale path.  All four
 *     values are > 0 so the -ERANGE guard never fires.
 *   - SEED (jhash only) is coin-flipped present, value uniform u32; when
 *     absent the kernel synthesises one via prandom at init time, so
 *     both seeded and self-seeded init paths get coverage.
 *   - OFFSET is coin-flipped present, value uniform over
 *     {0, 1, 0x100, 0xffff}; when present the eval-time u32 add of
 *     (hash % modulus) + offset exercises the offset-fold path including
 *     the wrap that 0xffff + small-modulus produces.
 */
size_t build_nft_hash_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	static const __u32 lens[] = { 1U, 4U, 8U, 16U, 32U };
	static const __u32 moduli[] = {
		2U,			/* small: per-byte fan-out */
		16U,
		256U,
		65536U,			/* wide: per-port-style fan-out */
	};
	static const __u32 offsets[] = {
		0U, 1U, 0x100U, 0xffffU,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 dreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 modulus = moduli[rand32() % ARRAY_SIZE(moduli)];
	__u32 type = ONE_IN(2) ? NFT_HASH_JENKINS : NFT_HASH_SYM;
	bool with_offset = ONE_IN(2);
	bool with_seed = ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "hash");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_HASH_DREG, dreg);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_HASH_MODULUS, modulus);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_HASH_TYPE, type);
	if (!off)
		return 0;

	if (type == NFT_HASH_JENKINS) {
		__u32 sreg = regs[rand32() % ARRAY_SIZE(regs)];
		__u32 len = lens[rand32() % ARRAY_SIZE(lens)];

		off = nla_put_be32(buf, off, cap, NFTA_HASH_SREG, sreg);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_HASH_LEN, len);
		if (!off)
			return 0;

		if (with_seed) {
			off = nla_put_be32(buf, off, cap, NFTA_HASH_SEED,
					   rand32());
			if (!off)
				return 0;
		}
	}

	if (with_offset) {
		__u32 offset = offsets[rand32() % ARRAY_SIZE(offsets)];

		off = nla_put_be32(buf, off, cap, NFTA_HASH_OFFSET, offset);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_synproxy
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_synproxy.c
 * via the nft_synproxy_policy[] parser and nft_synproxy_do_init().
 *
 * Each of the three attributes is individually OPTIONAL in do_init
 * (each is gated by `if (tb[...])` in the init body), so any subset is
 * accepted by the parser.  Per-attr coin-flips drive presence; if all
 * three coin-flips would produce the empty payload, MSS is forced
 * present so the priv struct does not stay at default-zero — which
 * leaves every option-emit path in nft_synproxy_eval cold.
 *
 * Variants per call:
 *   - NFTA_SYNPROXY_MSS (NLA_U16, big-endian on wire — the kernel reads
 *     it via ntohs(nla_get_be16())) is the TCP MSS the synproxy hands
 *     back to the backend.  The policy has no validator beyond the
 *     type, so values roll uniformly across {0, 536, 1460, 9000} —
 *     covering the degenerate zero, the IPv4 minimum, the typical
 *     ethernet MSS, and the jumbo-frame end of the range.  All four
 *     fit in 16 bits, so the truncation guard is never reached.
 *   - NFTA_SYNPROXY_WSCALE (NLA_U8) is the TCP window-scale shift.
 *     The policy is NLA_POLICY_MAX(NLA_U8, TCP_MAX_WSCALE) where
 *     TCP_MAX_WSCALE == 14, so the parser rejects values > 14 with
 *     -EINVAL before do_init runs.  WSCALE rolls uniformly across the
 *     full valid 0..14 range, exercising both the unscaled (0) and
 *     fully-scaled (14) ends of the SYN/ACK option emit path.
 *   - NFTA_SYNPROXY_FLAGS (NLA_BE32) is the option mask the synproxy
 *     reflects into its SYN/ACK.  The policy is
 *     NLA_POLICY_MASK(NLA_BE32, NF_SYNPROXY_OPT_MASK) where the mask is
 *     MSS | WSCALE | SACK_PERM | TIMESTAMP == 0x0F.  NF_SYNPROXY_OPT_ECN
 *     (0x10) is intentionally excluded from the mask and rejected by
 *     the parser — so FLAGS rolls uniformly across 0..0x0F to stay
 *     structurally valid and never trip the mask guard.  All sixteen
 *     combinations of the four allowed bits get reached, including the
 *     zero-bits payload that suppresses every per-option emit branch
 *     and the all-four-set payload that exercises every emit branch in
 *     one shot.
 *
 * The parser is a single-arm dispatch (no NFTA_*_TYPE selector picking
 * between sub-inits the way nft_hash and nft_numgen have).  Chain
 * context (LOCAL_IN / FORWARD priority on a base chain) is enforced by
 * nft_synproxy_validate at validate-hook time, NOT inside do_init — so
 * a NEWRULE carrying this expression on any chain still drives the
 * policy walker and do_init reliably; the validate-hook -EOPNOTSUPP
 * (when present) fires after the structurally-interesting work the
 * slice is here to exercise.
 */
size_t build_nft_synproxy_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u16 mss_values[] = {
		0U,				/* degenerate zero */
		536U,				/* IPv4 minimum */
		1460U,				/* typical ethernet */
		9000U,				/* jumbo frame */
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_mss = ONE_IN(2);
	bool with_wscale = ONE_IN(2);
	bool with_flags = ONE_IN(2);

	/* At least one attr keeps the priv struct off default-zero. */
	if (!with_mss && !with_wscale && !with_flags)
		with_mss = true;

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "synproxy");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (with_mss) {
		__u16 mss = mss_values[rand32() % ARRAY_SIZE(mss_values)];

		off = nla_put_be16(buf, off, cap, NFTA_SYNPROXY_MSS, mss);
		if (!off)
			return 0;
	}

	if (with_wscale) {
		__u8 wscale = (__u8)(rand32() % (TCP_MAX_WSCALE + 1));

		off = nla_put(buf, off, cap, NFTA_SYNPROXY_WSCALE,
			      &wscale, sizeof(wscale));
		if (!off)
			return 0;
	}

	if (with_flags) {
		__u32 flags = rand32() & (NF_SYNPROXY_OPT_MSS |
					  NF_SYNPROXY_OPT_WSCALE |
					  NF_SYNPROXY_OPT_SACK_PERM |
					  NF_SYNPROXY_OPT_TIMESTAMP);

		off = nla_put_be32(buf, off, cap, NFTA_SYNPROXY_FLAGS, flags);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_counter
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_counter.c
 * (nft_counter_init): both NFTA_COUNTER_BYTES and NFTA_COUNTER_PACKETS
 * are individually OPTIONAL u64 attributes (each gated by `if (tb[...])`
 * in the init body) and are read off the wire as big-endian via
 * be64_to_cpu(nla_get_be64()).  Whichever attrs are present become the
 * starting byte / packet counts for the per-cpu counter that
 * nft_counter_eval increments per matched skb.  The policy has no
 * bounds (any u64 is accepted), no flag mask, and no chain-context
 * restriction (no validate hook beyond standard expression validation).
 *
 * Variants per call:
 *   - BYTES rolls across {0, small, INT_MAX (0x7fffffff), U32_MAX
 *     (0xffffffff), near-U64_MAX} via a rand64()-shifted bucket pick so
 *     the per-cpu-counter add arithmetic in nft_counter_eval and the
 *     accumulating dump path in nft_counter_dump see both the
 *     freshly-zeroed counter and the wraparound-imminent counter on the
 *     very first matched packet.
 *   - PACKETS rolls across the same {0, small, INT_MAX, U32_MAX,
 *     near-U64_MAX} spread for the same reason on the packet-count
 *     accumulator.
 *
 * Each attribute is coin-flipped present independently.  If the
 * coin-flips would emit zero attrs the priv struct ends up at
 * default-zero — which is a valid path through the parser but skips the
 * nft_be64_set storage path entirely; PACKETS is forced present in
 * that case so at least one be64 actually flows through the init body.
 */
size_t build_nft_counter_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_bytes = ONE_IN(2);
	bool with_packets = ONE_IN(2);

	/* At least one attr keeps init off the all-default-zero shortcut. */
	if (!with_bytes && !with_packets)
		with_packets = true;

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "counter");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (with_bytes) {
		__u64 r = rand64();
		__u64 bytes;

		switch (r & 0x7) {
		case 0:
			bytes = 0ULL;
			break;
		case 1:
			bytes = (r >> 3) & 0xffffULL;
			break;
		case 2:
		case 3:
			bytes = 0x7fffffffULL;	/* INT_MAX */
			break;
		case 4:
		case 5:
			bytes = 0xffffffffULL;	/* U32_MAX */
			break;
		default:
			bytes = ~0ULL - ((r >> 3) & 0xffffULL);
			break;
		}
		off = nla_put_be64(buf, off, cap, NFTA_COUNTER_BYTES, bytes);
		if (!off)
			return 0;
	}

	if (with_packets) {
		__u64 r = rand64();
		__u64 packets;

		switch (r & 0x7) {
		case 0:
			packets = 0ULL;
			break;
		case 1:
			packets = (r >> 3) & 0xffffULL;
			break;
		case 2:
		case 3:
			packets = 0x7fffffffULL;	/* INT_MAX */
			break;
		case 4:
		case 5:
			packets = 0xffffffffULL;	/* U32_MAX */
			break;
		default:
			packets = ~0ULL - ((r >> 3) & 0xffffULL);
			break;
		}
		off = nla_put_be64(buf, off, cap, NFTA_COUNTER_PACKETS, packets);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_connlimit
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_connlimit.c
 * (nft_connlimit_do_init): NFTA_CONNLIMIT_COUNT (NLA_U32, big-endian on
 * wire — read via ntohl(nla_get_be32())) is REQUIRED — the kernel
 * returns -EINVAL when the attribute is missing — and seeds the per-rule
 * connection-count cap that nft_connlimit_do_eval's `count > limit`
 * gate compares against.  NFTA_CONNLIMIT_FLAGS (NLA_U32, big-endian) is
 * OPTIONAL: the only legal bit is NFT_CONNLIMIT_F_INV (0x01); any other
 * bit fails `flags & ~NFT_CONNLIMIT_F_INV` with -EOPNOTSUPP before the
 * priv struct is initialised.  When set, the inversion flag flips the
 * eval comparator's verdict via XOR so the over-cap branch becomes the
 * matching side instead of the rejecting side.
 *
 * Variants per call:
 *   - COUNT rolls across {0, 1, small, INT_MAX, U32_MAX} via a rand32()
 *     bucket pick so the eval-time `count > limit` comparator and the
 *     `(count > limit) ^ invert` verdict flip see both the
 *     trivially-tripped (0/1) and the can-never-trip (U32_MAX) ends of
 *     the spectrum on the very first conntrack-bearing skb.
 *   - FLAGS is coin-flipped present.  When present, the value stays
 *     within {0, NFT_CONNLIMIT_F_INV} so do_init's policy walker
 *     reaches the priv-struct setup instead of bailing at the EOPNOTSUPP
 *     gate every time.  ONE_IN(8) of the flag-present emissions
 *     deliberately set an out-of-mask byte (0x02..0xff) so the
 *     EOPNOTSUPP rejection path through the same `flags & ~MASK` check
 *     also gets exercised.
 */
size_t build_nft_connlimit_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 count_buckets[] = {
		0U,			/* trivially tripped */
		1U,			/* trivially tripped on the second conn */
		8U,			/* small */
		0x7fffffffU,		/* INT_MAX */
		0xffffffffU,		/* U32_MAX — can-never-trip */
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 count = count_buckets[rand32() % ARRAY_SIZE(count_buckets)];
	bool with_flags = ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "connlimit");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_CONNLIMIT_COUNT, count);
	if (!off)
		return 0;

	if (with_flags) {
		__u32 flags;

		if (ONE_IN(8)) {
			/* Drive the `flags & ~NFT_CONNLIMIT_F_INV` ->
			 * -EOPNOTSUPP rejection path: pick any non-zero
			 * byte from the disallowed range. */
			flags = 0x02U + (rand32() % 0xfeU);
		} else {
			flags = ONE_IN(2) ? NFT_CONNLIMIT_F_INV : 0U;
		}
		off = nla_put_be32(buf, off, cap, NFTA_CONNLIMIT_FLAGS, flags);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_masq
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_masq.c
 * (nft_masq_init, shared by the nft_masq_ipv4 / nft_masq_ipv6 /
 * nft_masq_inet modules via the same nft_masq_policy[]).  All three
 * attributes are OPTIONAL:
 *   - NFTA_MASQ_FLAGS (NLA_U32, big-endian on wire — read via
 *     ntohl(nla_get_be32())) is a subset of nf_nat_range flags.  The
 *     legal bits are NF_NAT_RANGE_PROTO_RANDOM (0x4),
 *     NF_NAT_RANGE_PERSISTENT (0x8) and NF_NAT_RANGE_PROTO_RANDOM_FULLY
 *     (0x10), i.e. NF_NAT_RANGE_MASK == 0x1c.  Any other bit fails the
 *     `flags & ~NF_NAT_RANGE_MASK` check with -EINVAL before the priv
 *     struct is initialised.
 *   - NFTA_MASQ_REG_PROTO_MIN / NFTA_MASQ_REG_PROTO_MAX (NLA_U32,
 *     big-endian) are register references (NFT_REG_*) bracketing the
 *     source-port rewrite range loaded at eval time.  If MIN is present
 *     and MAX is absent the kernel defaults MAX to MIN; MAX present
 *     without MIN is rejected with -EINVAL.
 * All three attributes absent leaves the expression at zero flags / no
 * port range — a legal but uninteresting pass-through, which is why the
 * coin-flips below favour at least one attribute being present most of
 * the time without forcing it.
 *
 * Variants per call:
 *   - FLAGS coin-flipped present (ONE_IN(2)).  When present, the value
 *     normally stays masked against NF_NAT_RANGE_MASK so do_init's
 *     policy walker reaches the priv-struct setup.  ONE_IN(8) of the
 *     flag-present emissions deliberately use a raw rand32() so the
 *     out-of-mask -EINVAL rejection path through the same
 *     `flags & ~NF_NAT_RANGE_MASK` check also gets exercised.
 *   - MIN coin-flipped present (ONE_IN(3)) with the value picked
 *     uniformly across NFT_REG_1..NFT_REG_4.
 *   - MAX is gated on MIN being present (ONE_IN(2) of the MIN-present
 *     emissions): emitting MAX without MIN would always trip the
 *     -EINVAL rejection that is NOT the intended coverage target here.
 */
size_t build_nft_masq_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_flags = ONE_IN(2);
	bool with_min = ONE_IN(3);
	bool with_max = with_min && ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "masq");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (with_flags) {
		__u32 flags;

		if (ONE_IN(8)) {
			/* Drive the `flags & ~NF_NAT_RANGE_MASK` ->
			 * -EINVAL rejection path with raw garbage that
			 * almost always lights up an out-of-mask bit. */
			flags = rand32();
		} else {
			flags = rand32() & 0x1cU;
		}
		off = nla_put_be32(buf, off, cap, NFTA_MASQ_FLAGS, flags);
		if (!off)
			return 0;
	}

	if (with_min) {
		__u32 reg = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap,
				   NFTA_MASQ_REG_PROTO_MIN, reg);
		if (!off)
			return 0;
	}

	if (with_max) {
		__u32 reg = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap,
				   NFTA_MASQ_REG_PROTO_MAX, reg);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_redir
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_redir.c
 * (nft_redir_init, shared by the nft_redir_ipv4 / nft_redir_ipv6 /
 * nft_redir_inet modules via the same nft_redir_policy[]).  All three
 * attributes are OPTIONAL:
 *   - NFTA_REDIR_REG_PROTO_MIN / NFTA_REDIR_REG_PROTO_MAX (NLA_U32,
 *     big-endian) are register references (NFT_REG_*) bracketing the
 *     destination-port rewrite range loaded at eval time.  If MIN is
 *     present and MAX is absent the kernel defaults MAX to MIN; MAX
 *     present without MIN is rejected with -EINVAL.
 *   - NFTA_REDIR_FLAGS (NLA_U32, big-endian on wire — read via
 *     ntohl(nla_get_be32())) is a subset of nf_nat_range flags drawn
 *     from the same NF_NAT_RANGE_MASK == 0x1c surface as nft_masq
 *     (NF_NAT_RANGE_PROTO_RANDOM 0x4, NF_NAT_RANGE_PERSISTENT 0x8,
 *     NF_NAT_RANGE_PROTO_RANDOM_FULLY 0x10).  Any other bit fails the
 *     `flags & ~NF_NAT_RANGE_MASK` check with -EINVAL before the priv
 *     struct is initialised.
 * All three attributes absent leaves the expression at zero flags / no
 * port range — a legal but uninteresting pass-through, which is why the
 * coin-flips below favour at least one attribute being present most of
 * the time without forcing it.
 *
 * Variants per call:
 *   - FLAGS coin-flipped present (ONE_IN(2)).  When present, the value
 *     normally stays masked against NF_NAT_RANGE_MASK so do_init's
 *     policy walker reaches the priv-struct setup.  ONE_IN(8) of the
 *     flag-present emissions deliberately use a raw rand32() so the
 *     out-of-mask -EINVAL rejection path through the same
 *     `flags & ~NF_NAT_RANGE_MASK` check also gets exercised.
 *   - MIN coin-flipped present (ONE_IN(3)) with the value picked
 *     uniformly across NFT_REG_1..NFT_REG_4.
 *   - MAX is gated on MIN being present (ONE_IN(2) of the MIN-present
 *     emissions): emitting MAX without MIN would always trip the
 *     -EINVAL rejection that is NOT the intended coverage target here.
 */
size_t build_nft_redir_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_flags = ONE_IN(2);
	bool with_min = ONE_IN(3);
	bool with_max = with_min && ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "redir");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (with_flags) {
		__u32 flags;

		if (ONE_IN(8)) {
			/* Drive the `flags & ~NF_NAT_RANGE_MASK` ->
			 * -EINVAL rejection path with raw garbage that
			 * almost always lights up an out-of-mask bit. */
			flags = rand32();
		} else {
			flags = rand32() & 0x1cU;
		}
		off = nla_put_be32(buf, off, cap, NFTA_REDIR_FLAGS, flags);
		if (!off)
			return 0;
	}

	if (with_min) {
		__u32 reg = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap,
				   NFTA_REDIR_REG_PROTO_MIN, reg);
		if (!off)
			return 0;
	}

	if (with_max) {
		__u32 reg = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap,
				   NFTA_REDIR_REG_PROTO_MAX, reg);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_tproxy
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_tproxy.c
 * (nft_tproxy_init), which walks nft_tproxy_policy[]:
 *   - NFTA_TPROXY_FAMILY (NLA_U32, big-endian on wire — read via
 *     ntohl(nla_get_be32())) carries the address family of the proxied
 *     destination.  Only NFPROTO_IPV4 (2) and NFPROTO_IPV6 (10) are
 *     accepted; any other value is rejected with -EINVAL before the
 *     priv struct is initialised.
 *   - NFTA_TPROXY_REG_ADDR / NFTA_TPROXY_REG_PORT (NLA_U32, big-endian)
 *     are register references (NFT_REG_*) bracketing the rewritten
 *     dst-addr / dst-port loaded at eval time.  Out-of-range register
 *     values are rejected with -ERANGE through nft_parse_register_load.
 * The kernel allows REG_ADDR and REG_PORT independently when the
 * family-resolution path is OK, so neither is gated on the other.
 *
 * Variants per call:
 *   - FAMILY: ONE_IN(2) emit IPV4 (2), else IPV6 (10) — the two
 *     accepted values that drive the priv-struct setup path.
 *     ONE_IN(8) of the FAMILY emissions deliberately uses a raw
 *     rand32() so the bad-family -EINVAL rejection path also gets
 *     exercised.
 *   - REG_ADDR coin-flipped present (ONE_IN(3)) with the value picked
 *     uniformly across NFT_REG_1..NFT_REG_4.
 *   - REG_PORT coin-flipped present (ONE_IN(3)), same register pick.
 *     Not gated on REG_ADDR — kernel accepts either independently.
 */
size_t build_nft_tproxy_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_addr = ONE_IN(3);
	bool with_port = ONE_IN(3);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "tproxy");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	{
		__u32 family;

		if (ONE_IN(8)) {
			/* Drive the bad-family -EINVAL rejection path
			 * with raw garbage that almost never lands on
			 * NFPROTO_IPV4 or NFPROTO_IPV6. */
			family = rand32();
		} else if (ONE_IN(2)) {
			family = NFPROTO_IPV4;
		} else {
			family = NFPROTO_IPV6;
		}
		off = nla_put_be32(buf, off, cap, NFTA_TPROXY_FAMILY, family);
		if (!off)
			return 0;
	}

	if (with_addr) {
		__u32 reg = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap,
				   NFTA_TPROXY_REG_ADDR, reg);
		if (!off)
			return 0;
	}

	if (with_port) {
		__u32 reg = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap,
				   NFTA_TPROXY_REG_PORT, reg);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_xfrm
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_xfrm.c
 * (nft_xfrm_get_init), which walks nft_xfrm_policy[] and requires all
 * three of NFTA_XFRM_KEY, NFTA_XFRM_DIR and NFTA_XFRM_DREG to be
 * present (-EINVAL otherwise).  ctx->family must be NFPROTO_IPV4 /
 * NFPROTO_IPV6 / NFPROTO_INET (-EOPNOTSUPP otherwise) and is enforced
 * before the policy walk.  NFTA_XFRM_SPNUM (NLA_POLICY_MAX(NLA_BE32,
 * 255)) is OPTIONAL — secpath array index, kernel ntohl()s the wire
 * value.
 *
 * Variants per call:
 *   - KEY: ONE_IN(7) for each of the six valid enum values
 *     (DADDR_IP4=1, DADDR_IP6=2, SADDR_IP4=3, SADDR_IP6=4, REQID=5,
 *     SPI=6) — these drive the success path through the init switch.
 *     ONE_IN(8) of the KEY emissions instead drops a raw rand32()
 *     capped at 255 so UNSPEC (0) and any value above the enum max
 *     exercise the -EINVAL leg.
 *   - DIR: ONE_IN(2) emit XFRM_POLICY_IN (0), else XFRM_POLICY_OUT
 *     (1) — the two accepted values.  ONE_IN(8) of the DIR emissions
 *     instead drops a raw u8 through to exercise the bad-direction
 *     -EINVAL rejection path.
 *   - DREG picked uniformly across NFT_REG_1..NFT_REG_4 inline,
 *     matching the cmp / range / numgen / hash / masq / redir / tproxy
 *     sibling pattern in this file (no shared helper).
 *   - SPNUM coin-flipped present (ONE_IN(3)).  When emitted, ONE_IN(2)
 *     small (0..7) else raw rand32() capped at 255 so both the
 *     reasonable-index and the policy-mask boundary get exercise.
 */
size_t build_nft_xfrm_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 dreg = NFT_REG_1 + (rand32() % 4);
	__u32 key;
	__u8 dir;

	if (ONE_IN(8)) {
		/* Drive UNSPEC(0) / >MAX -EINVAL legs through the
		 * NLA_POLICY_MAX cap and the init switch. */
		key = rand32() & 0xff;
	} else {
		switch (rand32() % 7) {
		case 0:
			key = NFT_XFRM_KEY_DADDR_IP4;
			break;
		case 1:
			key = NFT_XFRM_KEY_DADDR_IP6;
			break;
		case 2:
			key = NFT_XFRM_KEY_SADDR_IP4;
			break;
		case 3:
			key = NFT_XFRM_KEY_SADDR_IP6;
			break;
		case 4:
			key = NFT_XFRM_KEY_REQID;
			break;
		case 5:
			key = NFT_XFRM_KEY_SPI;
			break;
		default:
			/* Bucket 6: another raw-cap shot at the
			 * rejection path so the bad-key coverage is
			 * not entirely gated on the ONE_IN(8) above. */
			key = rand32() & 0xff;
			break;
		}
	}

	if (ONE_IN(8)) {
		dir = (__u8)(rand32() & 0xff);
	} else if (ONE_IN(2)) {
		dir = XFRM_POLICY_IN;
	} else {
		dir = XFRM_POLICY_OUT;
	}

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "xfrm");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_XFRM_KEY, key);
	if (!off)
		return 0;
	off = nla_put(buf, off, cap, NFTA_XFRM_DIR, &dir, sizeof(dir));
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_XFRM_DREG, dreg);
	if (!off)
		return 0;

	if (ONE_IN(3)) {
		__u32 spnum;

		if (ONE_IN(2))
			spnum = rand32() & 0x7;
		else
			spnum = rand32() & 0xff;
		off = nla_put_be32(buf, off, cap, NFTA_XFRM_SPNUM, spnum);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid
 * nft_dup_netdev expression into buf at off, returning the new offset
 * (or 0 on overflow).  Reaches the validator in
 * net/netfilter/nft_dup_netdev.c (nft_dup_netdev_init), which walks
 * nft_dup_netdev_policy[] and requires NFTA_DUP_SREG_DEV — a NLA_U32
 * register reference resolved through nft_parse_register_load with
 * NFT_DATA_VALUE size sizeof(int).  Missing returns -EINVAL,
 * out-of-range register values return -ERANGE.  The expression is
 * registered for NFPROTO_NETDEV table family only; emissions in any
 * other family get rejected at expression-type lookup before init
 * runs, which exercises the lookup-side rejection path on top of the
 * netdev-family success path.
 *
 * Variants per call:
 *   - SREG_DEV picked uniformly across NFT_REG_1..NFT_REG_4 inline,
 *     matching the cmp / range / numgen / hash / masq / redir /
 *     tproxy / xfrm sibling pattern in this file (no shared helper).
 *   - ONE_IN(8) of the SREG_DEV emissions instead drops a raw
 *     rand32() so out-of-range register values exercise the -ERANGE
 *     rejection leg in nft_parse_register_load.
 */
size_t build_nft_dup_netdev_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 sreg_dev;

	if (ONE_IN(8))
		sreg_dev = rand32();
	else
		sreg_dev = NFT_REG_1 + (rand32() % 4);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "dup");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_DUP_SREG_DEV, sreg_dev);
	if (!off)
		return 0;

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid
 * nft_dup_ipv4 expression into buf at off, returning the new offset
 * (or 0 on overflow).  Reaches the validator in
 * net/ipv4/netfilter/nft_dup_ipv4.c (nft_dup_ipv4_init), which walks
 * nft_dup_ipv4_policy[] and consumes:
 *   - NFTA_DUP_SREG_ADDR (NLA_U32) — REQUIRED — source register
 *     loading a __be32 IPv4 gateway address (sizeof(struct in_addr)),
 *     resolved through nft_parse_register_load.  Missing returns
 *     -EINVAL, out-of-range register values return -ERANGE.
 *   - NFTA_DUP_SREG_DEV (NLA_U32) — OPTIONAL — source register
 *     loading the int oif; absent leaves oif == -1 in the kernel
 *     branch.
 *
 * The expression is registered for NFPROTO_IPV4 table family only and
 * shares the "dup" expression name with the NFPROTO_NETDEV sibling in
 * net/netfilter/nft_dup_netdev.c — the expression-type lookup
 * disambiguates by ctx->family.  Emissions on non-IPv4 chains get
 * rejected at lookup before init runs, exercising the -ENOPROTOOPT
 * leg on top of the IPv4-family success path.  The dispatch loop in
 * this file is family-blind today; the family-mismatch coverage is
 * intentional kernel-side gating.
 *
 * Variants per call:
 *   - SREG_ADDR always emitted (the required-gate); picked uniformly
 *     across NFT_REG_1..NFT_REG_4 inline, matching the cmp / range /
 *     numgen / hash / masq / redir / tproxy / xfrm / dup_netdev
 *     sibling pattern in this file (no shared helper).
 *     ONE_IN(8) instead drops a raw rand32() so out-of-range register
 *     values exercise the -ERANGE rejection leg in
 *     nft_parse_register_load.
 *   - SREG_DEV coin-flipped present (ONE_IN(2)).  When emitted,
 *     picked uniformly across NFT_REG_1..NFT_REG_4 with the same
 *     ONE_IN(8) raw-rand32() escape hatch for -ERANGE coverage.
 */
size_t build_nft_dup_ipv4_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_dev = ONE_IN(2);
	__u32 sreg_addr, sreg_dev;

	if (ONE_IN(8))
		sreg_addr = rand32();
	else
		sreg_addr = NFT_REG_1 + (rand32() % 4);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "dup");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_DUP_SREG_ADDR, sreg_addr);
	if (!off)
		return 0;

	if (with_dev) {
		if (ONE_IN(8))
			sreg_dev = rand32();
		else
			sreg_dev = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap, NFTA_DUP_SREG_DEV, sreg_dev);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid
 * nft_dup_ipv6 expression into buf at off, returning the new offset
 * (or 0 on overflow).  Reaches the validator in
 * net/ipv6/netfilter/nft_dup_ipv6.c (nft_dup_ipv6_init), which walks
 * nft_dup_ipv6_policy[] and consumes:
 *   - NFTA_DUP_SREG_ADDR (NLA_U32) — REQUIRED — source register
 *     loading a struct in6_addr IPv6 gateway address
 *     (sizeof(struct in6_addr) == 16), resolved through
 *     nft_parse_register_load with NFT_DATA_VALUE.  Missing returns
 *     -EINVAL up front; out-of-range register values are rejected
 *     with -ERANGE inside nft_parse_register_load, and the
 *     16-byte load size makes -ERANGE easier to hit than the
 *     IPv4 sibling because high register indices have less room
 *     left in the register file.
 *   - NFTA_DUP_SREG_DEV (NLA_U32) — OPTIONAL — source register
 *     loading the int oif; absent leaves oif == -1 in the kernel
 *     branch.
 *
 * The expression is registered for NFPROTO_IPV6 table family only and
 * shares the "dup" expression name with the NFPROTO_NETDEV and
 * NFPROTO_IPV4 siblings in net/netfilter/nft_dup_netdev.c and
 * net/ipv4/netfilter/nft_dup_ipv4.c — the expression-type lookup
 * disambiguates by ctx->family.  Emissions on non-IPv6 chains
 * (ipv4 / inet / arp / bridge / netdev) get rejected at
 * expression-type lookup with -ENOPROTOOPT before init runs, which
 * exercises the family-mismatch leg on top of the IPv6-family success
 * path.  The dispatch loop in this file is family-blind today; the
 * family-mismatch coverage is intentional kernel-side gating.
 *
 * Variants per call:
 *   - SREG_ADDR always emitted (the required-gate); picked uniformly
 *     across NFT_REG_1..NFT_REG_4 inline, matching the cmp / range /
 *     numgen / hash / masq / redir / tproxy / xfrm / dup_netdev /
 *     dup_ipv4 sibling pattern in this file (no shared helper).
 *     ONE_IN(8) instead drops a raw rand32() so out-of-range register
 *     values exercise the -ERANGE rejection leg in
 *     nft_parse_register_load — particularly relevant here because
 *     the 16-byte in6_addr load tightens the upper bound on which
 *     register indices fit.
 *   - SREG_DEV coin-flipped present (ONE_IN(2)).  When emitted,
 *     picked uniformly across NFT_REG_1..NFT_REG_4 with the same
 *     ONE_IN(8) raw-rand32() escape hatch for -ERANGE coverage.
 */
size_t build_nft_dup_ipv6_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_dev = ONE_IN(2);
	__u32 sreg_addr, sreg_dev;

	if (ONE_IN(8))
		sreg_addr = rand32();
	else
		sreg_addr = NFT_REG_1 + (rand32() % 4);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "dup");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_DUP_SREG_ADDR, sreg_addr);
	if (!off)
		return 0;

	if (with_dev) {
		if (ONE_IN(8))
			sreg_dev = rand32();
		else
			sreg_dev = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap, NFTA_DUP_SREG_DEV, sreg_dev);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid
 * nft_fwd_netdev expression into buf at off, returning the new offset
 * (or 0 on overflow).  Reaches the validator in
 * net/netfilter/nft_fwd_netdev.c, which has two init paths sharing
 * the NFTA_FWD_* uapi enum:
 *   - nft_fwd_netdev_init (bare-forward arm): consumes only
 *     NFTA_FWD_SREG_DEV (NLA_U32) — REQUIRED — source register loading
 *     the int oif, resolved through nft_parse_register_load with
 *     NFT_DATA_VALUE size sizeof(int).  Missing returns -EINVAL up
 *     front; out-of-range register values are rejected with -ERANGE.
 *   - nft_fwd_neigh_init (forward-with-neigh-resolve arm): selected
 *     by the kernel when NFTA_FWD_SREG_ADDR is present.  Consumes
 *     NFTA_FWD_SREG_DEV (REQUIRED, same as above), NFTA_FWD_SREG_ADDR
 *     (NLA_U32) — source register loading struct in_addr (4 bytes)
 *     or struct in6_addr (16 bytes), and NFTA_FWD_NFPROTO (NLA_U32) —
 *     REQUIRED for this arm — carrying NFPROTO_IPV4 or NFPROTO_IPV6
 *     to pick the address load size.  Other family values are
 *     rejected on the address-load side.
 *
 * The expression is registered for NFPROTO_NETDEV table family only
 * and uses the expression name "fwd" (distinct from the "dup" name
 * shared by the nft_dup_* siblings).  Emissions on any other table
 * family are rejected at expression-type lookup with -ENOPROTOOPT
 * before init runs — that exercises the family-mismatch leg on top of
 * the netdev-family success path.  The dispatch loop in this file is
 * family-blind today; the family-mismatch coverage is intentional
 * kernel-side gating.
 *
 * Variants per call:
 *   - SREG_DEV always emitted (the required-gate); picked uniformly
 *     across NFT_REG_1..NFT_REG_4 inline, matching the cmp / range /
 *     numgen / hash / masq / redir / tproxy / xfrm / dup_netdev /
 *     dup_ipv4 / dup_ipv6 sibling pattern in this file (no shared
 *     helper).  ONE_IN(8) instead drops a raw rand32() so out-of-range
 *     register values exercise the -ERANGE rejection leg in
 *     nft_parse_register_load.
 *   - with_neigh coin-flipped (ONE_IN(2)).  When false, only SREG_DEV
 *     is emitted and the kernel takes the bare-forward init path;
 *     when true, SREG_ADDR + NFPROTO are also emitted and the kernel
 *     switches to nft_fwd_neigh_init.  Both arms are interesting.
 *     SREG_ADDR uses the same NFT_REG_1..NFT_REG_4 / ONE_IN(8) raw
 *     rand32() escape hatch as SREG_DEV.  NFPROTO is picked uniformly
 *     across {NFPROTO_IPV4, NFPROTO_IPV6}, with a ONE_IN(8) raw
 *     rand32() escape that hands the kernel a bogus family so the
 *     address-load size selection rejects it.
 */
size_t build_nft_fwd_netdev_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_neigh = ONE_IN(2);
	__u32 sreg_dev, sreg_addr, nfproto;

	if (ONE_IN(8))
		sreg_dev = rand32();
	else
		sreg_dev = NFT_REG_1 + (rand32() % 4);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "fwd");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_FWD_SREG_DEV, sreg_dev);
	if (!off)
		return 0;

	if (with_neigh) {
		if (ONE_IN(8))
			sreg_addr = rand32();
		else
			sreg_addr = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap, NFTA_FWD_SREG_ADDR, sreg_addr);
		if (!off)
			return 0;

		if (ONE_IN(8))
			nfproto = rand32();
		else if (ONE_IN(2))
			nfproto = NFPROTO_IPV4;
		else
			nfproto = NFPROTO_IPV6;

		off = nla_put_be32(buf, off, cap, NFTA_FWD_NFPROTO, nfproto);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_last
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_last.c
 * (nft_last_init) — both attributes are OPTIONAL.  NFTA_LAST_SET
 * (NLA_U32, big-endian on wire — read via ntohl(nla_get_be32())) is a
 * 0/1 flag controlling whether the 'last seen' state is pre-seeded as
 * already set.  NFTA_LAST_MSECS (NLA_U64, big-endian on wire — fed
 * through nf_msecs_to_jiffies64, which rejects negative-from-jiffies
 * wraps and oversized future-jiffies values) is only consumed when
 * SET == 1; init treats MSECS-with-SET==0 as a no-op for the seed.
 * The eval path just stores `jiffies` and bumps `set`, and dump
 * round-trips both fields, so the interesting validator coverage is
 * at init time.
 *
 * Bucket distribution per call (rand32() % 8):
 *   - both attributes absent (~1/4): default-init path, neither
 *     attribute seeds anything.
 *   - SET only present, value 0 (~1/8): policy walker consumes SET
 *     but the seed branch stays dormant.
 *   - SET only present, value 1 (~1/4): seeds 'set' with the default
 *     jiffies offset since MSECS is missing.
 *   - SET == 1 + MSECS small {0, 1, 1000} (~1/4): drives the
 *     fast-path through nf_msecs_to_jiffies64 with values that round
 *     to a sub-second jiffies offset.
 *   - SET == 1 + MSECS large {INT_MAX, U32_MAX, U64_MAX} as a 64-bit
 *     BE value (~1/8): drives nf_msecs_to_jiffies64's range-rejection
 *     paths for oversized future-jiffies and negative-from-jiffies
 *     wraps.
 */
size_t build_nft_last_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u64 msecs_small[] = { 0ULL, 1ULL, 1000ULL };
	static const __u64 msecs_large[] = {
		0x7fffffffULL,		/* INT_MAX */
		0xffffffffULL,		/* U32_MAX */
		0xffffffffffffffffULL,	/* U64_MAX */
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 bucket = rand32() & 0x7;
	bool with_set = false;
	bool with_msecs = false;
	__u32 set_val = 0;
	__u64 msecs_val = 0;

	switch (bucket) {
	case 0:
	case 1:
		/* both attributes absent — default-init shape */
		break;
	case 2:
		with_set = true;
		set_val = 0;
		break;
	case 3:
	case 4:
		with_set = true;
		set_val = 1;
		break;
	case 5:
	case 6:
		with_set = true;
		set_val = 1;
		with_msecs = true;
		msecs_val = msecs_small[rand32() % ARRAY_SIZE(msecs_small)];
		break;
	default:
		with_set = true;
		set_val = 1;
		with_msecs = true;
		msecs_val = msecs_large[rand32() % ARRAY_SIZE(msecs_large)];
		break;
	}

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "last");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (with_set) {
		off = nla_put_be32(buf, off, cap, NFTA_LAST_SET, set_val);
		if (!off)
			return 0;
	}

	if (with_msecs) {
		off = nla_put_be64(buf, off, cap, NFTA_LAST_MSECS, msecs_val);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_rt
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_rt.c
 * (nft_rt_init -> priv->key dispatch, then nft_rt_validate at commit
 * time).  Both NFTA_RT_DREG (NLA_U32) and NFTA_RT_KEY
 * (NLA_POLICY_MAX(NLA_BE32, 255)) are MANDATORY.
 *
 * KEY distribution per call (rand32() % 8):
 *   - CLASSID  ~1/4 (buckets 0,1): always valid across IPv4/IPv6/INET.
 *   - NEXTHOP4 ~1/4 (buckets 2,3): always valid.
 *   - NEXTHOP6 ~1/4 (buckets 4,5): always valid.
 *   - XFRM     ~1/8 (bucket  6):   always valid.
 *   - TCPMSS   ~1/8 (bucket  7):   only valid in FORWARD/LOCAL_OUT/
 *     POST_ROUTING hooks; nft_rt_validate rejects other hooks with
 *     -EOPNOTSUPP, which is the rejection-path coverage we want.
 *
 * DREG is picked uniformly from NFT_REG_1..NFT_REG_4 inline since the
 * existing emitters in this file each open-code their own register
 * pick (no shared helper).  No upper-bound clamping on KEY beyond what
 * the kernel mask enforces — picking from the valid enum exercises
 * the success path, and the kernel's own switch statement in
 * nft_rt_init rejects out-of-enum keys with -EINVAL when stale-host
 * headers expand to unknown values.
 */
size_t build_nft_rt_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 dreg = NFT_REG_1 + (rand32() % 4);
	__u32 bucket = rand32() & 0x7;
	__u32 key;

	switch (bucket) {
	case 0:
	case 1:
		key = NFT_RT_CLASSID;
		break;
	case 2:
	case 3:
		key = NFT_RT_NEXTHOP4;
		break;
	case 4:
	case 5:
		key = NFT_RT_NEXTHOP6;
		break;
	case 6:
		key = NFT_RT_XFRM;
		break;
	default:
		key = NFT_RT_TCPMSS;
		break;
	}

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "rt");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_RT_KEY, key);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_RT_DREG, dreg);
	if (!off)
		return 0;

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_fib
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_fib.c
 * (nft_fib_init -> cross-field constraint checks, then nft_fib_validate
 * at commit time for hook restrictions).  All three of NFTA_FIB_DREG
 * (NLA_U32), NFTA_FIB_RESULT (NLA_U32), and NFTA_FIB_FLAGS (NLA_U32)
 * are MANDATORY.
 *
 * RESULT distribution per call (rand32() % 3) — roughly 1/3 each:
 *   - OIF       (1): valid only on PRE_ROUTING/LOCAL_IN/FORWARD/
 *     LOCAL_OUT/POST_ROUTING hooks (nft_fib_validate -> -EOPNOTSUPP
 *     elsewhere).
 *   - OIFNAME   (2): same hook restriction as OIF.
 *   - ADDRTYPE  (3): no hook restriction unless OIF flag is set; the
 *     only RESULT that legally combines with NFTA_FIB_F_PRESENT.
 *
 * FLAGS distribution per call:
 *   - SADDR / DADDR slot (rand32() % 16): bucket 0 leaves NEITHER set
 *     (~1/16, drives -EINVAL in nft_fib_init), bucket 1 sets BOTH
 *     (~1/16, also -EINVAL), buckets 2..15 set exactly one (14/16
 *     total, split 7/7 between SADDR and DADDR by parity for a clean
 *     50/50 inside the in-policy slice).
 *   - MARK (~1/4 via ONE_IN(4)): legal when CONFIG_NF_CONNTRACK_MARK
 *     is on; rejected with -EOPNOTSUPP otherwise.
 *   - IIF / OIF (mutually exclusive, ~1/8 each via rand32() % 16
 *     buckets 0,1 -> IIF and 2,3 -> OIF; the kernel rejects -EINVAL
 *     if both are ever set, which can't happen here).
 *   - PRESENT (~1/4 via ONE_IN(4)) ONLY when RESULT=ADDRTYPE; on the
 *     other two RESULT values nft_fib_init returns -EOPNOTSUPP, so we
 *     deliberately leave PRESENT off to keep that bucket exercising
 *     the success path.
 *
 * DREG is picked uniformly from NFT_REG_1..NFT_REG_4 inline since the
 * existing emitters in this file each open-code their own register
 * pick (no shared helper).  No upper-bound clamping on RESULT or FLAGS
 * beyond what the kernel mask enforces — out-of-enum RESULT values
 * are rejected by nft_fib_init's switch statement with -EINVAL, which
 * is intended coverage if a stale-host header expands an unknown
 * value.
 */
size_t build_nft_fib_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 dreg = NFT_REG_1 + (rand32() % 4);
	__u32 result_bucket = rand32() % 3;
	__u32 saddr_daddr_bucket = rand32() % 16;
	__u32 iif_oif_bucket = rand32() % 16;
	__u32 result;
	__u32 flags = 0;

	switch (result_bucket) {
	case 0:
		result = NFT_FIB_RESULT_OIF;
		break;
	case 1:
		result = NFT_FIB_RESULT_OIFNAME;
		break;
	default:
		result = NFT_FIB_RESULT_ADDRTYPE;
		break;
	}

	switch (saddr_daddr_bucket) {
	case 0:
		break;
	case 1:
		flags |= NFTA_FIB_F_SADDR | NFTA_FIB_F_DADDR;
		break;
	default:
		if (saddr_daddr_bucket & 1)
			flags |= NFTA_FIB_F_DADDR;
		else
			flags |= NFTA_FIB_F_SADDR;
		break;
	}

	if (ONE_IN(4))
		flags |= NFTA_FIB_F_MARK;

	switch (iif_oif_bucket) {
	case 0:
	case 1:
		flags |= NFTA_FIB_F_IIF;
		break;
	case 2:
	case 3:
		flags |= NFTA_FIB_F_OIF;
		break;
	default:
		break;
	}

	if (result == NFT_FIB_RESULT_ADDRTYPE && ONE_IN(4))
		flags |= NFTA_FIB_F_PRESENT;

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "fib");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_FIB_RESULT, result);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_FIB_FLAGS, flags);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_FIB_DREG, dreg);
	if (!off)
		return 0;

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_exthdr
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the 4-arm parser in net/netfilter/nft_exthdr.c —
 * nft_exthdr_init dispatches on NFTA_EXTHDR_OP to one of
 * nft_exthdr_ipv6_init (OP_IPV6, the default when the attr is absent),
 * nft_exthdr_tcp_init (OP_TCPOPT, the only arm with a write variant via
 * NFTA_EXTHDR_SREG), nft_exthdr_ipv4_init (OP_IPV4) and
 * nft_exthdr_sctp_init (OP_SCTP).  Mandatory wire attrs are TYPE
 * (NLA_U8 — semantics depend on OP), OFFSET (NLA_U32 big-endian, byte
 * offset within the parsed header), LEN (NLA_U32 big-endian, validator
 * clamps at 127) plus exactly one of DREG (read) or SREG (write).
 *
 * OP distribution per call (rand32() % 4) — uniform across the four
 * kernel arms so each init helper sees an equal share of inbound
 * messages.  TYPE per arm is picked from an arm-appropriate set so the
 * post-OP switch lands on a recognised value:
 *   - OP_IPV6   : HOPOPT(0), ROUTING(43), FRAGMENT(44), DSTOPT(60),
 *                 MOBILITY(135) — drives nft_exthdr_ipv6_eval's
 *                 ipv6_find_hdr lookup with a real protocol number.
 *   - OP_TCPOPT : NOP(1), MSS(2), WSCALE(3), SACK_PERM(4), SACK(5),
 *                 TIMESTAMP(8), MD5SIG(19), AO(29), FASTOPEN(34) —
 *                 the kinds nft_exthdr_tcp_eval inspects.
 *   - OP_IPV4   : EOL(0), NOP(1), RR(7), TS(68), RA(148) — reachable
 *                 IPv4 option types parsed by nft_exthdr_ipv4_eval.
 *   - OP_SCTP   : DATA(0), INIT(1), INIT_ACK(2), SACK(3), HEARTBEAT(4),
 *                 HEARTBEAT_ACK(5) — chunk types walked by
 *                 nft_exthdr_sctp_eval.
 *
 * OFFSET is 0..63 (well within every arm's accept range) and LEN is
 * 1..16 (clear of the validator's 127 clamp).  DREG vs SREG split:
 * SREG is legal only on OP_TCPOPT, so for any other OP DREG is forced;
 * on OP_TCPOPT a coin flip (ONE_IN(4)) picks SREG to drive the write
 * arm, otherwise DREG drives the read arm.  Register value is uniform
 * across NFT_REG_1..NFT_REG_4 inline (no shared helper, matching the
 * surrounding emitters).  FLAGS is read-only territory: NFT_EXTHDR_F_PRESENT
 * is emitted ONE_IN(4) but only when SREG is NOT set — combining FLAGS
 * with SREG fails -EINVAL, and the rejection-path bucket is intentionally
 * kept narrow so the success path dominates.
 *
 * History: CVE-2022-1015 was a signed-integer wrap in nft_exthdr_init's
 * register-bound check on this expression; this emitter keeps the
 * validator path warm so any future regression in the same area
 * surfaces under fuzz.
 */
size_t build_nft_exthdr_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u8 ipv6_types[] = { 0, 43, 44, 60, 135 };
	static const __u8 tcpopt_types[] = { 1, 2, 3, 4, 5, 8, 19, 29, 34 };
	static const __u8 ipv4_types[] = { 0, 1, 7, 68, 148 };
	static const __u8 sctp_types[] = { 0, 1, 2, 3, 4, 5 };
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 op_bucket = rand32() % 4;
	__u32 op;
	__u8 type;
	__u32 offset = rand32() % 64;
	__u32 len = 1 + (rand32() % 16);
	__u32 reg = NFT_REG_1 + (rand32() % 4);
	bool use_sreg = false;
	bool emit_flags;

	switch (op_bucket) {
	case 0:
	default:
		op = NFT_EXTHDR_OP_IPV6;
		type = ipv6_types[rand32() % ARRAY_SIZE(ipv6_types)];
		break;
	case 1:
		op = NFT_EXTHDR_OP_TCPOPT;
		type = tcpopt_types[rand32() % ARRAY_SIZE(tcpopt_types)];
		use_sreg = ONE_IN(4);
		break;
	case 2:
		op = NFT_EXTHDR_OP_IPV4;
		type = ipv4_types[rand32() % ARRAY_SIZE(ipv4_types)];
		break;
	case 3:
		op = NFT_EXTHDR_OP_SCTP;
		type = sctp_types[rand32() % ARRAY_SIZE(sctp_types)];
		break;
	}

	emit_flags = !use_sreg && ONE_IN(4);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "exthdr");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (use_sreg)
		off = nla_put_be32(buf, off, cap, NFTA_EXTHDR_SREG, reg);
	else
		off = nla_put_be32(buf, off, cap, NFTA_EXTHDR_DREG, reg);
	if (!off)
		return 0;

	off = nla_put(buf, off, cap, NFTA_EXTHDR_TYPE, &type, sizeof(type));
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_EXTHDR_OFFSET, offset);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_EXTHDR_LEN, len);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_EXTHDR_OP, op);
	if (!off)
		return 0;

	if (emit_flags) {
		off = nla_put_be32(buf, off, cap, NFTA_EXTHDR_FLAGS,
				   NFT_EXTHDR_F_PRESENT);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_osf
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_osf.c
 * (nft_osf_init): NFTA_OSF_DREG is mandatory (NLA_BE32 register
 * destination capped at NFT_REG32_MAX, written across two 16-byte
 * register slots so the genre string up to NFT_OSF_MAXGENRELEN fits),
 * NFTA_OSF_TTL is optional (NLA_U8 — init only accepts 0..2, any value
 * above 2 trips -EINVAL) and NFTA_OSF_FLAGS is optional (NLA_BE32 —
 * init only accepts the exact value NFT_OSF_F_VERSION (0x01); any other
 * bit pattern, including 0, is rejected with -EINVAL).  nft_osf is
 * built CONFIG_NFT_OSF=m on the test kernel, so the policy validation
 * path only runs once the module is loaded — the emitter still produces
 * structurally-valid netlink either way.
 *
 * Variants per call:
 *   - DREG picks uniformly from NFT_REG_1..NFT_REG_4 so the genre
 *     string lands in whatever register a following cmp/range/bitwise
 *     emit will read against.
 *   - TTL is rolled ONE_IN(2); when attached the in-policy values
 *     {0, 1, 2} are weighted at ~7/8 (uniform across the three) so the
 *     success path dominates, with ~1/8 falling out to a uniform draw
 *     across the rejection range 3..255 to keep the -EINVAL bucket in
 *     nft_osf_init warm.
 *   - FLAGS is rolled ONE_IN(3); when attached the in-policy value
 *     NFT_OSF_F_VERSION is weighted at ~3/4 and the remaining ~1/4
 *     rolls a uniform draw across out-of-policy values
 *     {0, 0x2, 0x80, 0xff, 0xffffffff} so the exact-equals check in
 *     nft_osf_init also sees rejection traffic.
 */
size_t build_nft_osf_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 bad_flags[] = {
		0, 0x2, 0x80, 0xff, 0xffffffffU,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 dreg = NFT_REG_1 + (rand32() % 4);
	bool with_ttl = ONE_IN(2);
	bool with_flags = ONE_IN(3);
	__u8 ttl;
	__u32 flags;

	if (with_ttl) {
		if (ONE_IN(8))
			ttl = 3 + (rand32() % 253);	/* 3..255: -EINVAL */
		else
			ttl = (__u8)(rand32() % 3);	/* 0..2: in policy */
	} else {
		ttl = 0;
	}

	if (with_flags) {
		if (ONE_IN(4))
			flags = bad_flags[rand32() % ARRAY_SIZE(bad_flags)];
		else
			flags = NFT_OSF_F_VERSION;
	} else {
		flags = 0;
	}

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "osf");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_OSF_DREG, dreg);
	if (!off)
		return 0;

	if (with_ttl) {
		off = nla_put(buf, off, cap, NFTA_OSF_TTL, &ttl, sizeof(ttl));
		if (!off)
			return 0;
	}

	if (with_flags) {
		off = nla_put_be32(buf, off, cap, NFTA_OSF_FLAGS, flags);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_queue
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_queue.c — a
 * two-arm parser dispatched by nft_queue_init on whether
 * NFTA_QUEUE_SREG_QNUM is present:
 *
 *   STATIC arm (no SREG_QNUM):
 *     NFTA_QUEUE_NUM is mandatory (NLA_U16, BE16 on wire — the queue
 *     index).  NFTA_QUEUE_TOTAL is optional (NLA_U16, BE16 on wire,
 *     default 1, fanout count).  Init enforces
 *     priv->queuenum + priv->queues_total - 1 <= USHRT_MAX or
 *     -ERANGE.  NFTA_QUEUE_FLAGS is optional (NLA_U16, BE16 on wire);
 *     init checks (flags & ~NFT_QUEUE_FLAG_MASK) == 0 — any bit
 *     outside NFT_QUEUE_FLAG_BYPASS | NFT_QUEUE_FLAG_CPU_FANOUT trips
 *     -EINVAL.
 *
 *   SREG arm (SREG_QNUM present, no NUM):
 *     nft_queue_sreg_init reads NFTA_QUEUE_SREG_QNUM as a u32 register
 *     source (validated by nft_parse_register_load against
 *     NFT_REG32_00..NFT_REG32_15).  FLAGS still optional and validated
 *     against NFT_QUEUE_FLAG_MASK on this path too.
 *
 *   NUM and SREG_QNUM are mutually exclusive — passing both yields
 *   -EINVAL.  This emitter never produces that shape; the rejection
 *   path is left for a future bad-shape childop.
 *
 * Variants per call:
 *   - Arm picked uniformly via ONE_IN(2): STATIC vs SREG.
 *   - STATIC.NUM: drawn so NUM + (TOTAL ? TOTAL : 1) - 1 <= USHRT_MAX.
 *     With no TOTAL, NUM is uniform 0..0xFFFE.  With TOTAL = T, NUM is
 *     uniform 0..(0xFFFF - T) so the success path stays in policy.
 *   - STATIC.TOTAL: ONE_IN(2); when attached, uniform 1..16 to keep
 *     fanout small while still exercising the multi-queue path.
 *   - STATIC/SREG.FLAGS: ONE_IN(3); when attached, ~3/4 a uniform
 *     in-policy draw across {0, NFT_QUEUE_FLAG_BYPASS,
 *     NFT_QUEUE_FLAG_CPU_FANOUT, NFT_QUEUE_FLAG_MASK} so the success
 *     path dominates, and ~1/4 a uniform out-of-policy draw across
 *     {0x04, 0x08, 0x40, 0x80, 0xff, 0xfffe, 0xffff} to keep the
 *     ~NFT_QUEUE_FLAG_MASK rejection bucket in nft_queue_init warm.
 *   - SREG.SREG_QNUM: uniform across NFT_REG32_00..NFT_REG32_15.
 */
size_t build_nft_queue_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u16 good_flags[] = {
		0,
		NFT_QUEUE_FLAG_BYPASS,
		NFT_QUEUE_FLAG_CPU_FANOUT,
		NFT_QUEUE_FLAG_MASK,
	};
	static const __u16 bad_flags[] = {
		0x04, 0x08, 0x40, 0x80, 0xff, 0xfffe, 0xffff,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool sreg_arm = ONE_IN(2);
	bool with_total = !sreg_arm && ONE_IN(2);
	bool with_flags = ONE_IN(3);
	__u16 num = 0, total = 0, flags = 0;
	__u32 sreg_qnum = 0;

	if (sreg_arm) {
		sreg_qnum = NFT_REG32_00 + (rand32() % 16);
	} else {
		if (with_total) {
			total = (__u16)(1 + (rand32() % 16));
			num = (__u16)(rand32() % (0x10000U - total));
		} else {
			num = (__u16)(rand32() % 0xFFFFU);
		}
	}

	if (with_flags) {
		if (ONE_IN(4))
			flags = bad_flags[rand32() % ARRAY_SIZE(bad_flags)];
		else
			flags = good_flags[rand32() % ARRAY_SIZE(good_flags)];
	}

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "queue");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (sreg_arm) {
		off = nla_put_be32(buf, off, cap, NFTA_QUEUE_SREG_QNUM,
				   sreg_qnum);
		if (!off)
			return 0;
	} else {
		off = nla_put_be16(buf, off, cap, NFTA_QUEUE_NUM, num);
		if (!off)
			return 0;
		if (with_total) {
			off = nla_put_be16(buf, off, cap, NFTA_QUEUE_TOTAL,
					   total);
			if (!off)
				return 0;
		}
	}

	if (with_flags) {
		off = nla_put_be16(buf, off, cap, NFTA_QUEUE_FLAGS, flags);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Structurally-valid nft_immediate expression element.  Net layout:
 *   NFTA_LIST_ELEM (nested)
 *     NFTA_EXPR_NAME = "immediate"
 *     NFTA_EXPR_DATA (nested)
 *       NFTA_IMMEDIATE_DREG = NFT_REG_VERDICT | NFT_REG_1..NFT_REG_4
 *       NFTA_IMMEDIATE_DATA (nested)
 *         if DREG == NFT_REG_VERDICT:
 *           NFTA_DATA_VERDICT (nested)
 *             NFTA_VERDICT_CODE = NF_DROP|NF_ACCEPT|NFT_RETURN|NFT_CONTINUE
 *         else:
 *           NFTA_DATA_VALUE = LEN bytes random
 *
 * DREG picks NFT_REG_VERDICT (verdict carrier) ONE_IN(2), else uniform
 * across NFT_REG_1..NFT_REG_4 (constant-data loader).  When carrying a
 * verdict, terminal verdict codes are picked uniformly from
 * {NF_DROP, NF_ACCEPT, NFT_RETURN, NFT_CONTINUE} — this exercises the
 * non-jumping verdict branches in nft_immediate_eval that the hard-coded
 * NFT_JUMP/NFT_GOTO verdict element below never visits.  Constant-data
 * width coin-flips across {1, 2, 4, 8, 16} matching the cmp/bitwise
 * register-width spread.
 */
size_t build_nft_immediate_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 lens[] = { 1, 2, 4, 8, 16 };
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	static const __u32 verdicts[] = {
		NF_DROP, NF_ACCEPT, NFT_RETURN, NFT_CONTINUE,
	};
	struct nlattr *elem, *expr_data, *imm_data;
	size_t elem_off, expr_data_off, imm_data_off;
	__u32 dreg = ONE_IN(2)
		? NFT_REG_VERDICT
		: regs[rand32() % ARRAY_SIZE(regs)];

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "immediate");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_IMMEDIATE_DREG, dreg);
	if (!off)
		return 0;

	imm_data_off = off;
	off = nla_put(buf, off, cap, NFTA_IMMEDIATE_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (dreg == NFT_REG_VERDICT) {
		struct nlattr *verdict;
		size_t verdict_off;
		__u32 code = verdicts[rand32() % ARRAY_SIZE(verdicts)];

		verdict_off = off;
		off = nla_put(buf, off, cap,
			      NFTA_DATA_VERDICT | NLA_F_NESTED, NULL, 0);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_VERDICT_CODE, code);
		if (!off)
			return 0;
		verdict = (struct nlattr *)(buf + verdict_off);
		verdict->nla_len = (unsigned short)(off - verdict_off);
	} else {
		__u32 len_v = lens[rand32() % ARRAY_SIZE(lens)];
		unsigned char bytes[16];

		generate_rand_bytes(bytes, len_v);
		off = nla_put(buf, off, cap, NFTA_DATA_VALUE, bytes, len_v);
		if (!off)
			return 0;
	}

	imm_data = (struct nlattr *)(buf + imm_data_off);
	imm_data->nla_len = (unsigned short)(off - imm_data_off);
	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Structurally-valid nft_dynset expression element.  Net layout:
 *   NFTA_LIST_ELEM (nested)
 *     NFTA_EXPR_NAME = "dynset"
 *     NFTA_EXPR_DATA (nested)
 *       NFTA_DYNSET_SET_NAME = anon set built by build_newset
 *       NFTA_DYNSET_SET_ID   = matching cookie (in-batch resolution)
 *       NFTA_DYNSET_OP       = ADD | UPDATE | DELETE
 *       NFTA_DYNSET_SREG_KEY = NFT_REG_1..NFT_REG_4
 *       NFTA_DYNSET_SREG_DATA (1-in-2)  = NFT_REG_1..NFT_REG_4
 *       NFTA_DYNSET_TIMEOUT  (1-in-3)   = small u64 ms
 *       NFTA_DYNSET_FLAGS    (1-in-4)   = NFT_DYNSET_F_INV
 *
 * Reaches the validator in net/netfilter/nft_dynset.c (nft_dynset_init)
 * — set-binding lookup, op enum range check, sreg/timeout validation,
 * and the inv-flag gate that only makes sense for OP_DELETE.  dynset is
 * the runtime-mutating set update primitive used by conntrack helpers,
 * rate limiters, and the limit/quota convenience expressions; it has
 * been a recurring fuzz target (race against set teardown is the same
 * commit-vs-datapath window CVE-2024-1086 hung off).  Heavier weight
 * than the logging exprs because dynset mutates kernel state on every
 * datapath packet rather than just emitting a side effect.
 *
 * NFTA_DYNSET_EXPR / NFTA_DYNSET_EXPRESSIONS (nested expression
 * containers attached to each new set element) are intentionally not
 * emitted here — they need their own slice with care around the
 * stateful-vs-stateless expression policy.
 */
size_t build_nft_dynset_expr(unsigned char *buf, size_t off,
				    size_t cap, const char *set_name,
				    __u32 set_id)
{
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	static const __u32 ops[] = {
		NFT_DYNSET_OP_ADD,
		NFT_DYNSET_OP_UPDATE,
		NFT_DYNSET_OP_DELETE,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 op = ops[rand32() % ARRAY_SIZE(ops)];
	__u32 sreg_key = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 sreg_data = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 flags = ONE_IN(4) ? NFT_DYNSET_F_INV : 0;
	bool with_sreg_data = ONE_IN(2);
	bool with_timeout = ONE_IN(3);
	bool with_flags = ONE_IN(4);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "dynset");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_DYNSET_SET_NAME, set_name);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_DYNSET_SET_ID, set_id);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_DYNSET_OP, op);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_DYNSET_SREG_KEY, sreg_key);
	if (!off)
		return 0;
	if (with_sreg_data) {
		off = nla_put_be32(buf, off, cap,
				   NFTA_DYNSET_SREG_DATA, sreg_data);
		if (!off)
			return 0;
	}
	if (with_timeout) {
		__u64 timeout_ms = (__u64)((rand32() % 1000) + 1);
		__u64 be_t = ((__u64)htonl((__u32)(timeout_ms >> 32))) |
			     (((__u64)htonl((__u32)timeout_ms)) << 32);

		off = nla_put(buf, off, cap, NFTA_DYNSET_TIMEOUT,
			      &be_t, sizeof(be_t));
		if (!off)
			return 0;
	}
	if (with_flags) {
		off = nla_put_be32(buf, off, cap, NFTA_DYNSET_FLAGS, flags);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Structurally-valid nft_ct expression element.  Net layout:
 *   NFTA_LIST_ELEM (nested)
 *     NFTA_EXPR_NAME = "ct"
 *     NFTA_EXPR_DATA (nested)
 *       NFTA_CT_KEY = NFT_CT_*
 *       LOAD mode:
 *         NFTA_CT_DREG = NFT_REG_1..NFT_REG_4
 *         NFTA_CT_DIRECTION (1-in-2 for tuple keys) = ORIGINAL|REPLY
 *       STORE mode:
 *         NFTA_CT_SREG = NFT_REG_1..NFT_REG_4
 *
 * Reaches the validator in net/netfilter/nft_ct.c (nft_ct_get_init for
 * LOAD, nft_ct_set_init for STORE).  The per-key dispatch table maps
 * NFTA_CT_KEY to a load/store helper; STORE is rejected outright on
 * read-only keys, and the tuple-key handlers honour NFTA_CT_DIRECTION
 * to pick origin- vs reply-side conntrack tuple data.
 *
 * nft_ct is one of the most-used expressions in real rulesets —
 * connection tracking is foundational, every stateful firewall touches
 * it.  Hot kernel path with per-key dispatch logic, direction handling,
 * and LOAD/STORE asymmetry — all attractive bug surfaces.  Heavier
 * weight than the logging exprs because ct expressions touch live
 * conntrack state on every datapath packet.
 *
 * STORE-eligible keys mirror the nft_ct_set_keys[] table in the
 * kernel: NFT_CT_MARK, NFT_CT_LABELS, NFT_CT_EVENTMASK, NFT_CT_ZONE.
 * Tuple keys (direction-meaningful) are SRC/DST/PROTO_SRC/PROTO_DST
 * plus the explicit IPv4/IPv6 SRC_IP/DST_IP variants and the L3/L4
 * protocol pair.
 */
size_t build_nft_ct_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	static const __u32 load_keys[] = {
		NFT_CT_STATE, NFT_CT_DIRECTION, NFT_CT_STATUS,
		NFT_CT_MARK, NFT_CT_SECMARK, NFT_CT_EXPIRATION,
		NFT_CT_HELPER, NFT_CT_L3PROTOCOL, NFT_CT_PROTOCOL,
		NFT_CT_SRC, NFT_CT_DST, NFT_CT_PROTO_SRC, NFT_CT_PROTO_DST,
		NFT_CT_LABELS, NFT_CT_PKTS, NFT_CT_BYTES, NFT_CT_AVGPKT,
		NFT_CT_ZONE, NFT_CT_EVENTMASK,
		NFT_CT_SRC_IP, NFT_CT_DST_IP,
		NFT_CT_SRC_IP6, NFT_CT_DST_IP6,
		NFT_CT_ID,
	};
	static const __u32 store_keys[] = {
		NFT_CT_MARK, NFT_CT_LABELS, NFT_CT_EVENTMASK, NFT_CT_ZONE,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool store_mode = ONE_IN(2);
	__u32 key;
	__u32 reg = regs[rand32() % ARRAY_SIZE(regs)];

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "ct");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (store_mode) {
		key = store_keys[rand32() % ARRAY_SIZE(store_keys)];
		off = nla_put_be32(buf, off, cap, NFTA_CT_KEY, key);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_CT_SREG, reg);
		if (!off)
			return 0;
	} else {
		bool tuple_key;

		key = load_keys[rand32() % ARRAY_SIZE(load_keys)];
		off = nla_put_be32(buf, off, cap, NFTA_CT_KEY, key);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_CT_DREG, reg);
		if (!off)
			return 0;

		tuple_key = (key == NFT_CT_SRC || key == NFT_CT_DST ||
			     key == NFT_CT_PROTO_SRC ||
			     key == NFT_CT_PROTO_DST ||
			     key == NFT_CT_SRC_IP || key == NFT_CT_DST_IP ||
			     key == NFT_CT_SRC_IP6 || key == NFT_CT_DST_IP6);
		if (tuple_key && ONE_IN(2)) {
			__u8 dir = (rand32() & 1) ? IP_CT_DIR_REPLY
						  : IP_CT_DIR_ORIGINAL;

			off = nla_put(buf, off, cap, NFTA_CT_DIRECTION,
				      &dir, sizeof(dir));
			if (!off)
				return 0;
		}
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}
