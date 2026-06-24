/*
 * nftables-churn-exprs-data.c
 *
 * The data-plane primitive expression builders: payload, meta,
 * immediate, cmp, range, bitwise, byteorder, exthdr.
 *
 * Carved out of nftables-churn-exprs.c so the per-family builders
 * compile in parallel; see nftables-churn-internal.h for the
 * cross-TU symbol boundary.
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
