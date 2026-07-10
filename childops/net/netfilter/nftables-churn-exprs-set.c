/*
 * nftables-churn-exprs-set.c
 *
 * The set / map binding expression builders: lookup, objref, dynset.
 *
 * Carved out of nftables-churn-exprs.c so the per-family builders
 * compile in parallel; see nftables-churn-internal.h for the
 * cross-TU symbol boundary.
 */

#include "nftables-churn-internal.h"

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
	__u32 sreg = NFT_REG32_00 + rnd_modulo_u32(16);
	__u32 dreg = NFT_REG32_00 + rnd_modulo_u32(16);
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
		__u32 sreg = RAND_ARRAY(regs);
		bool with_name = ONE_IN(2);
		bool with_id = with_name ? ONE_IN(2) : true;

		off = nla_put_be32(buf, off, cap,
				   NFTA_OBJREF_SET_SREG, sreg);
		if (!off)
			return 0;
		if (with_name) {
			const char *nm = RAND_ARRAY(obj_names);

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
		const char *nm = RAND_ARRAY(obj_names);
		__u32 type = RAND_ARRAY(obj_types);

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
	__u32 op = RAND_ARRAY(ops);
	__u32 sreg_key = RAND_ARRAY(regs);
	__u32 sreg_data = RAND_ARRAY(regs);
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
		__u64 timeout_ms = (__u64)(rnd_modulo_u32(1000) + 1);
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
