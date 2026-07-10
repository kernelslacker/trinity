/*
 * nftables-churn-exprs-hash.c
 *
 * The numgen / hash / queue / syn-defense expression builders:
 * numgen, hash, synproxy, osf, queue.
 *
 * Carved out of nftables-churn-exprs.c so the per-family builders
 * compile in parallel; see nftables-churn-internal.h for the
 * cross-TU symbol boundary.
 */

#include "nftables-churn-internal.h"

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
	__u32 dreg = RAND_ARRAY(regs);
	__u32 modulus = RAND_ARRAY(moduli);
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
		__u32 offset = RAND_ARRAY(offsets);

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
	__u32 dreg = RAND_ARRAY(regs);
	__u32 modulus = RAND_ARRAY(moduli);
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
		__u32 sreg = RAND_ARRAY(regs);
		__u32 len = RAND_ARRAY(lens);

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
		__u32 offset = RAND_ARRAY(offsets);

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
		__u16 mss = RAND_ARRAY(mss_values);

		off = nla_put_be16(buf, off, cap, NFTA_SYNPROXY_MSS, mss);
		if (!off)
			return 0;
	}

	if (with_wscale) {
		__u8 wscale = (__u8)rnd_modulo_u32(TCP_MAX_WSCALE + 1);

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
	__u32 dreg = NFT_REG_1 + rnd_modulo_u32(4);
	bool with_ttl = ONE_IN(2);
	bool with_flags = ONE_IN(3);
	__u8 ttl;
	__u32 flags;

	if (with_ttl) {
		if (ONE_IN(8))
			ttl = 3 + rnd_modulo_u32(253);	/* 3..255: -EINVAL */
		else
			ttl = (__u8)rnd_modulo_u32(3);	/* 0..2: in policy */
	} else {
		ttl = 0;
	}

	if (with_flags) {
		if (ONE_IN(4))
			flags = RAND_ARRAY(bad_flags);
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
		sreg_qnum = NFT_REG32_00 + rnd_modulo_u32(16);
	} else {
		if (with_total) {
			total = (__u16)(1 + rnd_modulo_u32(16));
			num = (__u16)rnd_modulo_u32(0x10000U - total);
		} else {
			num = (__u16)rnd_modulo_u32(0xFFFFU);
		}
	}

	if (with_flags) {
		if (ONE_IN(4))
			flags = RAND_ARRAY(bad_flags);
		else
			flags = RAND_ARRAY(good_flags);
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
