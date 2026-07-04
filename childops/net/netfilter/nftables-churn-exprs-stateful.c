/*
 * nftables-churn-exprs-stateful.c
 *
 * The stateful expression builders: counter, connlimit, quota, limit,
 * last, log.
 *
 * Carved out of nftables-churn-exprs.c so the per-family builders
 * compile in parallel; see nftables-churn-internal.h for the
 * cross-TU symbol boundary.
 */

#include "nftables-churn-internal.h"

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
