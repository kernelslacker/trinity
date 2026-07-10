/*
 * nftables-churn-exprs-nat.c
 *
 * The NAT / netdev redirect / dup / fwd expression builders: masq,
 * redir, tproxy, dup_netdev, dup_ipv4, dup_ipv6, fwd_netdev.
 *
 * Carved out of nftables-churn-exprs.c so the per-family builders
 * compile in parallel; see nftables-churn-internal.h for the
 * cross-TU symbol boundary.
 */

#include "nftables-churn-internal.h"

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
		__u32 reg = NFT_REG_1 + (rnd_modulo_u32(4));

		off = nla_put_be32(buf, off, cap,
				   NFTA_MASQ_REG_PROTO_MIN, reg);
		if (!off)
			return 0;
	}

	if (with_max) {
		__u32 reg = NFT_REG_1 + (rnd_modulo_u32(4));

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
		__u32 reg = NFT_REG_1 + (rnd_modulo_u32(4));

		off = nla_put_be32(buf, off, cap,
				   NFTA_REDIR_REG_PROTO_MIN, reg);
		if (!off)
			return 0;
	}

	if (with_max) {
		__u32 reg = NFT_REG_1 + (rnd_modulo_u32(4));

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
		__u32 reg = NFT_REG_1 + (rnd_modulo_u32(4));

		off = nla_put_be32(buf, off, cap,
				   NFTA_TPROXY_REG_ADDR, reg);
		if (!off)
			return 0;
	}

	if (with_port) {
		__u32 reg = NFT_REG_1 + (rnd_modulo_u32(4));

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
		sreg_dev = NFT_REG_1 + (rnd_modulo_u32(4));

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
		sreg_addr = NFT_REG_1 + (rnd_modulo_u32(4));

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
			sreg_dev = NFT_REG_1 + (rnd_modulo_u32(4));

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
		sreg_addr = NFT_REG_1 + (rnd_modulo_u32(4));

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
			sreg_dev = NFT_REG_1 + (rnd_modulo_u32(4));

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
		sreg_dev = NFT_REG_1 + (rnd_modulo_u32(4));

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
			sreg_addr = NFT_REG_1 + (rnd_modulo_u32(4));

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
