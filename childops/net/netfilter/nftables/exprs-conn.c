/*
 * exprs-conn.c
 *
 * The connection / routing / xfrm / socket expression builders: ct,
 * fib, rt, xfrm, socket.
 *
 * Carved out of exprs.c so the per-family builders
 * compile in parallel; see internal.h for the
 * cross-TU symbol boundary.
 */

#include "internal.h"

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
	__u32 reg = RAND_ARRAY(regs);

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
		key = RAND_ARRAY(store_keys);
		off = nla_put_be32(buf, off, cap, NFTA_CT_KEY, key);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_CT_SREG, reg);
		if (!off)
			return 0;
	} else {
		bool tuple_key;

		key = RAND_ARRAY(load_keys);
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

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_fib
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_fib.c
 * (nft_fib_init -> cross-field constraint checks, then nft_fib_validate
 * at commit time for hook restrictions).  All three of NFTA_FIB_DREG
 * (NLA_U32), NFTA_FIB_RESULT (NLA_U32), and NFTA_FIB_FLAGS (NLA_U32)
 * are MANDATORY.
 *
 * RESULT distribution per call (rnd_modulo_u32(3)) — roughly 1/3 each:
 *   - OIF       (1): valid only on PRE_ROUTING/LOCAL_IN/FORWARD/
 *     LOCAL_OUT/POST_ROUTING hooks (nft_fib_validate -> -EOPNOTSUPP
 *     elsewhere).
 *   - OIFNAME   (2): same hook restriction as OIF.
 *   - ADDRTYPE  (3): no hook restriction unless OIF flag is set; the
 *     only RESULT that legally combines with NFTA_FIB_F_PRESENT.
 *
 * FLAGS distribution per call:
 *   - SADDR / DADDR slot (rnd_modulo_u32(16)): bucket 0 leaves NEITHER set
 *     (~1/16, drives -EINVAL in nft_fib_init), bucket 1 sets BOTH
 *     (~1/16, also -EINVAL), buckets 2..15 set exactly one (14/16
 *     total, split 7/7 between SADDR and DADDR by parity for a clean
 *     50/50 inside the in-policy slice).
 *   - MARK (~1/4 via ONE_IN(4)): legal when CONFIG_NF_CONNTRACK_MARK
 *     is on; rejected with -EOPNOTSUPP otherwise.
 *   - IIF / OIF (mutually exclusive, ~1/8 each via rnd_modulo_u32(16)
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
	__u32 dreg = NFT_REG_1 + rnd_modulo_u32(4);
	__u32 result_bucket = rnd_modulo_u32(3);
	__u32 saddr_daddr_bucket = rnd_modulo_u32(16);
	__u32 iif_oif_bucket = rnd_modulo_u32(16);
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
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_rt
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_rt.c
 * (nft_rt_init -> priv->key dispatch, then nft_rt_validate at commit
 * time).  Both NFTA_RT_DREG (NLA_U32) and NFTA_RT_KEY
 * (NLA_POLICY_MAX(NLA_BE32, 255)) are MANDATORY.
 *
 * KEY distribution per call (rand32() & 0x7):
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
	__u32 dreg = NFT_REG_1 + rnd_modulo_u32(4);
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
	__u32 dreg = NFT_REG_1 + rnd_modulo_u32(4);
	__u32 key;
	__u8 dir;

	if (ONE_IN(8)) {
		/* Drive UNSPEC(0) / >MAX -EINVAL legs through the
		 * NLA_POLICY_MAX cap and the init switch. */
		key = rand32() & 0xff;
	} else {
		switch (rnd_modulo_u32(7)) {
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
	__u32 key = RAND_ARRAY(keys);
	__u32 dreg = RAND_ARRAY(regs);
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
