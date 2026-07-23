/*
 * msg-rtnl-payloads.c
 *
 * Per-rtnetlink-group attribute payload builders, split out of
 * net/netlink/msg.c so the message emitter / dispatcher TU stays
 * focused on protocol-body and dispatch logic and the per-group
 * payload bodies can compile in parallel.  The five generators here
 * (gen_rta_{route,link,addr,neigh,dcb}_payload) are dispatched from
 * the gen_rta_payload switch in msg.c.
 *
 * The four cross-family helpers (rand_ipv4, rand_ipv6, start_nlattr,
 * build_nested_attrs) live in net/netlink/msg-rtnl-common.c and are
 * declared in msg-rtnl-common.h so any per-family TU that is later
 * split out of here can reuse the same bodies without duplication.
 */
#include <sys/socket.h>
#include <stddef.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if_addrlabel.h>
#include <linux/if_link.h>
#include <linux/neighbour.h>
#include <linux/fib_rules.h>
#include <linux/dcbnl.h>
#include <linux/nexthop.h>
#include <linux/netconf.h>
#include <linux/if_bridge.h>
#include <linux/net_namespace.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <string.h>
#include "netlink-attrs.h"
#include "msg-internal.h"
#include "msg-rtnl-common.h"
#include "random.h"
#include "trinity.h"
#include "rnd.h"
#include "utils-macros.h"		/* ARRAY_SIZE, RAND_ARRAY */

/* Prototype mirrored from the forward declaration in net/netlink/msg.c;
 * kept here (rather than in msg-internal.h next to its
 * gen_rta_* siblings) to keep the rtnl_addrlabel wire-up confined to
 * the two TUs that actually need it. */
size_t gen_rta_addrlabel_payload(unsigned char *p, size_t avail,
				 unsigned short nla_type);

/* Same shape as gen_rta_neightbl_payload above: prototype kept here
 * rather than in msg-internal.h to confine the rtnl_stats
 * wire-up to the two TUs that actually need it. */
size_t gen_rta_stats_payload(unsigned char *p, size_t avail,
			     unsigned short nla_type);

/* Same shape as gen_rta_neightbl_payload above: prototype kept here
 * rather than in msg-internal.h to confine the rtnl_action
 * wire-up to the two TUs that actually need it. */
size_t gen_rta_action_payload(unsigned char *p, size_t avail,
			      unsigned short nla_type);

/*
 * Generate a structured payload for address attributes (IFA_*).
 */
size_t gen_rta_addr_payload(unsigned char *p, size_t avail,
			    unsigned short nla_type, unsigned char family)
{
	switch (nla_type) {
	case IFA_ADDRESS:
	case IFA_LOCAL:
	case IFA_BROADCAST:
	case IFA_ANYCAST:
		if (family == AF_INET6 && avail >= 16) {
			struct in6_addr addr;
			rand_ipv6(&addr);
			memcpy(p, &addr, 16);
			return 16;
		}
		if (avail >= 4) {
			__u32 addr = rand_ipv4();
			memcpy(p, &addr, 4);
			return 4;
		}
		return 0;

	case IFA_LABEL: {
		static const char *labels[] = {
			"eth0", "eth0:1", "lo", "br0",
		};
		const char *label = RAND_ARRAY(labels);
		size_t slen = strlen(label) + 1;

		if (avail >= slen) {
			memcpy(p, label, slen);
			return slen;
		}
		return 0;
	}

	case IFA_CACHEINFO:
		if (avail >= sizeof(struct ifa_cacheinfo)) {
			struct ifa_cacheinfo ci;
			ci.ifa_prefered = rand32();
			ci.ifa_valid = rand32();
			ci.cstamp = rand32();
			ci.tstamp = rand32();
			memcpy(p, &ci, sizeof(ci));
			return sizeof(ci);
		}
		return 0;

	case IFA_FLAGS:
	case IFA_RT_PRIORITY:
		if (avail >= 4) {
			__u32 val = rand32();
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case IFA_PROTO:
		if (avail >= 1) {
			*p = rnd_modulo_u32(256);
			return 1;
		}
		return 0;

	default:
		return 0;
	}
}

/*
 * Generate a structured payload for DCB rtnetlink attributes (DCB_ATTR_*).
 * Only the two attrs the kernel demuxer cares about for reaching the
 * per-feature setters get structured payloads here; everything else
 * returns 0 so the caller falls back to a random blob.
 */
size_t gen_rta_dcb_payload(unsigned char *p, size_t avail,
			   unsigned short nla_type)
{
	switch (nla_type) {
	case DCB_ATTR_IFNAME: {
		static const char *names[] = {
			"lo", "eth0", "br0", "veth0", "dummy0",
		};
		const char *name = RAND_ARRAY(names);
		size_t slen = strlen(name) + 1;

		if (avail >= slen) {
			memcpy(p, name, slen);
			return slen;
		}
		return 0;
	}

	case DCB_ATTR_IEEE:
		/* Nested container of DCB_ATTR_IEEE_* sub-attributes;
		 * mirrors RTA_METRICS' use of build_nested_attrs above. */
		if (avail >= NLA_HDRLEN + 8) {
			return build_nested_attrs(p, avail, dcb_ieee_attrs,
						  dcb_ieee_attrs_n, 0);
		}
		return 0;

	default:
		return 0;
	}
}

/*
 * Generate a structured payload for tc rtnetlink attributes (TCA_*).
 * Covers RTM_*QDISC / RTM_*TCLASS / RTM_*TFILTER message groups (5/6/7).
 * TCA_KIND is the single highest-leverage attr: it selects the
 * Qdisc_ops / tcf_proto_ops the kernel demuxes to, so a real kind name
 * is what gets the message past find_qdisc_kind() / tcf_proto_lookup()
 * into the per-kind validator.  The fixed-size structs (tc_estimator,
 * tc_stats) and scalar u32/u8 attrs follow the rtm_tca_policy widths
 * so they survive the top-level NLA_BINARY / NLA_U32 / NLA_U8 length
 * checks.  Anything outside this set returns 0 so the caller falls
 * back to a random blob.
 */
size_t gen_rta_tc_payload(unsigned char *p, size_t avail,
			  unsigned short nla_type)
{
	switch (nla_type) {
	case TCA_KIND: {
		/* String: qdisc / class / filter kind.  Picking a real kind
		 * resolves a Qdisc_ops or tcf_proto_ops and reaches the
		 * per-kind validator instead of bouncing off -ENOENT. */
		static const char *kinds[] = {
			"pfifo", "bfifo", "pfifo_fast", "fq", "fq_codel",
			"codel", "htb", "hfsc", "tbf", "sfq", "red", "prio",
			"noqueue", "ingress", "clsact", "netem", "drr",
			"mqprio", "multiq", "etf", "taprio", "ets", "cake",
			"u32", "fw", "route", "tcindex", "basic", "cgroup",
			"matchall", "flower", "bpf", "rsvp",
		};
		const char *name = RAND_ARRAY(kinds);
		size_t slen = strlen(name) + 1;

		if (avail >= slen) {
			memcpy(p, name, slen);
			return slen;
		}
		return 0;
	}

	case TCA_RATE:
		if (avail >= sizeof(struct tc_estimator)) {
			struct tc_estimator est;

			est.interval = rnd_modulo_u32(8);
			est.ewma_log = rnd_modulo_u32(16);
			memcpy(p, &est, sizeof(est));
			return sizeof(est);
		}
		return 0;

	case TCA_CHAIN:
	case TCA_INGRESS_BLOCK:
	case TCA_EGRESS_BLOCK:
	case TCA_FCNT:
		if (avail >= 4) {
			__u32 val = rnd_modulo_u32(64);

			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case TCA_HW_OFFLOAD:
		if (avail >= 1) {
			*p = rnd_modulo_u32(2);
			return 1;
		}
		return 0;

	case TCA_DUMP_FLAGS:
		/* NLA_BITFIELD32: u32 value + u32 selector mask. */
		if (avail >= sizeof(struct nla_bitfield32)) {
			struct nla_bitfield32 bf;

			bf.selector = TCA_DUMP_FLAGS_TERSE;
			bf.value = rnd_modulo_u32(2) ? TCA_DUMP_FLAGS_TERSE : 0;
			memcpy(p, &bf, sizeof(bf));
			return sizeof(bf);
		}
		return 0;

	case TCA_EXT_WARN_MSG: {
		static const char *msgs[] = {
			"warn", "kind-mismatch", "bad-attr",
		};
		const char *msg = RAND_ARRAY(msgs);
		size_t slen = strlen(msg) + 1;

		if (avail >= slen) {
			memcpy(p, msg, slen);
			return slen;
		}
		return 0;
	}

	case TCA_STATS:
		/* Legacy fixed-size struct tc_stats. */
		if (avail >= sizeof(struct tc_stats)) {
			struct tc_stats st;

			generate_rand_bytes((unsigned char *)&st, sizeof(st));
			memcpy(p, &st, sizeof(st));
			return sizeof(st);
		}
		return 0;

	case TCA_OPTIONS:
	case TCA_STAB:
	case TCA_STATS2:
		/* Nested containers.  TCA_OPTIONS is the per-kind options
		 * blob (cls_u32_policy, fq_codel_policy, …); TCA_STAB is
		 * the size table; TCA_STATS2 is the modern stats nest.
		 * The sub-attr namespaces differ per container, so emit a
		 * generic small nest with valid nlattr framing — that gets
		 * past nla_parse_nested into the per-kind / per-stat
		 * policy walker. */
		if (avail >= NLA_HDRLEN + 8) {
			return build_nested_attrs(p, avail, tca_attrs,
						  tca_attrs_n, 0);
		}
		return 0;

	default:
		return 0;
	}
}

/*
 * Generate a structured payload for netconf rtnetlink attributes
 * (NETCONFA_*).  Covers the RTM_*NETCONF message group (16).
 * The kernel ipv4 / ipv6 devconf_{ipv4,ipv6}_policy walker pins
 * NETCONFA_IFINDEX at nla_len == sizeof(int); a random-byte payload
 * almost never lands exactly 4 bytes wide, so the message bounces on
 * nla_parse before reaching inet_netconf_get_devconf / its ipv6
 * sibling.  Sizing every NETCONFA_* to its s32 width gets the
 * message past nla_parse into the per-attr handlers, where the
 * meaningful sentinels NETCONFA_IFINDEX_ALL (-1) and
 * NETCONFA_IFINDEX_DEFAULT (-2) pick the all-devices / default
 * arms before the per-ifindex devinet lookup runs.
 */
size_t gen_rta_netconf_payload(unsigned char *p, size_t avail,
			       unsigned short nla_type)
{
	switch (nla_type) {
	case NETCONFA_IFINDEX:
		/* s32 ifindex; the two negative sentinels are real
		 * userland values the kernel handler special-cases
		 * before the per-ifindex devinet lookup, so seed them
		 * alongside small positive values that ride a sibling
		 * ifindex's per-netns slot. */
		if (avail >= 4) {
			__s32 val;

			switch (rnd_modulo_u32(4)) {
			case 0: val = -1; break;
			case 1: val = -2; break;
			default: val = rnd_modulo_u32(64); break;
			}
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case NETCONFA_FORWARDING:
	case NETCONFA_RP_FILTER:
	case NETCONFA_MC_FORWARDING:
	case NETCONFA_PROXY_NEIGH:
	case NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN:
	case NETCONFA_INPUT:
	case NETCONFA_BC_FORWARDING:
		/* s32 toggle attrs the ipv4 / ipv6 fill paths emit via
		 * nla_put_s32; the kernel stores them into per-netns /
		 * per-ifa devconf as truthy / zero / negative, so mix
		 * 0 / 1 / -1 / wider values to exercise sign-handling
		 * and range-trim arms in the per-setting writers. */
		if (avail >= 4) {
			__s32 val;

			switch (rnd_modulo_u32(4)) {
			case 0: val = 0; break;
			case 1: val = 1; break;
			case 2: val = -1; break;
			default: val = (__s32)rnd_u32(); break;
			}
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	default:
		return 0;
	}
}

/*
 * Generate a structured payload for address-label rtnetlink attributes
 * (IFAL_*).  Covers the RTM_*ADDRLABEL message group (14).  The kernel
 * net/ipv6/addrlabel.c:ip6addrlbl_newdel walker parses ifal_policy,
 * which length-rejects IFAL_ADDRESS (.len = sizeof(struct in6_addr))
 * and IFAL_LABEL (.len = sizeof(u32)) at the wrong-width gate before
 * the per-attr writer runs -- a random-byte payload of length [0, 64)
 * almost never lands at exactly 16 / 4 bytes wide, so the message is
 * rejected at nla_parse before ip6addrlbl_{add,del} runs and the
 * handler additionally requires both attrs present to dispatch.  Size
 * IFAL_ADDRESS to 16 bytes via the existing rand_ipv6 helper
 * (addrlabel is IPv6-only: ip6addrlbl_newdel -EINVALs unless
 * ifal_family == AF_INET6) and IFAL_LABEL to 4 bytes so the parse
 * reaches the per-attr writers.
 */
size_t gen_rta_addrlabel_payload(unsigned char *p, size_t avail,
				 unsigned short nla_type)
{
	switch (nla_type) {
	case IFAL_ADDRESS:
		if (avail >= sizeof(struct in6_addr)) {
			struct in6_addr addr;

			rand_ipv6(&addr);
			memcpy(p, &addr, sizeof(addr));
			return sizeof(addr);
		}
		return 0;

	case IFAL_LABEL:
		if (avail >= 4) {
			__u32 val = rnd_modulo_u32(64);

			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	default:
		return 0;
	}
}

/*
 * Generate a structured payload for link-stats rtnetlink attributes
 * (IFLA_STATS_*).  Covers the RTM_*STATS message group (19).  The
 * IFLA_STATS_LINK_64 attr carries a fixed-width struct
 * rtnl_link_stats64 -- a random-byte payload of length [0, 64) almost
 * never lands at exactly sizeof(struct rtnl_link_stats64), so the attr
 * is length-rejected at the policy gate before any consumer sees it.
 * Size IFLA_STATS_LINK_64 to the struct width and fill with random
 * counter values so the per-attr writer runs.  The remaining
 * IFLA_STATS_* slots (LINK_XSTATS, LINK_XSTATS_SLAVE,
 * LINK_OFFLOAD_XSTATS, AF_SPEC) are NLA_NESTED chains; let those fall
 * through to the random-byte fallback.
 */
size_t gen_rta_stats_payload(unsigned char *p, size_t avail,
			     unsigned short nla_type)
{
	switch (nla_type) {
	case IFLA_STATS_LINK_64:
		if (avail >= sizeof(struct rtnl_link_stats64)) {
			struct rtnl_link_stats64 st;

			generate_rand_bytes((unsigned char *)&st, sizeof(st));
			memcpy(p, &st, sizeof(st));
			return sizeof(st);
		}
		return 0;

	default:
		return 0;
	}
}

/*
 * Registered tc action kind names.  Selecting one resolves a
 * tc_action_ops via tcf_action_lookup_ops and reaches the per-act
 * init_module / late-binding init instead of bouncing on the
 * request_module / -ENOENT path inside tcf_action_init_1.
 */
static const char * const tc_act_kinds[] = {
	"gact", "mirred", "nat", "pedit", "skbedit", "vlan", "bpf",
	"connmark", "skbmod", "csum", "tunnel_key", "simple", "ife",
	"sample", "ct", "police", "mpls", "ctinfo",
};

/*
 * Build a single nested per-action container, written at p+offset and
 * sized within cap.  Lays down a leading TCA_ACT_KIND string sub-attr
 * (required; tcf_action_init_1 -EINVALs the action when missing) then
 * 0-3 random siblings drawn from the inner TCA_ACT_* set sized to the
 * widths the kernel's tca_act_policy walker expects (NLA_BITFIELD32
 * for FLAGS / HW_STATS, NLA_U32 for INDEX / USED_HW_STATS /
 * IN_HW_COUNT, NLA_NESTED for OPTIONS / STATS).  Returns the inner
 * payload length (excluding the outer per-action header, which the
 * caller writes); 0 on no-room.
 */
static size_t build_tca_act_nested(unsigned char *p, size_t avail)
{
	const char *kind;
	size_t klen;
	size_t off = 0;
	size_t cap;
	int children;

	cap = avail;
	if (cap > 192)
		cap = 192;

	kind = tc_act_kinds[rnd_modulo_u32(ARRAY_SIZE(tc_act_kinds))];
	klen = strlen(kind) + 1;
	if (off + NLA_ALIGN(NLA_HDRLEN + klen) > cap)
		return 0;
	if (!start_nlattr(p, off, cap, TCA_ACT_KIND, klen))
		return 0;
	memcpy(p + off + NLA_HDRLEN, kind, klen);
	off += NLA_ALIGN(NLA_HDRLEN + klen);

	children = RAND_RANGE(0, 3);
	while (children-- > 0) {
		unsigned short atype;
		size_t plen;
		size_t total;
		unsigned char *payload;

		switch (rnd_modulo_u32(6)) {
		case 0:
			atype = TCA_ACT_INDEX;
			plen = sizeof(__u32);
			break;
		case 1:
			atype = TCA_ACT_IN_HW_COUNT;
			plen = sizeof(__u32);
			break;
		case 2:
			atype = TCA_ACT_FLAGS;
			plen = sizeof(struct nla_bitfield32);
			break;
		case 3:
			atype = TCA_ACT_HW_STATS;
			plen = sizeof(struct nla_bitfield32);
			break;
		case 4:
			atype = TCA_ACT_USED_HW_STATS;
			plen = sizeof(struct nla_bitfield32);
			break;
		default:
			/* TCA_ACT_OPTIONS / TCA_ACT_STATS are per-act nested
			 * containers — the sub-attr namespaces are
			 * tc_action_ops::policy and TCA_STATS_* and differ per
			 * kind.  Random siblings here keep the inner walker
			 * exercised without the per-kind table the policy
			 * would need to validate cleanly. */
			atype = RAND_BOOL() ? TCA_ACT_OPTIONS : TCA_ACT_STATS;
			plen = RAND_RANGE(4, 16);
			break;
		}

		total = NLA_ALIGN(NLA_HDRLEN + plen);
		if (off + total > cap)
			break;
		if (!start_nlattr(p, off, cap, atype, plen))
			break;
		payload = p + off + NLA_HDRLEN;
		if (atype == TCA_ACT_FLAGS) {
			struct nla_bitfield32 bf;

			bf.selector = TCA_ACT_FLAGS_NO_PERCPU_STATS |
				      TCA_ACT_FLAGS_SKIP_HW |
				      TCA_ACT_FLAGS_SKIP_SW;
			bf.value = rnd_u32() & bf.selector;
			memcpy(payload, &bf, sizeof(bf));
		} else if (atype == TCA_ACT_HW_STATS ||
			   atype == TCA_ACT_USED_HW_STATS) {
			struct nla_bitfield32 bf;

			bf.selector = TCA_ACT_HW_STATS_IMMEDIATE |
				      TCA_ACT_HW_STATS_DELAYED;
			bf.value = rnd_u32() & bf.selector;
			memcpy(payload, &bf, sizeof(bf));
		} else if (plen == sizeof(__u32)) {
			__u32 val = rnd_modulo_u32(64);

			memcpy(payload, &val, sizeof(val));
		} else {
			generate_rand_bytes(payload, plen);
		}
		off += total;
	}

	return off;
}

/*
 * Build the TCA_ROOT_TAB nested payload: 1-3 per-action containers,
 * each at nla_type = action-index in [1, TCA_ACT_MAX_PRIO-1] (the
 * kernel's tcf_action_init walker iterates tb[1..TCA_ACT_MAX_PRIO]
 * and -EINVALs on index 0 / >= TCA_ACT_MAX_PRIO).  Each inner
 * container is the typed TCA_ACT_* chain build_tca_act_nested lays
 * down.  Indices are assigned sequentially starting at a small base
 * so the kernel walker sees a contiguous run from tb[base] onward.
 * The outer TCA_ROOT_TAB header is written by append_nlattr.
 */
static size_t build_tca_root_tab_nested(unsigned char *p, size_t avail)
{
	size_t off = 0;
	size_t cap;
	int n_actions;
	int act_idx;

	if (avail < 2 * NLA_HDRLEN + 4)
		return 0;

	cap = avail;
	if (cap > 384)
		cap = 384;

	n_actions = RAND_RANGE(1, 3);
	act_idx = 1;

	while (n_actions-- > 0 && act_idx < TCA_ACT_MAX_PRIO) {
		struct nlattr act;
		size_t inner_avail;
		size_t inner_off;

		if (off + NLA_HDRLEN + NLA_HDRLEN > cap)
			break;

		inner_avail = cap - off - NLA_HDRLEN;
		inner_off = build_tca_act_nested(p + off + NLA_HDRLEN,
						 inner_avail);
		if (inner_off == 0)
			break;

		act.nla_len = NLA_HDRLEN + inner_off;
		act.nla_type = act_idx | NLA_F_NESTED;
		memcpy(p + off, &act, NLA_HDRLEN);
		off += NLA_ALIGN(NLA_HDRLEN + inner_off);
		act_idx++;
	}

	return off;
}

/*
 * Generate a structured payload for tc-action rtnetlink attributes
 * (TCA_ROOT_*).  Covers the RTM_*ACTION message group (8).  The kernel
 * net/sched/act_api.c:tca_action_gd walker parses tcaa_policy and
 * length-rejects TCA_ROOT_FLAGS (NLA_BITFIELD32), TCA_ROOT_COUNT
 * (NLA_U32) and TCA_ROOT_TIME_DELTA (NLA_U32) at the wrong-width gate;
 * TCA_ROOT_TAB (== TCA_ACT_TAB) is the NLA_NESTED container the per-
 * action parser walks via tcf_action_init -> tcf_action_init_1, and
 * the parse short-circuits at -EINVAL when the leading TCA_ACT_KIND
 * sub-attr is missing or doesn't resolve to a registered
 * tc_action_ops.  Size each TCA_ROOT_* to its policy width and build
 * TCA_ROOT_TAB as a typed per-action chain so the inner per-kind
 * init runs instead of bouncing at the outer parse.
 *
 * TCA_ROOT_TAB aliases TCA_ROOT_FLAGS=2 / TCA_ROOT_COUNT=3 /
 * TCA_ROOT_TIME_DELTA=4 with the inner TCA_ACT_KIND=1 /
 * TCA_ACT_OPTIONS=2 / TCA_ACT_INDEX=3 / TCA_ACT_STATS=4 values, so
 * those inner attrs aren't emitted at the top level here -- they
 * appear inside the build_tca_act_nested chain.
 */
size_t gen_rta_action_payload(unsigned char *p, size_t avail,
			      unsigned short nla_type)
{
	switch (nla_type) {
	case TCA_ROOT_TAB:
		if (avail >= 2 * NLA_HDRLEN + 4)
			return build_tca_root_tab_nested(p, avail);
		return 0;

	case TCA_ROOT_FLAGS:
		/* NLA_BITFIELD32 over the tcaa_root_flags_policy bits
		 * (TCA_FLAG_LARGE_DUMP_ON / TCA_ACT_FLAG_TERSE_DUMP). */
		if (avail >= sizeof(struct nla_bitfield32)) {
			struct nla_bitfield32 bf;

			bf.selector = TCA_FLAG_LARGE_DUMP_ON |
				      TCA_ACT_FLAG_TERSE_DUMP;
			bf.value = rnd_u32() & bf.selector;
			memcpy(p, &bf, sizeof(bf));
			return sizeof(bf);
		}
		return 0;

	case TCA_ROOT_COUNT:
	case TCA_ROOT_TIME_DELTA:
		if (avail >= 4) {
			__u32 val = rnd_modulo_u32(64);

			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case TCA_ROOT_EXT_WARN_MSG: {
		static const char * const msgs[] = {
			"act-warn", "kind-mismatch", "bad-attr",
		};
		const char *msg = msgs[rnd_modulo_u32(ARRAY_SIZE(msgs))];
		size_t slen = strlen(msg) + 1;

		if (avail >= slen) {
			memcpy(p, msg, slen);
			return slen;
		}
		return 0;
	}

	default:
		return 0;
	}
}

