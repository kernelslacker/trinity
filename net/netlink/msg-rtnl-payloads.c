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
 * gen_rta_* siblings) to keep the rtnl_neightbl wire-up confined to
 * the two TUs that actually need it. */
size_t gen_rta_neightbl_payload(unsigned char *p, size_t avail,
				unsigned short nla_type);

/* Same shape as gen_rta_neightbl_payload above: prototype kept here
 * rather than in msg-internal.h to confine the rtnl_addrlabel
 * wire-up to the two TUs that actually need it. */
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

/* Same shape as gen_rta_neightbl_payload above: prototype kept here
 * rather than in msg-internal.h to confine the rtnl_tunnel
 * wire-up to the two TUs that actually need it. */
size_t gen_rta_tunnel_payload(unsigned char *p, size_t avail,
			      unsigned short nla_type);

/* Same shape as gen_rta_neightbl_payload above: prototype kept here
 * rather than in msg-internal.h to confine the rtnl_linkprop
 * wire-up to the two TUs that actually need it. */
size_t gen_rta_linkprop_payload(unsigned char *p, size_t avail,
				unsigned short nla_type);

static size_t gen_link_ifname(unsigned char *p, size_t avail)
{
	static const char *names[] = {
		"eth0", "lo", "br0", "bond0", "veth0",
		"dummy0", "wlan0", "tun0",
	};
	const char *name = RAND_ARRAY(names);
	size_t slen = strlen(name) + 1;

	if (avail >= slen) {
		memcpy(p, name, slen);
		return slen;
	}
	return 0;
}

static size_t gen_link_alt_ifname(unsigned char *p, size_t avail)
{
	static const char *alts[] = { "altname0", "renamed1" };
	const char *name = RAND_ARRAY(alts);
	size_t slen = strlen(name) + 1;

	if (avail >= slen) {
		memcpy(p, name, slen);
		return slen;
	}
	return 0;
}

#ifndef RTEXT_FILTER_NAME_ONLY
#define RTEXT_FILTER_NAME_ONLY (1 << 8)
#endif
static size_t gen_link_ext_mask(unsigned char *p, size_t avail)
{
	if (avail >= 4) {
		static const unsigned long rtext_filter_bits[] = {
			RTEXT_FILTER_VF,
			RTEXT_FILTER_BRVLAN,
			RTEXT_FILTER_BRVLAN_COMPRESSED,
			RTEXT_FILTER_SKIP_STATS,
			RTEXT_FILTER_MRP,
			RTEXT_FILTER_CFM_CONFIG,
			RTEXT_FILTER_CFM_STATUS,
			RTEXT_FILTER_MST,
			RTEXT_FILTER_NAME_ONLY,
		};
		__u32 val = (__u32) set_rand_bitmask(
			sizeof(rtext_filter_bits) / sizeof(rtext_filter_bits[0]),
			rtext_filter_bits);
		memcpy(p, &val, 4);
		return 4;
	}
	return 0;
}

static size_t gen_link_linkinfo(unsigned char *p, size_t avail)
{
	/* Nested: IFLA_INFO_KIND (string) + optional IFLA_INFO_DATA */
	if (avail >= NLA_HDRLEN + 8) {
		size_t nested_len = 0;
		const char *kind = link_kinds[rnd_modulo_u32(link_kinds_n)];
		size_t kind_len = strlen(kind) + 1;
		size_t kind_total = NLA_ALIGN(NLA_HDRLEN + kind_len);

		/* IFLA_INFO_KIND */
		if (nested_len + kind_total <= avail) {
			if (start_nlattr(p, nested_len, avail,
					 IFLA_INFO_KIND, kind_len)) {
				memcpy(p + nested_len + NLA_HDRLEN,
				       kind, kind_len);
				nested_len += kind_total;
			}
		}

		/* Sometimes add IFLA_INFO_DATA with random nested attrs */
		if (RAND_BOOL() && nested_len + NLA_HDRLEN + 8 <= avail) {
			size_t data_avail = avail - nested_len - NLA_HDRLEN;
			size_t data_len;
			unsigned char sub[128];

			if (data_avail > sizeof(sub))
				data_avail = sizeof(sub);
			data_len = RAND_RANGE((size_t)4, data_avail);
			generate_rand_bytes(sub, data_len);

			if (start_nlattr(p, nested_len, avail,
					 IFLA_INFO_DATA | NLA_F_NESTED,
					 data_len)) {
				memcpy(p + nested_len + NLA_HDRLEN,
				       sub, data_len);
				nested_len += NLA_ALIGN(NLA_HDRLEN + data_len);
			}
		}

		return nested_len;
	}
	return 0;
}

static size_t gen_link_af_spec(unsigned char *p, size_t avail)
{
	/* Nested: per-address-family containers */
	size_t nested_len = 0;
	int i, count = RAND_RANGE(1, 3);
	static const unsigned char af_types[] = {
		AF_INET, AF_INET6, AF_BRIDGE,
	};

	for (i = 0; i < count && nested_len + NLA_HDRLEN + 8 <= avail; i++) {
		unsigned char af = RAND_ARRAY(af_types);
		size_t inner_avail = avail - nested_len - NLA_HDRLEN;
		size_t inner_len;
		unsigned char inner[64];

		if (inner_avail > sizeof(inner))
			inner_avail = sizeof(inner);
		inner_len = RAND_RANGE((size_t)4, inner_avail);
		generate_rand_bytes(inner, inner_len);

		if (start_nlattr(p, nested_len, avail,
				 af | NLA_F_NESTED, inner_len)) {
			memcpy(p + nested_len + NLA_HDRLEN,
			       inner, inner_len);
			nested_len += NLA_ALIGN(NLA_HDRLEN + inner_len);
		}
	}
	return nested_len;
}

/*
 * Generate a structured payload for link attributes (IFLA_*).
 */
size_t gen_rta_link_payload(unsigned char *p, size_t avail,
			    unsigned short nla_type)
{
	switch (nla_type) {
	case IFLA_IFNAME:
	case IFLA_QDISC:
	case IFLA_IFALIAS:
		return gen_link_ifname(p, avail);

	case IFLA_ALT_IFNAME:
		return gen_link_alt_ifname(p, avail);

	case IFLA_MTU:
	case IFLA_MIN_MTU:
	case IFLA_MAX_MTU:
		if (avail >= 4) {
			__u32 val = RAND_RANGE(68, 65535);
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case IFLA_TXQLEN:
		if (avail >= 4) {
			__u32 val = RAND_RANGE(0, 10000);
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case IFLA_GROUP:
	case IFLA_PROMISCUITY:
	case IFLA_NUM_TX_QUEUES:
	case IFLA_NUM_RX_QUEUES:
	case IFLA_NUM_VF:
	case IFLA_GSO_MAX_SEGS:
	case IFLA_GSO_MAX_SIZE:
	case IFLA_NEW_IFINDEX:
	case IFLA_LINK:
	case IFLA_MASTER:
	case IFLA_LINK_NETNSID:
	case IFLA_NET_NS_PID:
	case IFLA_NET_NS_FD:
		if (avail >= 4) {
			__u32 val = rnd_modulo_u32(64);
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case IFLA_EXT_MASK:
		return gen_link_ext_mask(p, avail);

	case IFLA_ADDRESS:
	case IFLA_BROADCAST:
	case IFLA_PERM_ADDRESS:
		/* MAC address: 6 bytes */
		if (avail >= 6) {
			generate_rand_bytes(p, 6);
			return 6;
		}
		return 0;

	case IFLA_OPERSTATE:
	case IFLA_LINKMODE:
	case IFLA_CARRIER:
	case IFLA_PROTO_DOWN:
		if (avail >= 1) {
			*p = rnd_modulo_u32(8);
			return 1;
		}
		return 0;

	case IFLA_WEIGHT:
	case IFLA_COST:
	case IFLA_PRIORITY:
		if (avail >= 4) {
			__u32 val = rand32();
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case IFLA_LINKINFO:
		return gen_link_linkinfo(p, avail);

	case IFLA_AF_SPEC:
		return gen_link_af_spec(p, avail);

	default:
		return 0;
	}
}

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
 * Generate a structured payload for neighbor attributes (NDA_*).
 */
size_t gen_rta_neigh_payload(unsigned char *p, size_t avail,
			     unsigned short nla_type, unsigned char family)
{
	switch (nla_type) {
	case NDA_DST:
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

	case NDA_LLADDR:
		/* Link-layer address (MAC): 6 bytes */
		if (avail >= 6) {
			generate_rand_bytes(p, 6);
			return 6;
		}
		return 0;

	case NDA_CACHEINFO:
		if (avail >= sizeof(struct nda_cacheinfo)) {
			struct nda_cacheinfo ci;
			ci.ndm_confirmed = rand32();
			ci.ndm_used = rand32();
			ci.ndm_updated = rand32();
			ci.ndm_refcnt = rand32();
			memcpy(p, &ci, sizeof(ci));
			return sizeof(ci);
		}
		return 0;

	case NDA_PROBES:
	case NDA_IFINDEX:
	case NDA_MASTER:
	case NDA_LINK_NETNSID:
	case NDA_SRC_VNI:
	case NDA_VNI:
	case NDA_NH_ID:
	case NDA_FLAGS_EXT:
	case NDA_NDM_STATE_MASK:
	case NDA_NDM_FLAGS_MASK:
		if (avail >= 4) {
			__u32 val = rand32();
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case NDA_VLAN:
	case NDA_PORT:
		if (avail >= 2) {
			unsigned short val = rand16();
			memcpy(p, &val, 2);
			return 2;
		}
		return 0;

	case NDA_PROTOCOL:
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
 * Populate a struct br_mdb_entry that survives the kernel's
 * rtnl_validate_mdb_entry gate: a non-zero ifindex, MDB_TEMPORARY /
 * MDB_PERMANENT state, a vid below VLAN_VID_MASK (0xfff), and a group
 * address consistent with addr.proto -- a global IPv4 multicast that is
 * not link-local (224.0.0.0/24), an IPv6 site-local multicast that is
 * not the all-nodes group, or an L2 multicast MAC (group bit set on the
 * first octet).
 */
static void fill_mdb_entry(struct br_mdb_entry *e)
{
	memset(e, 0, sizeof(*e));
	e->ifindex = 1 + rnd_modulo_u32(63);
	e->state = RAND_BOOL() ? MDB_PERMANENT : MDB_TEMPORARY;
	e->vid = RAND_BOOL() ? 0 : rnd_modulo_u32(0xfff);

	switch (rnd_modulo_u32(3)) {
	case 0:
		e->addr.proto = htons(ETH_P_IP);
		e->addr.u.ip4 = htonl(0xe1000000 |
				      (rnd_u32() & 0x00ffffff));
		break;
	case 1:
		e->addr.proto = htons(ETH_P_IPV6);
		e->addr.u.ip6.s6_addr[0] = 0xff;
		e->addr.u.ip6.s6_addr[1] = 0x05;
		e->addr.u.ip6.s6_addr[15] = 1 + rnd_modulo_u32(254);
		break;
	default:
		e->addr.proto = 0;
		generate_rand_bytes(e->addr.u.mac_addr, ETH_ALEN);
		e->addr.u.mac_addr[0] |= 0x01;
		break;
	}
}

/*
 * Build the MDBA_MDB dump-reply payload: MDBA_MDB_ENTRY ->
 * MDBA_MDB_ENTRY_INFO carrying a raw struct br_mdb_entry (the kernel
 * emits it with nla_put_nohdr so no inner nlattr header wraps it)
 * followed by random-payload MDBA_MDB_EATTR_* siblings.  The two outer
 * MDBA_MDB_ENTRY / MDBA_MDB_ENTRY_INFO headers are laid down here; the
 * caller writes the outer MDBA_MDB header in append_nlattr.
 */
static size_t build_mdba_mdb_nested(unsigned char *p, size_t avail)
{
	static const unsigned short eattrs[] = {
		MDBA_MDB_EATTR_TIMER,    MDBA_MDB_EATTR_GROUP_MODE,
		MDBA_MDB_EATTR_RTPROT,   MDBA_MDB_EATTR_SOURCE,
		MDBA_MDB_EATTR_VNI,      MDBA_MDB_EATTR_SRC_VNI,
		MDBA_MDB_EATTR_IFINDEX,  MDBA_MDB_EATTR_DST_PORT,
	};
	struct br_mdb_entry entry;
	struct nlattr mid, info;
	unsigned char *info_payload;
	size_t info_off;
	size_t info_cap;
	size_t mid_payload;

	if (avail < 2 * NLA_HDRLEN + sizeof(entry))
		return 0;

	info_payload = p + 2 * NLA_HDRLEN;
	info_cap = avail - 2 * NLA_HDRLEN;
	if (info_cap > 192)
		info_cap = 192;

	fill_mdb_entry(&entry);
	memcpy(info_payload, &entry, sizeof(entry));
	info_off = NLA_ALIGN(sizeof(entry));

	if (info_off < info_cap)
		info_off += build_nested_attrs(info_payload + info_off,
					       info_cap - info_off,
					       eattrs, ARRAY_SIZE(eattrs), 0);

	info.nla_len = NLA_HDRLEN + info_off;
	info.nla_type = MDBA_MDB_ENTRY_INFO | NLA_F_NESTED;
	memcpy(p + NLA_HDRLEN, &info, NLA_HDRLEN);

	mid_payload = NLA_ALIGN(NLA_HDRLEN + info_off);
	mid.nla_len = NLA_HDRLEN + mid_payload;
	mid.nla_type = MDBA_MDB_ENTRY | NLA_F_NESTED;
	memcpy(p, &mid, NLA_HDRLEN);

	return NLA_HDRLEN + mid_payload;
}

/*
 * Build the MDBA_ROUTER dump-reply payload: one MDBA_ROUTER_PORT
 * container that begins with a header-less u32 ifindex (the kernel
 * emits it via nla_put_nohdr) and continues with random-payload
 * MDBA_ROUTER_PATTR_* siblings.  The outer MDBA_ROUTER header is
 * written by append_nlattr.
 */
static size_t build_mdba_router_nested(unsigned char *p, size_t avail)
{
	static const unsigned short pattrs[] = {
		MDBA_ROUTER_PATTR_TIMER, MDBA_ROUTER_PATTR_TYPE,
		MDBA_ROUTER_PATTR_INET_TIMER,
		MDBA_ROUTER_PATTR_INET6_TIMER,
		MDBA_ROUTER_PATTR_VID,
	};
	struct nlattr port;
	unsigned char *port_payload;
	size_t port_off = 0;
	size_t port_cap;
	__u32 ifindex;

	if (avail < NLA_HDRLEN + sizeof(__u32))
		return 0;

	port_payload = p + NLA_HDRLEN;
	port_cap = avail - NLA_HDRLEN;
	if (port_cap > 128)
		port_cap = 128;

	ifindex = 1 + rnd_modulo_u32(63);
	memcpy(port_payload, &ifindex, sizeof(ifindex));
	port_off = NLA_ALIGN(sizeof(ifindex));

	if (port_off < port_cap)
		port_off += build_nested_attrs(port_payload + port_off,
					       port_cap - port_off,
					       pattrs, ARRAY_SIZE(pattrs), 0);

	port.nla_len = NLA_HDRLEN + port_off;
	port.nla_type = MDBA_ROUTER_PORT | NLA_F_NESTED;
	memcpy(p, &port, NLA_HDRLEN);

	return NLA_ALIGN(NLA_HDRLEN + port_off);
}

/*
 * Generate a structured payload for bridge multicast database
 * rtnetlink attributes.  Covers the RTM_*MDB message group (17).
 *
 * The MDBA_* and MDBA_SET_ENTRY_* / MDBA_GET_ENTRY_* enums alias each
 * other on the wire: MDBA_MDB shares value 1 with MDBA_SET_ENTRY /
 * MDBA_GET_ENTRY, and MDBA_ROUTER shares value 2 with
 * MDBA_SET_ENTRY_ATTRS / MDBA_GET_ENTRY_ATTRS.  The kernel parses the
 * request-side meaning (MDBA_SET_ENTRY = NLA_BINARY of struct
 * br_mdb_entry, MDBA_SET_ENTRY_ATTRS = NLA_NESTED of MDBE_ATTR_*) via
 * rtnl_validate_mdb_entry and br_mdbe_attrs_pol; the MDBA_MDB /
 * MDBA_ROUTER nested layout is the dump-reply shape userspace receives
 * from br_mdb_fill_info.  Bias toward the request-side shapes since
 * those reach an actual handler, but occasionally emit the reply-side
 * nested layout so nla_parse walks well-formed nested TLVs that no
 * random-byte fallback would ever assemble.
 */
size_t gen_rta_mdba_payload(unsigned char *p, size_t avail,
			    unsigned short nla_type)
{
	switch (nla_type) {
	case MDBA_MDB:	/* aliases MDBA_SET_ENTRY / MDBA_GET_ENTRY (= 1) */
		if (ONE_IN(4))
			return build_mdba_mdb_nested(p, avail);
		if (avail >= sizeof(struct br_mdb_entry)) {
			struct br_mdb_entry entry;

			fill_mdb_entry(&entry);
			memcpy(p, &entry, sizeof(entry));
			return sizeof(entry);
		}
		return 0;

	case MDBA_ROUTER: /* aliases MDBA_SET_ENTRY_ATTRS / MDBA_GET_ENTRY_ATTRS (= 2) */
		if (ONE_IN(4))
			return build_mdba_router_nested(p, avail);
		/* MDBE_ATTR_* chain that satisfies br_mdbe_attrs_pol --
		 * random sub-attr payloads, valid type bytes; the per-attr
		 * NLA_BINARY / NLA_U8 / NLA_NESTED policies will still
		 * length-reject some sub-attrs, but the parse reaches the
		 * inner walker instead of bouncing on the outer nlattr. */
		if (avail >= NLA_HDRLEN + 4) {
			static const unsigned short mdbe_attrs[] = {
				MDBE_ATTR_SOURCE,    MDBE_ATTR_SRC_LIST,
				MDBE_ATTR_GROUP_MODE, MDBE_ATTR_RTPROT,
				MDBE_ATTR_DST,       MDBE_ATTR_DST_PORT,
				MDBE_ATTR_VNI,       MDBE_ATTR_IFINDEX,
				MDBE_ATTR_SRC_VNI,   MDBE_ATTR_STATE_MASK,
			};
			return build_nested_attrs(p, avail, mdbe_attrs,
						  ARRAY_SIZE(mdbe_attrs), 0);
		}
		return 0;

	default:
		return 0;
	}
}

/*
 * Fill a struct bridge_vlan_info with a vid in [1, VLAN_VID_MASK-1]
 * (vid 0 and vid 4095 are rejected by br_validate_vlan_id) and a flags
 * field drawn from the curated BRIDGE_VLAN_INFO_* bits the kernel
 * br_vlan_process_one_opts / br_vlan_rtm_process_one walkers act on.
 * Keeping the vid and flags inside the valid envelope lets the parse
 * fall through to nbp_vlan_add / br_vlan_add instead of bouncing at
 * the per-field gate.
 */
static void fill_bridge_vlan_info(struct bridge_vlan_info *info)
{
	static const __u16 valid_flags =
		BRIDGE_VLAN_INFO_MASTER | BRIDGE_VLAN_INFO_PVID |
		BRIDGE_VLAN_INFO_UNTAGGED |
		BRIDGE_VLAN_INFO_RANGE_BEGIN |
		BRIDGE_VLAN_INFO_RANGE_END |
		BRIDGE_VLAN_INFO_BRENTRY |
		BRIDGE_VLAN_INFO_ONLY_OPTS;

	info->flags = rnd_u32() & valid_flags;
	info->vid = 1 + rnd_modulo_u32(4094);
}

/*
 * Build the BRIDGE_VLANDB_ENTRY container: a leading
 * BRIDGE_VLANDB_ENTRY_INFO sub-attr (NLA_EXACT_LEN of struct
 * bridge_vlan_info -- the kernel's br_vlan_db_dump_policy /
 * br_vlandb_entry_policy length-reject any other size) followed by
 * random-payload BRIDGE_VLANDB_ENTRY_* siblings (RANGE / STATE /
 * TUNNEL_INFO / STATS / MCAST_ROUTER / MCAST_N_GROUPS /
 * MCAST_MAX_GROUPS / NEIGH_SUPPRESS).  The outer BRIDGE_VLANDB_ENTRY
 * header is written by append_nlattr.
 */
static size_t build_vlandb_entry_nested(unsigned char *p, size_t avail)
{
	static const unsigned short entry_attrs[] = {
		BRIDGE_VLANDB_ENTRY_RANGE,
		BRIDGE_VLANDB_ENTRY_STATE,
		BRIDGE_VLANDB_ENTRY_TUNNEL_INFO,
		BRIDGE_VLANDB_ENTRY_STATS,
		BRIDGE_VLANDB_ENTRY_MCAST_ROUTER,
		BRIDGE_VLANDB_ENTRY_MCAST_N_GROUPS,
		BRIDGE_VLANDB_ENTRY_MCAST_MAX_GROUPS,
		BRIDGE_VLANDB_ENTRY_NEIGH_SUPPRESS,
	};
	struct bridge_vlan_info info;
	size_t off = 0;
	size_t cap;

	if (avail < NLA_HDRLEN + sizeof(info))
		return 0;

	cap = avail;
	if (cap > 192)
		cap = 192;

	if (!start_nlattr(p, off, cap, BRIDGE_VLANDB_ENTRY_INFO,
			  sizeof(info)))
		return 0;
	fill_bridge_vlan_info(&info);
	memcpy(p + off + NLA_HDRLEN, &info, sizeof(info));
	off += NLA_ALIGN(NLA_HDRLEN + sizeof(info));

	if (off < cap)
		off += build_nested_attrs(p + off, cap - off,
					  entry_attrs,
					  ARRAY_SIZE(entry_attrs), 0);

	return off;
}

/*
 * Build the BRIDGE_VLANDB_GLOBAL_OPTIONS container: a leading
 * BRIDGE_VLANDB_GOPTS_ID sub-attr (NLA_U16 vid in the valid envelope)
 * followed by random-payload BRIDGE_VLANDB_GOPTS_* siblings (RANGE /
 * MCAST_SNOOPING / MCAST_IGMP_VERSION / ... / MSTI).  The outer
 * BRIDGE_VLANDB_GLOBAL_OPTIONS header is written by append_nlattr.
 */
static size_t build_vlandb_gopts_nested(unsigned char *p, size_t avail)
{
	static const unsigned short gopts_attrs[] = {
		BRIDGE_VLANDB_GOPTS_RANGE,
		BRIDGE_VLANDB_GOPTS_MCAST_SNOOPING,
		BRIDGE_VLANDB_GOPTS_MCAST_IGMP_VERSION,
		BRIDGE_VLANDB_GOPTS_MCAST_MLD_VERSION,
		BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_CNT,
		BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_CNT,
		BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_INTVL,
		BRIDGE_VLANDB_GOPTS_MCAST_MEMBERSHIP_INTVL,
		BRIDGE_VLANDB_GOPTS_MCAST_QUERIER_INTVL,
		BRIDGE_VLANDB_GOPTS_MCAST_QUERY_INTVL,
		BRIDGE_VLANDB_GOPTS_MCAST_QUERY_RESPONSE_INTVL,
		BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_INTVL,
		BRIDGE_VLANDB_GOPTS_MCAST_QUERIER,
		BRIDGE_VLANDB_GOPTS_MCAST_ROUTER_PORTS,
		BRIDGE_VLANDB_GOPTS_MSTI,
	};
	__u16 vid;
	size_t off = 0;
	size_t cap;

	if (avail < NLA_HDRLEN + sizeof(vid))
		return 0;

	cap = avail;
	if (cap > 192)
		cap = 192;

	if (!start_nlattr(p, off, cap, BRIDGE_VLANDB_GOPTS_ID, sizeof(vid)))
		return 0;
	vid = 1 + rnd_modulo_u32(4094);
	memcpy(p + off + NLA_HDRLEN, &vid, sizeof(vid));
	off += NLA_ALIGN(NLA_HDRLEN + sizeof(vid));

	if (off < cap)
		off += build_nested_attrs(p + off, cap - off,
					  gopts_attrs,
					  ARRAY_SIZE(gopts_attrs), 0);

	return off;
}

/*
 * Generate a structured payload for bridge VLAN database rtnetlink
 * attributes.  Covers the RTM_*VLAN message group (18).
 *
 * Both top-level attrs are NLA_NESTED containers in br_vlan_db_policy:
 *   BRIDGE_VLANDB_ENTRY            -> BRIDGE_VLANDB_ENTRY_*
 *   BRIDGE_VLANDB_GLOBAL_OPTIONS   -> BRIDGE_VLANDB_GOPTS_*
 * In each case the kernel parser requires a typed leading sub-attr
 * (BRIDGE_VLANDB_ENTRY_INFO carrying struct bridge_vlan_info, or
 * BRIDGE_VLANDB_GOPTS_ID carrying a u16 vid) and length-rejects the
 * container at nla_parse_nested if it can't find a valid one.  Random
 * outer bytes never satisfy either, so the message bounces before
 * br_vlan_rtm_process / br_vlan_rtm_process_global_options ever runs.
 * Lay down the typed leading sub-attr in the valid envelope, then
 * append random-payload typed siblings so the inner per-attr walker
 * reaches its own policy table instead of failing at the outer parse.
 */
size_t gen_rta_vlandb_payload(unsigned char *p, size_t avail,
			      unsigned short nla_type)
{
	switch (nla_type) {
	case BRIDGE_VLANDB_ENTRY:
		return build_vlandb_entry_nested(p, avail);
	case BRIDGE_VLANDB_GLOBAL_OPTIONS:
		return build_vlandb_gopts_nested(p, avail);
	default:
		return 0;
	}
}

/*
 * NDTPA_* u32 sub-attrs: lookup_neigh_parms + NEIGH_VAR_SET arms in
 * net/core/neighbour.c:neightbl_set() length-check each one at
 * sizeof(u32) via nl_ntbl_parm_policy, so sizing them at 4 bytes lets
 * the inner per-attr walker reach the actual writer instead of bouncing
 * at nla_validate.
 */
static const unsigned short ndtpa_u32_attrs[] = {
	NDTPA_QUEUE_LEN, NDTPA_QUEUE_LENBYTES, NDTPA_PROXY_QLEN,
	NDTPA_APP_PROBES, NDTPA_UCAST_PROBES, NDTPA_MCAST_PROBES,
	NDTPA_MCAST_REPROBES,
};

/*
 * NDTPA_* u64 sub-attrs: msec-valued timers the policy declares as
 * NLA_U64 (BASE_REACHABLE_TIME / GC_STALETIME / DELAY_PROBE_TIME /
 * RETRANS_TIME / ANYCAST_DELAY / PROXY_DELAY / LOCKTIME /
 * INTERVAL_PROBE_TIME_MS).  Random-byte payloads at the wrong width
 * length-reject at nla_validate; emit them at 8 bytes so the inner
 * NEIGH_VAR_SET arm runs.  INTERVAL_PROBE_TIME_MS additionally has a
 * .min = 1 policy gate; the random u64 payload trips that exactly 1
 * in 2^64 of the time, which is fine — the other timers don't have
 * that gate and exercise the writer regardless.
 */
static const unsigned short ndtpa_u64_attrs[] = {
	NDTPA_BASE_REACHABLE_TIME, NDTPA_GC_STALETIME,
	NDTPA_DELAY_PROBE_TIME, NDTPA_RETRANS_TIME,
	NDTPA_ANYCAST_DELAY, NDTPA_PROXY_DELAY, NDTPA_LOCKTIME,
	NDTPA_INTERVAL_PROBE_TIME_MS,
};

/*
 * Build the NDTA_PARMS nested payload: a leading NDTPA_IFINDEX u32
 * (ifindex == 0 selects the per-table base neigh_parms slot, anything
 * else needs lookup_neigh_parms to match a per-device slot — bias
 * toward 0 plus small ifindices so the lookup actually resolves)
 * followed by 1-4 NDTPA_* u32/u64 siblings sized to the policy widths.
 * The outer NDTA_PARMS header is written by append_nlattr.
 */
static size_t build_ndta_parms_nested(unsigned char *p, size_t avail)
{
	__u32 ifindex;
	size_t off = 0;
	size_t cap;
	int children;

	if (avail < NLA_HDRLEN + sizeof(ifindex))
		return 0;

	cap = avail;
	if (cap > 192)
		cap = 192;

	if (!start_nlattr(p, off, cap, NDTPA_IFINDEX, sizeof(ifindex)))
		return 0;
	ifindex = ONE_IN(2) ? 0 : rnd_modulo_u32(64);
	memcpy(p + off + NLA_HDRLEN, &ifindex, sizeof(ifindex));
	off += NLA_ALIGN(NLA_HDRLEN + sizeof(ifindex));

	children = RAND_RANGE(1, 4);
	while (children-- > 0) {
		unsigned short atype;
		size_t plen;
		size_t total;

		if (RAND_BOOL()) {
			atype = ndtpa_u32_attrs[rnd_modulo_u32(ARRAY_SIZE(ndtpa_u32_attrs))];
			plen = sizeof(__u32);
		} else {
			atype = ndtpa_u64_attrs[rnd_modulo_u32(ARRAY_SIZE(ndtpa_u64_attrs))];
			plen = sizeof(__u64);
		}

		total = NLA_ALIGN(NLA_HDRLEN + plen);
		if (off + total > cap)
			break;
		if (!start_nlattr(p, off, cap, atype, plen))
			break;
		generate_rand_bytes(p + off + NLA_HDRLEN, plen);
		off += total;
	}
	return off;
}

/*
 * Generate a structured payload for neighbour-table rtnetlink
 * attributes (NDTA_*).  Covers the RTM_*NEIGHTBL message group (12).
 * The kernel net/core/neighbour.c:neightbl_set() handler walks
 * nl_neightbl_policy and bounces NDTA_NAME (NLA_STRING — and the SET
 * path additionally requires the string to nla_strcmp-equal a
 * registered neigh_table .id, else -ENOENT), NDTA_THRESH[1-3] (u32),
 * NDTA_GC_INTERVAL (u64) and NDTA_PARMS (nested NDTPA_*) on the
 * wrong-width / wrong-shape gate before any of the per-attr writers
 * run.  A random-byte payload of length [0, 64) almost never lands
 * exactly the right width — and almost never matches a registered
 * table name — so the message is rejected at nla_parse before the
 * per-table SET path runs.  Seed NDTA_NAME from the {arp_cache,
 * ndisc_cache} pair the kernel registers (dn_neigh_cache is a
 * historical DECnet name that is harmless to emit — kernel just
 * -ENOENTs it after the parse), size each scalar to its policy
 * width, and build NDTA_PARMS as a typed NDTPA_* chain so the inner
 * lookup_neigh_parms + NEIGH_VAR_SET arms run instead of failing at
 * the outer parse.  NDTA_CONFIG / NDTA_STATS are dump-only (no
 * policy entry; neightbl_set() ignores them), but include sized
 * payloads so the nla walker doesn't bounce on a struct ndt_config /
 * ndt_stats short-read if anyone emits them.
 */
size_t gen_rta_neightbl_payload(unsigned char *p, size_t avail,
				unsigned short nla_type)
{
	switch (nla_type) {
	case NDTA_NAME: {
		/* Registered neigh_table .id strings.  neightbl_set walks
		 * NEIGH_NR_TABLES rcu_dereference(neigh_tables[]) entries
		 * and matches via nla_strcmp; missing the match -ENOENTs
		 * before the per-table writers ever run. */
		static const char * const names[] = {
			"arp_cache", "ndisc_cache", "dn_neigh_cache",
		};
		const char *name = names[rnd_modulo_u32(ARRAY_SIZE(names))];
		size_t slen = strlen(name) + 1;

		if (avail >= slen) {
			memcpy(p, name, slen);
			return slen;
		}
		return 0;
	}

	case NDTA_THRESH1:
	case NDTA_THRESH2:
	case NDTA_THRESH3:
		if (avail >= 4) {
			__u32 val = rnd_modulo_u32(1024);
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case NDTA_GC_INTERVAL:
		if (avail >= 8) {
			__u64 val = rnd_modulo_u32(1 << 16);
			memcpy(p, &val, 8);
			return 8;
		}
		return 0;

	case NDTA_PARMS:
		if (avail >= NLA_HDRLEN + 4)
			return build_ndta_parms_nested(p, avail);
		return 0;

	case NDTA_CONFIG:
		if (avail >= sizeof(struct ndt_config)) {
			struct ndt_config cfg;

			generate_rand_bytes((unsigned char *)&cfg, sizeof(cfg));
			memcpy(p, &cfg, sizeof(cfg));
			return sizeof(cfg);
		}
		return 0;

	case NDTA_STATS:
		if (avail >= sizeof(struct ndt_stats)) {
			struct ndt_stats st;

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

/*
 * Build a single VXLAN_VNIFILTER_ENTRY nested payload, written at p
 * and sized within cap.  Lays down a leading VXLAN_VNIFILTER_ENTRY_START
 * sub-attr (the kernel's vxlan_process_vni_filter -EINVALs an entry
 * whose START and END are both zero, so emit a non-zero VNI in
 * [1, 0xFFFFFF] -- VNIs are 24-bit) then 0-3 optional siblings drawn
 * from the inner VXLAN_VNIFILTER_ENTRY_* set sized to the widths the
 * kernel's vni_filter_entry_policy walker expects: NLA_U32 for END,
 * NLA_BINARY sizeof(struct in_addr) for GROUP, NLA_BINARY
 * sizeof(struct in6_addr) for GROUP6.  Returns the inner payload
 * length (excluding the outer per-entry header, which the caller
 * writes); 0 on no-room.
 */
static size_t build_vxlan_vni_entry_nested(unsigned char *p, size_t avail)
{
	size_t off = 0;
	size_t cap;
	__u32 vni_start;
	int siblings;

	cap = avail;
	if (cap > 96)
		cap = 96;

	if (off + NLA_ALIGN(NLA_HDRLEN + sizeof(__u32)) > cap)
		return 0;
	if (!start_nlattr(p, off, cap,
			  VXLAN_VNIFILTER_ENTRY_START, sizeof(__u32)))
		return 0;
	vni_start = 1 + rnd_modulo_u32(0xFFFFFF);
	memcpy(p + off + NLA_HDRLEN, &vni_start, sizeof(vni_start));
	off += NLA_ALIGN(NLA_HDRLEN + sizeof(__u32));

	siblings = RAND_RANGE(0, 3);
	while (siblings-- > 0) {
		unsigned short atype;
		size_t plen;
		size_t total;
		unsigned char *payload;

		switch (rnd_modulo_u32(3)) {
		case 0:
			atype = VXLAN_VNIFILTER_ENTRY_END;
			plen = sizeof(__u32);
			break;
		case 1:
			atype = VXLAN_VNIFILTER_ENTRY_GROUP;
			plen = sizeof(struct in_addr);
			break;
		default:
			atype = VXLAN_VNIFILTER_ENTRY_GROUP6;
			plen = sizeof(struct in6_addr);
			break;
		}

		total = NLA_ALIGN(NLA_HDRLEN + plen);
		if (off + total > cap)
			break;
		if (!start_nlattr(p, off, cap, atype, plen))
			break;
		payload = p + off + NLA_HDRLEN;
		if (atype == VXLAN_VNIFILTER_ENTRY_END) {
			__u32 span = 0xFFFFFF - vni_start;
			__u32 vni_end;

			/* END must satisfy vni_start <= vni_end <= 0xFFFFFF;
			 * keep the span small so a single message stays a
			 * tractable range install rather than a 24-bit sweep. */
			if (span > 63)
				span = 63;
			vni_end = vni_start + rnd_modulo_u32(span + 1);
			memcpy(payload, &vni_end, sizeof(vni_end));
		} else if (atype == VXLAN_VNIFILTER_ENTRY_GROUP) {
			__u32 v4 = rand_ipv4();

			memcpy(payload, &v4, sizeof(v4));
		} else {
			struct in6_addr v6;

			rand_ipv6(&v6);
			memcpy(payload, &v6, sizeof(v6));
		}
		off += total;
	}

	return off;
}

/*
 * Generate a structured payload for vxlan vni-filter rtnetlink
 * attributes carried in the RTM_*TUNNEL message family (group 26 in
 * the gen_rta_payload switch).  The only kernel-side handler today is
 * drivers/net/vxlan/vxlan_vnifilter.c::vxlan_vnifilter_process,
 * registered for PF_BRIDGE; it walks the message via
 * nlmsg_parse(..., vni_filter_policy, ...) which only declares the
 * NLA_NESTED VXLAN_VNIFILTER_ENTRY top-level attr.  The kernel then
 * iterates nlmsg_for_each_attr_type(VXLAN_VNIFILTER_ENTRY) and for
 * each entry runs nla_parse_nested(..., vni_filter_entry_policy, ...)
 * over { START, END, GROUP, GROUP6 } -- the sub-attrs
 * build_vxlan_vni_entry_nested lays down.  Sizing this here means the
 * inner per-entry parser actually runs instead of bouncing at the
 * outer nlmsg_parse on a random-byte payload.
 *
 * VXLAN_VNIFILTER_ENTRY_STATS has no entry in vni_filter_entry_policy
 * (it is dump-only, written via nla_nest_start in the reply path), so
 * it is not emitted here.
 */
size_t gen_rta_tunnel_payload(unsigned char *p, size_t avail,
			      unsigned short nla_type)
{
	switch (nla_type) {
	case VXLAN_VNIFILTER_ENTRY:
		if (avail >= NLA_HDRLEN + sizeof(__u32))
			return build_vxlan_vni_entry_nested(p, avail);
		return 0;

	default:
		return 0;
	}
}

/*
 * Build the IFLA_PROP_LIST container body: 1-3 IFLA_ALT_IFNAME string
 * sub-attrs.  rtnl_linkprop only walks IFLA_ALT_IFNAME children of the
 * prop list and ignores any other type, so emitting only that type
 * here keeps every sub-attr on a live arm of rtnl_alt_ifname instead
 * of bouncing in the nested walker.  Names are short fixed strings
 * (NUL-terminated) so nla_strscpy / dev_valid_altname run; the kernel
 * will -EEXIST a duplicate add and -ENOENT a missing del, both of
 * which are useful coverage of the altname add/del paths.
 */
static size_t build_linkprop_nested(unsigned char *p, size_t avail)
{
	static const char * const alts[] = {
		"altname0", "altname1", "renamed0", "renamed1", "fuzzname",
	};
	size_t off = 0;
	int count = RAND_RANGE(1, 3);

	while (count-- > 0) {
		const char *name = RAND_ARRAY(alts);
		size_t slen = strlen(name) + 1;
		size_t total = NLA_ALIGN(NLA_HDRLEN + slen);

		if (off + total > avail)
			break;
		if (!start_nlattr(p, off, avail, IFLA_ALT_IFNAME, slen))
			break;
		memcpy(p + off + NLA_HDRLEN, name, slen);
		off += total;
	}
	return off;
}

/*
 * Generate a structured payload for link-property rtnetlink attributes.
 * Covers the RTM_*LINKPROP message group (23).  net/core/rtnetlink.c's
 * rtnl_linkprop shares ifla_policy with the link handlers but only acts
 * on a narrow slice: ifm->ifi_index in the body picks the target dev,
 * and when that's zero IFLA_IFNAME / IFLA_ALT_IFNAME resolve it
 * instead; the per-message work then walks IFLA_PROP_LIST (a required
 * NLA_NESTED) for IFLA_ALT_IFNAME children that rtnl_alt_ifname adds
 * or removes.  Random-byte payloads at IFLA_PROP_LIST almost never
 * frame as a valid nested chain so nla_validate_nested bounces the
 * outer attr before rtnl_alt_ifname ever runs; lay down a typed
 * nested chain here to get past that gate.  Anything outside this
 * subset returns 0 so the caller falls back to a random blob.
 */
size_t gen_rta_linkprop_payload(unsigned char *p, size_t avail,
				unsigned short nla_type)
{
	switch (nla_type) {
	case IFLA_PROP_LIST:
		if (avail >= NLA_HDRLEN + 8)
			return build_linkprop_nested(p, avail);
		return 0;

	case IFLA_IFNAME:
	case IFLA_ALT_IFNAME: {
		static const char * const names[] = {
			"eth0", "lo", "br0", "altname0", "renamed1",
		};
		const char *name = RAND_ARRAY(names);
		size_t slen = strlen(name) + 1;

		if (avail >= slen) {
			memcpy(p, name, slen);
			return slen;
		}
		return 0;
	}

	default:
		return 0;
	}
}
