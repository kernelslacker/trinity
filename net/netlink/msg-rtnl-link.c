/*
 * msg-rtnl-link.c
 *
 * Per-family rtnetlink payload builders for the link (IFLA_*),
 * link-property (RTM_*LINKPROP) and tunnel (RTM_*TUNNEL /
 * vxlan-vnifilter) groups, split out of
 * net/netlink/msg-rtnl-payloads.c so each family's rationale comments
 * and per-attr switch live in a TU a reviewer thinks about
 * separately.  Shared helpers (rand_ipv4, rand_ipv6, start_nlattr,
 * build_nested_attrs) live in net/netlink/msg-rtnl-common.c.
 */
#include <sys/socket.h>
#include <stddef.h>
#include <netinet/in.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_bridge.h>
#include "netlink-attrs.h"
#include "msg-internal.h"
#include "msg-rtnl-common.h"
#include "random.h"
#include "trinity.h"
#include "rnd.h"
#include "utils-macros.h"		/* ARRAY_SIZE, RAND_ARRAY */

/* Prototypes for external-linkage generators defined below.  Their
 * sibling declarations for the dispatcher live in net/netlink/msg.c;
 * these self-declarations satisfy -Wmissing-prototypes without
 * widening the per-family wire-up beyond the two TUs that need it
 * (this file and msg.c). */
size_t gen_rta_tunnel_payload(unsigned char *p, size_t avail,
			      unsigned short nla_type);
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
