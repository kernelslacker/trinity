/*
 * netlink-msg-rtnl-payloads.c
 *
 * Per-rtnetlink-group attribute payload builders, split out of
 * net/netlink-msg.c so the message emitter / dispatcher TU stays
 * focused on protocol-body and dispatch logic and the per-group
 * payload bodies can compile in parallel.  The five generators here
 * (gen_rta_{route,link,addr,neigh,dcb}_payload) are dispatched from
 * the gen_rta_payload switch in netlink-msg.c.
 *
 * The four file-static helpers (rand_ipv4, rand_ipv6, start_nlattr,
 * build_nested_attrs) are only consumed inside this TU so they stay
 * file-static here.  Only the five payload generators are widened to
 * external linkage and declared in netlink-msg-internal.h.
 */
#include <sys/socket.h>
#include <stddef.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/neighbour.h>
#include <linux/fib_rules.h>
#include <linux/dcbnl.h>
#include <linux/pkt_sched.h>
#include <string.h>
#include "netlink-attrs.h"
#include "netlink-msg-internal.h"
#include "random.h"
#include "trinity.h"
#include "rnd.h"

/*
 * Generate random IPv4 address, biased toward useful values.
 */
static __u32 rand_ipv4(void)
{
	if (ONE_IN(4))
		return htonl(0x7f000001);	/* 127.0.0.1 */
	if (ONE_IN(4))
		return htonl(RAND_RANGE(0xc0a80001, 0xc0a800fe)); /* 192.168.0.x */
	if (ONE_IN(4))
		return htonl(RAND_RANGE(0x0a000001, 0x0a0000fe)); /* 10.0.0.x */
	return rand32();
}

/*
 * Generate random IPv6 address.
 */
static void rand_ipv6(struct in6_addr *addr)
{
	if (ONE_IN(4)) {
		/* ::1 loopback */
		memset(addr, 0, sizeof(*addr));
		addr->s6_addr[15] = 1;
	} else if (ONE_IN(3)) {
		/* fe80:: link-local */
		memset(addr, 0, sizeof(*addr));
		addr->s6_addr[0] = 0xfe;
		addr->s6_addr[1] = 0x80;
		generate_rand_bytes(&addr->s6_addr[8], 8);
	} else {
		generate_rand_bytes((unsigned char *)addr, sizeof(*addr));
	}
}

/*
 * Write an nlattr header at buf+offset. Returns pointer past the header,
 * or NULL if there's not enough room. Caller fills the payload.
 * After filling, caller must update nla_len if known, and advance offset
 * by NLA_ALIGN(nla_len).
 */
static struct nlattr *start_nlattr(unsigned char *buf, size_t offset,
				   size_t buflen, unsigned short nla_type,
				   size_t payload_len)
{
	struct nlattr nla;
	size_t total = NLA_ALIGN(NLA_HDRLEN + payload_len);

	if (offset + total > buflen)
		return NULL;

	nla.nla_len = NLA_HDRLEN + payload_len;
	nla.nla_type = nla_type;
	memcpy(buf + offset, &nla, NLA_HDRLEN);
	return (struct nlattr *)(buf + offset);
}

/*
 * Build a chain of nested sub-attributes inside a buffer.
 * Returns the total length of the nested chain (unaligned).
 * This is used for containers like RTA_METRICS, IFLA_LINKINFO, IFLA_AF_SPEC.
 */
static size_t build_nested_attrs(unsigned char *buf, size_t buflen,
				 const unsigned short *attr_types,
				 size_t nr_types, int max_depth)
{
	size_t offset = 0;
	int count = RAND_RANGE(1, 4);

	if (max_depth <= 0)
		count = RAND_RANGE(1, 2);

	while (count-- > 0 && offset + NLA_HDRLEN + 4 <= buflen) {
		unsigned short atype = attr_types[rnd_modulo_u32(nr_types)];
		size_t payload_len;
		size_t total;

		/* Random payload 4-32 bytes */
		payload_len = RAND_RANGE(4, 32);
		if (payload_len > buflen - offset - NLA_HDRLEN)
			payload_len = buflen - offset - NLA_HDRLEN;

		total = NLA_ALIGN(NLA_HDRLEN + payload_len);
		if (offset + total > buflen)
			break;

		if (!start_nlattr(buf, offset, buflen, atype, payload_len))
			break;
		generate_rand_bytes(buf + offset + NLA_HDRLEN, payload_len);
		offset += total;
	}
	return offset;
}

/*
 * Generate a structured payload for route attributes (RTA_*).
 * Returns payload length, or 0 for random fallback.
 */
size_t gen_rta_route_payload(unsigned char *p, size_t avail,
			     unsigned short nla_type, unsigned char family)
{
	switch (nla_type) {
	case RTA_DST:
	case RTA_SRC:
	case RTA_GATEWAY:
	case RTA_PREFSRC:
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

	case RTA_OIF:
	case RTA_IIF:
	case RTA_TABLE:
	case RTA_MARK:
	case RTA_NH_ID:
	case RTA_PRIORITY:
		if (avail >= 4) {
			__u32 val = rnd_modulo_u32(64);
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case RTA_PREF:
	case RTA_TTL_PROPAGATE:
	case RTA_IP_PROTO:
		if (avail >= 1) {
			*p = rnd_modulo_u32(256);
			return 1;
		}
		return 0;

	case RTA_SPORT:
	case RTA_DPORT:
	case RTA_ENCAP_TYPE:
		if (avail >= 2) {
			unsigned short val = rand16();
			memcpy(p, &val, 2);
			return 2;
		}
		return 0;

	case RTA_UID:
	case RTA_EXPIRES:
		if (avail >= 4) {
			__u32 val = rand32();
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case RTA_CACHEINFO:
		if (avail >= sizeof(struct rta_cacheinfo)) {
			struct rta_cacheinfo ci;
			generate_rand_bytes((unsigned char *)&ci, sizeof(ci));
			memcpy(p, &ci, sizeof(ci));
			return sizeof(ci);
		}
		return 0;

	case RTA_METRICS:
		/* Nested container of RTAX_* sub-attributes */
		if (avail >= NLA_HDRLEN + 8) {
			return build_nested_attrs(p, avail, rtax_attrs,
						  rtax_attrs_n, 0);
		}
		return 0;

	case RTA_MULTIPATH: {
		/* Array of struct rtnexthop, each optionally followed by RTA_GATEWAY */
		size_t written = 0;
		int nhops = RAND_RANGE(1, 3);

		while (nhops-- > 0 && written + sizeof(struct rtnexthop) <= avail) {
			struct rtnexthop nh;
			size_t nh_start = written;

			nh.rtnh_flags = rnd_modulo_u32(256);
			nh.rtnh_hops = rnd_modulo_u32(256);
			nh.rtnh_ifindex = rnd_modulo_u32(64);
			nh.rtnh_len = sizeof(struct rtnexthop);

			memcpy(p + written, &nh, sizeof(nh));
			written += sizeof(struct rtnexthop);

			/* Sometimes append an RTA_GATEWAY after the nexthop */
			if (RAND_BOOL() && written + NLA_HDRLEN + 4 <= avail) {
				struct nlattr gw_nla;
				__u32 gw = rand_ipv4();

				gw_nla.nla_len = NLA_HDRLEN + 4;
				gw_nla.nla_type = RTA_GATEWAY;
				memcpy(p + written, &gw_nla, NLA_HDRLEN);
				memcpy(p + written + NLA_HDRLEN, &gw, 4);
				written += NLA_ALIGN(NLA_HDRLEN + 4);
			}

			/* Update rtnh_len to include any trailing attrs */
			nh.rtnh_len = written - nh_start;
			memcpy(p + nh_start, &nh, sizeof(nh.rtnh_len));
		}
		return written;
	}

	default:
		return 0;
	}
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
	case IFLA_IFALIAS: {
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

	case IFLA_ALT_IFNAME: {
		static const char *alts[] = { "altname0", "renamed1" };
		const char *name = RAND_ARRAY(alts);
		size_t slen = strlen(name) + 1;

		if (avail >= slen) {
			memcpy(p, name, slen);
			return slen;
		}
		return 0;
	}

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
	case IFLA_EXT_MASK:
	case IFLA_LINK_NETNSID:
	case IFLA_NET_NS_PID:
	case IFLA_NET_NS_FD:
		if (avail >= 4) {
			__u32 val = rnd_modulo_u32(64);
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

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

	case IFLA_AF_SPEC: {
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
 * Generate a structured payload for fib-rule attributes (FRA_*).
 * Mirrors the route generator's shape: addresses sized to family,
 * ifnames as NUL-terminated strings, scalar attrs as the u32/u8 width
 * the kernel's fib_rule_policy expects.  Anything outside this set
 * returns 0 so the caller falls back to a random blob.
 */
size_t gen_rta_rule_payload(unsigned char *p, size_t avail,
			    unsigned short nla_type, unsigned char family)
{
	switch (nla_type) {
	case FRA_DST:
	case FRA_SRC:
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

	case FRA_IIFNAME:
	case FRA_OIFNAME: {
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

	case FRA_TABLE:
		if (avail >= 4) {
			__u32 val = rnd_modulo_u32(256);
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case FRA_FWMARK:
	case FRA_FWMASK:
	case FRA_PRIORITY:
	case FRA_GOTO:
		if (avail >= 4) {
			__u32 val = rand32();
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case FRA_L3MDEV:
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
