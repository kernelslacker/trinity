/*
 * msg-rtnl-route.c
 *
 * Per-family rtnetlink payload builders for the route / rule / nexthop
 * / prefix / nsid / chain groups, split out of
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
#include <linux/fib_rules.h>
#include <linux/nexthop.h>
#include <linux/net_namespace.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
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
size_t gen_rta_prefix_payload(unsigned char *p, size_t avail,
			      unsigned short nla_type);
size_t gen_rta_nsid_payload(unsigned char *p, size_t avail,
			    unsigned short nla_type);
size_t gen_rta_chain_payload(unsigned char *p, size_t avail,
			     unsigned short nla_type);

static size_t gen_route_addr(unsigned char *p, size_t avail, unsigned char family)
{
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
}

static size_t gen_route_multipath(unsigned char *p, size_t avail)
{
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
		return gen_route_addr(p, avail, family);

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

	case RTA_MULTIPATH:
		return gen_route_multipath(p, avail);

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
 * Generate a structured payload for nexthop rtnetlink attributes (NHA_*).
 * Covers RTM_*NEXTHOP / RTM_*NEXTHOPBUCKET message groups (22/25).
 * The kernel's rtm_nh_policy_new walker rejects almost every random-byte
 * NHA_* attr on length / mask / range before the message ever reaches
 * nh_create_ipv4 / nh_create_group: NHA_ID / NHA_OIF / NHA_MASTER are
 * fixed-width u32, NHA_GROUP_TYPE is NLA_U16 capped at
 * NEXTHOP_GRP_TYPE_MAX, NHA_GROUP is an array of struct nexthop_grp
 * sized to a multiple of the entry stride, NHA_OP_FLAGS is bitmask-
 * validated against NHA_OP_FLAG_DUMP_{STATS,HW_STATS}.  Sizing each
 * attr to its policy gets the message past nla_parse into those per-
 * attr validators and onward into nh_check_attr_* / nexthop_create.
 *
 * Skipped on purpose:
 *   NHA_GATEWAY     — kernel demands nla_len == 4 (AF_INET) or 16
 *                     (AF_INET6); the dispatch signature doesn't carry
 *                     nhmsg.nh_family, so the random fallback (which
 *                     occasionally lands exactly on 4 or 16) is
 *                     strictly better than guessing the wrong size.
 *   NHA_ENCAP       — opaque per-encap-type payload (mpls labels, ila
 *                     identifier, seg6 srh, …); only useful in lock-
 *                     step with NHA_ENCAP_TYPE, deferred.
 *   NHA_BLACKHOLE / NHA_GROUPS / NHA_FDB — NLA_FLAG attrs that need a
 *                     zero-byte payload; the current generator->caller
 *                     protocol treats a 0 return as "fall back to
 *                     random", so these can't be expressed here.
 *   NHA_RES_GROUP / NHA_RES_BUCKET / NHA_GROUP_STATS — nested sub-attr
 *                     namespaces; would need their own tables to emit
 *                     usefully, deferred.
 */
size_t gen_rta_nexthop_payload(unsigned char *p, size_t avail,
			       unsigned short nla_type)
{
	switch (nla_type) {
	case NHA_ID:
	case NHA_OIF:
	case NHA_MASTER:
	case NHA_OP_FLAGS:
	case NHA_HW_STATS_ENABLE:
	case NHA_HW_STATS_USED:
		/* u32 scalar attrs.  NHA_ID == 0 asks the kernel to
		 * auto-assign; small ifindex / id values keep the per-
		 * netns nh_table lookup in the range a sibling nexthop
		 * could plausibly occupy. */
		if (avail >= 4) {
			__u32 val = rnd_modulo_u32(64);

			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case NHA_GROUP_TYPE:
		/* u16; one of NEXTHOP_GRP_TYPE_{MPATH,RES}. */
		if (avail >= 2) {
			unsigned short val =
				rnd_modulo_u32(NEXTHOP_GRP_TYPE_MAX + 1);

			memcpy(p, &val, 2);
			return 2;
		}
		return 0;

	case NHA_ENCAP_TYPE:
		/* u16; LWTUNNEL_ENCAP_* index.  Small range covers the
		 * in-tree encap kinds (MPLS, IP, ILA, IP6, SEG6, BPF,
		 * SEG6_LOCAL, RPL, IOAM6, XFRM) so
		 * lwtunnel_valid_encap_type() resolves to a registered
		 * ops vector instead of bouncing on -EOPNOTSUPP. */
		if (avail >= 2) {
			unsigned short val = rnd_modulo_u32(11);

			memcpy(p, &val, 2);
			return 2;
		}
		return 0;

	case NHA_GROUP: {
		/* Array of struct nexthop_grp entries.  The kernel walks
		 * nla_len / sizeof(nexthop_grp) entries and resolves each
		 * .id against the per-netns nh_table; small ids ride the
		 * same lookup real userspace exercises and let the walker
		 * reach nexthop_group_alloc / nh_grp_lookup. */
		size_t written = 0;
		int n_entries = RAND_RANGE(1, 4);

		while (n_entries-- > 0 &&
		       written + sizeof(struct nexthop_grp) <= avail) {
			struct nexthop_grp grp;

			grp.id = rnd_modulo_u32(64);
			grp.weight = rnd_modulo_u32(256);
			grp.weight_high = 0;
			grp.resvd2 = 0;
			memcpy(p + written, &grp, sizeof(grp));
			written += sizeof(grp);
		}
		return written;
	}

	default:
		return 0;
	}
}

/*
 * Generate a structured payload for prefix-information rtnetlink
 * attributes (PREFIX_*).  Covers the RTM_*PREFIX message group (9),
 * emitted by the kernel from net/ipv6/addrconf.c::inet6_prefix_notify
 * on receipt of an IPv6 Router Advertisement carrying a Prefix
 * Information option.  The two non-UNSPEC slots in the kernel's
 * enum -- PREFIX_ADDRESS and PREFIX_CACHEINFO -- are fixed-width:
 * PREFIX_ADDRESS is a 16-byte struct in6_addr (the advertised prefix)
 * and PREFIX_CACHEINFO is a struct prefix_cacheinfo carrying two u32
 * lifetimes (preferred_time, valid_time).  A random-byte payload of
 * length [0, 64) almost never lands at exactly 16 / 8 bytes wide, so
 * a length-checking parse would reject the message before the per-attr
 * writers run.  Size both to the struct widths so the parse reaches
 * the value-carrying path.
 */
size_t gen_rta_prefix_payload(unsigned char *p, size_t avail,
			      unsigned short nla_type)
{
	switch (nla_type) {
	case PREFIX_ADDRESS:
		if (avail >= sizeof(struct in6_addr)) {
			struct in6_addr addr;

			rand_ipv6(&addr);
			memcpy(p, &addr, sizeof(addr));
			return sizeof(addr);
		}
		return 0;

	case PREFIX_CACHEINFO:
		if (avail >= sizeof(struct prefix_cacheinfo)) {
			struct prefix_cacheinfo ci;

			ci.preferred_time = rand32();
			ci.valid_time = rand32();
			memcpy(p, &ci, sizeof(ci));
			return sizeof(ci);
		}
		return 0;

	default:
		return 0;
	}
}

/*
 * Generate a structured payload for network-namespace-id rtnetlink
 * attributes (NETNSA_*).  Covers the RTM_*NSID message group (18).  The
 * kernel net/core/net_namespace.c handlers rtnl_net_newid /
 * rtnl_net_getid walk rtnl_net_policy, which length-rejects
 * NETNSA_NSID / NETNSA_TARGET_NSID (.type = NLA_S32) and NETNSA_PID /
 * NETNSA_FD (.type = NLA_U32) at the wrong-width gate before the doit
 * handler runs -- a random-byte payload of length [0, 64) almost never
 * lands at exactly 4 bytes wide, so the message is rejected at
 * nla_parse before rtnl_net_{newid,getid} ever dispatches.  Size every
 * slot to 4 bytes so the parse reaches the value-carrying path; the
 * signed NSID slots bias toward small positive values (real allocated
 * nsids are small) with the occasional NETNSA_NSID_NOT_ASSIGNED (-1)
 * to exercise the "no id" gate.  NETNSA_CURRENT_NSID is reply-only in
 * the kernel (it has no rtnl_net_policy entry and is only emitted via
 * nla_put_s32 in the fill path) but is included in the emitted set so
 * the policy walker's unknown-attr arm runs alongside the live slots.
 */
size_t gen_rta_nsid_payload(unsigned char *p, size_t avail,
			    unsigned short nla_type)
{
	switch (nla_type) {
	case NETNSA_NSID:
	case NETNSA_TARGET_NSID:
	case NETNSA_CURRENT_NSID:
		if (avail >= 4) {
			__s32 val;

			if (ONE_IN(8))
				val = NETNSA_NSID_NOT_ASSIGNED;
			else
				val = (__s32)rnd_modulo_u32(1024);
			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case NETNSA_PID:
	case NETNSA_FD:
		if (avail >= 4) {
			__u32 val = rnd_modulo_u32(1 << 16);

			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	default:
		return 0;
	}
}

/*
 * Generate a structured payload for chain-template rtnetlink attributes.
 * Covers the RTM_*CHAIN message group (21).  net/sched/cls_api.c's
 * tc_ctl_chain shares rtm_tca_policy with the qdisc / tclass / tfilter
 * handlers but only acts on a narrow slice of TCA_*: TCA_KIND selects a
 * tcf_proto_ops vector via tcf_proto_lookup_ops (only the classifiers
 * with a non-NULL .tmplt_create reach the per-kind template builder;
 * the rest bounce at the EOPNOTSUPP gate, which is still useful
 * coverage); TCA_OPTIONS carries the per-kind template options nest
 * (TCA_FLOWER_* etc.); TCA_CHAIN is read as u32 via nla_get_u32 to pick
 * the chain index; TCA_DUMP_FLAGS is the only other attr the chain
 * dump path consults.  Random-byte payloads almost never land at the
 * widths rtm_tca_policy demands (4 for the u32 / bitfield32 slots,
 * NUL-terminated for TCA_KIND) so the message is rejected at nla_parse
 * before tc_ctl_chain dispatches; sizing each slot to the policy gets
 * past that gate.  Anything outside this subset returns 0 so the caller
 * falls back to a random blob.
 */
size_t gen_rta_chain_payload(unsigned char *p, size_t avail,
			     unsigned short nla_type)
{
	switch (nla_type) {
	case TCA_KIND: {
		/* String: classifier kind.  tcf_proto_lookup_ops resolves
		 * this to a tcf_proto_ops vector; the per-kind .tmplt_create
		 * (where present) runs over TCA_OPTIONS. */
		static const char *kinds[] = {
			"flower", "basic", "matchall", "u32", "fw",
			"route", "tcindex", "cgroup", "bpf", "rsvp",
		};
		const char *name = RAND_ARRAY(kinds);
		size_t slen = strlen(name) + 1;

		if (avail >= slen) {
			memcpy(p, name, slen);
			return slen;
		}
		return 0;
	}

	case TCA_CHAIN:
		if (avail >= 4) {
			__u32 val = rnd_modulo_u32(64);

			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case TCA_OPTIONS:
		/* Nested per-kind template options blob.  The sub-attr
		 * namespace differs per classifier (TCA_FLOWER_*,
		 * TCA_BASIC_*, ...); emit a generic small nest with valid
		 * nlattr framing so the per-kind policy walker runs rather
		 * than the message bouncing at nla_parse_nested. */
		if (avail >= NLA_HDRLEN + 8) {
			return build_nested_attrs(p, avail, tca_attrs,
						  tca_attrs_n, 0);
		}
		return 0;

	case TCA_DUMP_FLAGS:
		/* NLA_BITFIELD32 gating the dump terse mode. */
		if (avail >= sizeof(struct nla_bitfield32)) {
			struct nla_bitfield32 bf;

			bf.selector = TCA_DUMP_FLAGS_TERSE;
			bf.value = rnd_modulo_u32(2) ? TCA_DUMP_FLAGS_TERSE : 0;
			memcpy(p, &bf, sizeof(bf));
			return sizeof(bf);
		}
		return 0;

	default:
		return 0;
	}
}
