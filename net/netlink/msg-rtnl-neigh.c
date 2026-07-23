/*
 * msg-rtnl-neigh.c
 *
 * Per-family rtnetlink payload builders for the neighbour (NDA_*),
 * neighbour-table (NDTA_*), bridge multicast database (MDBA_*) and
 * bridge VLAN database (BRIDGE_VLANDB_*) groups, split out of
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
#include <linux/if_bridge.h>
#include <linux/neighbour.h>
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
size_t gen_rta_neightbl_payload(unsigned char *p, size_t avail,
				unsigned short nla_type);

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
