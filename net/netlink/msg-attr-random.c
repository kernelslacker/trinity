/*
 * Legacy random-payload attribute emission split out of net/netlink/msg-core.c.
 *
 * Families without a curated nla_attr_spec table (chiefly NETLINK_ROUTE,
 * plus any unknown family that falls through pick_spec_table()) still
 * need per-attribute payload generation.  This TU carries that path:
 * the rtnetlink structured-payload dispatcher (gen_rta_payload plus its
 * rta_payload_is_nested classifier), the per-rtnl-group attribute-type
 * hint tables, pick_rtnl_attr_type(), and the two emitters
 * (append_nlattr, append_nested_attr_container) that iter_nlmsg_attr()
 * in msg-core.c dispatches to.
 *
 * The per-group "hint lists" (ndtbl_attrs, ifla_stats_attrs,
 * netnsa_attrs, tca_chain_attrs, linkprop_attrs) stay file-static here
 * for the same reason they were file-static before: each is only
 * consumed by pick_rtnl_attr_type()'s single switch arm.
 *
 * append_nested_attr_container() calls back into pick_attr_hint(),
 * which stays in msg-core.c because it fans out to per-family pickers in
 * both TUs; the declaration in msg-internal.h closes the loop.
 */
#include <stddef.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_bridge.h>
#include <linux/net_namespace.h>
#include "msg-internal.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "utils.h"

/* Forward declaration — defined in net/netlink/msg-rtnl-payloads.c.
 * Other gen_rta_* sibling declarations live in msg-internal.h;
 * this one is inline here to keep the rtnl_neightbl wire-up confined
 * to the two TUs that actually need it. */
size_t gen_rta_neightbl_payload(unsigned char *p, size_t avail,
				unsigned short nla_type);

/* Same shape as gen_rta_neightbl_payload above: declaration inline
 * here to keep the rtnl_addrlabel wire-up confined to the two TUs
 * that actually need it. */
size_t gen_rta_addrlabel_payload(unsigned char *p, size_t avail,
				 unsigned short nla_type);

/* Same shape as gen_rta_neightbl_payload above: declaration inline
 * here to keep the rtnl_stats wire-up confined to the two TUs that
 * actually need it. */
size_t gen_rta_stats_payload(unsigned char *p, size_t avail,
			     unsigned short nla_type);

/* Same shape as gen_rta_neightbl_payload above: declaration inline
 * here to keep the rtnl_action wire-up confined to the two TUs that
 * actually need it. */
size_t gen_rta_action_payload(unsigned char *p, size_t avail,
			      unsigned short nla_type);

/* Same shape as gen_rta_neightbl_payload above: declaration inline
 * here to keep the rtnl_tunnel wire-up confined to the two TUs that
 * actually need it. */
size_t gen_rta_tunnel_payload(unsigned char *p, size_t avail,
			      unsigned short nla_type);

/* Same shape as gen_rta_neightbl_payload above: declaration inline
 * here to keep the rtnl_prefix wire-up confined to the two TUs that
 * actually need it. */
size_t gen_rta_prefix_payload(unsigned char *p, size_t avail,
			      unsigned short nla_type);

/* Same shape as gen_rta_neightbl_payload above: declaration inline
 * here to keep the rtnl_nsid wire-up confined to the two TUs that
 * actually need it. */
size_t gen_rta_nsid_payload(unsigned char *p, size_t avail,
			    unsigned short nla_type);

/* Same shape as gen_rta_neightbl_payload above: declaration inline
 * here to keep the rtnl_chain wire-up confined to the two TUs that
 * actually need it. */
size_t gen_rta_chain_payload(unsigned char *p, size_t avail,
			     unsigned short nla_type);

/* Same shape as gen_rta_neightbl_payload above: declaration inline
 * here to keep the rtnl_linkprop wire-up confined to the two TUs that
 * actually need it. */
size_t gen_rta_linkprop_payload(unsigned char *p, size_t avail,
				unsigned short nla_type);

/*
 * Generate a structured payload for a specific rtnetlink attribute.
 * Dispatches to the appropriate per-group generator based on the
 * rtnetlink message group. Returns the payload length, or 0 for
 * random fallback.
 */
static size_t gen_rta_payload(unsigned char *buf, size_t offset, size_t buflen,
			      unsigned short nla_type, unsigned char family,
			      int rtnl_group)
{
	size_t avail = buflen - offset;
	unsigned char *p = buf + offset;

	switch (rtnl_group) {
	case 0: return gen_rta_link_payload(p, avail, nla_type);
	case 1: return gen_rta_addr_payload(p, avail, nla_type, family);
	case 2: return gen_rta_route_payload(p, avail, nla_type, family);
	case 3: return gen_rta_neigh_payload(p, avail, nla_type, family);
	case 4: return gen_rta_rule_payload(p, avail, nla_type, family);
	case 5:
	case 6:
	case 7: return gen_rta_tc_payload(p, avail, nla_type);
	case 8: return gen_rta_action_payload(p, avail, nla_type);
	case 9: return gen_rta_prefix_payload(p, avail, nla_type);
	case 12: return gen_rta_neightbl_payload(p, avail, nla_type);
	case 14: return gen_rta_addrlabel_payload(p, avail, nla_type);
	case 15: return gen_rta_dcb_payload(p, avail, nla_type);
	case 16: return gen_rta_netconf_payload(p, avail, nla_type);
	case 17: return gen_rta_mdba_payload(p, avail, nla_type);
	case 18: return gen_rta_nsid_payload(p, avail, nla_type);
	case 19: return gen_rta_stats_payload(p, avail, nla_type);
	case 21: return gen_rta_chain_payload(p, avail, nla_type);
	case 23: return gen_rta_linkprop_payload(p, avail, nla_type);
	case 24: return gen_rta_vlandb_payload(p, avail, nla_type);
	case 22:
	case 25: return gen_rta_nexthop_payload(p, avail, nla_type);
	case 26: return gen_rta_tunnel_payload(p, avail, nla_type);

	/*
	 * Groups 10, 11 and 13 have no user-settable attribute surface:
	 *
	 * Group 10: RTM_GETMULTICAST (RTM_NEWMULTICAST=56).  Registered
	 * with only a .dumpit handler in both IPv4 (net/ipv4/devinet.c,
	 * inet_dump_ifmcaddr) and IPv6 (net/ipv6/addrconf.c,
	 * inet6_dump_ifmcaddr).  The kernel enumerates multicast group
	 * memberships; the user supplies only a netlink dump request with
	 * no RTAs.
	 *
	 * Group 11: RTM_GETANYCAST (RTM_NEWANYCAST=60).  IPv6-only,
	 * registered with only .dumpit (net/ipv6/addrconf.c,
	 * inet6_dump_ifacaddr).  Same pattern as GETMULTICAST: dump-only,
	 * no user-writable RTA payload.
	 *
	 * Group 13: RTM_NEWNDUSEROPT (=68).  Purely a kernel-to-user
	 * notification; the kernel sends it when Neighbor Discovery
	 * processes Router Advertisement user options
	 * (net/ipv6/ndisc.c, ndisc_send_nduseropt).  No userspace .doit
	 * or .dumpit handler is registered; a sendmsg from userspace
	 * would be rejected by rtnetlink before any RTA is parsed.
	 */
	case 10: /* RTM_GETMULTICAST - dump-only, no user-settable RTAs */
	case 11: /* RTM_GETANYCAST  - dump-only, no user-settable RTAs */
	case 13: /* RTM_NEWNDUSEROPT - kernel-to-user notify only */
		/* fall through */
	default: return 0;
	}
}

/*
 * Returns non-zero iff gen_rta_payload() for (rtnl_group, nla_type)
 * emits a nested attribute chain (one or more NLA-headered children)
 * rather than a flat scalar / struct / string payload.  Setting
 * NLA_F_NESTED on a flat payload flips the kernel into the
 * nla_validate_nested arm, which then rejects on the first "nested
 * header" that doesn't fit — so the flag has to track the actual
 * payload shape.
 *
 * Keep this in sync with the structured-payload generators above:
 *   group 0 (link):  IFLA_LINKINFO, IFLA_AF_SPEC
 *   group 2 (route): RTA_METRICS, RTA_MULTIPATH
 *   groups 5/6/7 (tc): TCA_OPTIONS, TCA_STAB, TCA_STATS2
 *   group 8 (action): TCA_ROOT_TAB -- nested per-action chain whose
 *                   inner sub-attrs carry TCA_ACT_KIND etc.
 *   group 15 (dcb): DCB_ATTR_IEEE
 *   group 17 (mdb): MDBA_ROUTER -- always a NLA_NESTED chain (the
 *                   MDBE_ATTR_* request shape and the MDBA_ROUTER_PORT
 *                   reply shape are both nested). MDBA_MDB stays flat
 *                   here: the dominant emission is a struct br_mdb_entry
 *                   leaf and the alt MDBA_MDB_ENTRY reply shape is a
 *                   minority arm not worth a misleading nested flag.
 *   group 21 (chain): TCA_OPTIONS -- per-classifier-kind template
 *                   options nest; tc_ctl_chain doesn't consult
 *                   TCA_STAB / TCA_STATS2 so they stay flat here.
 *   group 23 (linkprop): IFLA_PROP_LIST -- required NLA_NESTED in
 *                   ifla_policy carrying IFLA_ALT_IFNAME string
 *                   children that rtnl_alt_ifname add/del walks.
 *   group 24 (vlandb): BRIDGE_VLANDB_ENTRY and
 *                   BRIDGE_VLANDB_GLOBAL_OPTIONS -- both are
 *                   NLA_NESTED in br_vlan_db_policy and the generator
 *                   always emits a typed nested chain (ENTRY_INFO /
 *                   GOPTS_ID leader plus random-payload siblings).
 *   group 26 (tunnel): VXLAN_VNIFILTER_ENTRY -- the only top-level
 *                   attr declared in vni_filter_policy (NLA_NESTED);
 *                   the inner walker drives vni_filter_entry_policy
 *                   over START / END / GROUP / GROUP6.
 * The address (group 1), neigh (group 3) and rule (group 4) generators
 * only emit flat payloads today; add their nested entries here if that
 * changes.
 */
static int rta_payload_is_nested(int rtnl_group, unsigned short nla_type)
{
	switch (rtnl_group) {
	case 0:
		return nla_type == IFLA_LINKINFO || nla_type == IFLA_AF_SPEC;
	case 2:
		return nla_type == RTA_METRICS || nla_type == RTA_MULTIPATH;
	case 5:
	case 6:
	case 7:
		return nla_type == TCA_OPTIONS || nla_type == TCA_STAB ||
		       nla_type == TCA_STATS2;
	case 8:
		return nla_type == TCA_ROOT_TAB;
	case 12:
		return nla_type == NDTA_PARMS;
	case 15:
		return nla_type == DCB_ATTR_IEEE;
	case 17:
		return nla_type == MDBA_ROUTER;
	case 21:
		return nla_type == TCA_OPTIONS;
	case 23:
		return nla_type == IFLA_PROP_LIST;
	case 24:
		return nla_type == BRIDGE_VLANDB_ENTRY ||
		       nla_type == BRIDGE_VLANDB_GLOBAL_OPTIONS;
	case 26:
		return nla_type == VXLAN_VNIFILTER_ENTRY;
	default:
		return 0;
	}
}

/*
 * Append a single nlattr to buf at offset. Returns new offset.
 * nla_type_hint is a protocol-appropriate attr type; 0 means random.
 * family is the address family from the body struct (for address sizing).
 */
size_t append_nlattr(unsigned char *buf, size_t offset, size_t buflen,
		     unsigned short nla_type_hint, unsigned char family,
		     int rtnl_group)
{
	struct nlattr nla;
	size_t payload_len;
	size_t structured_len;
	size_t total;
	unsigned short nla_type;

	if (offset + NLA_HDRLEN > buflen)
		return offset;

	/* Decide the attr type first */
	if (nla_type_hint && !ONE_IN(8))
		nla_type = nla_type_hint;
	else
		nla_type = rand16();

	/* Try structured payload generation for known types */
	structured_len = gen_rta_payload(buf, offset + NLA_HDRLEN, buflen,
					nla_type, family, rtnl_group);
	if (structured_len > 0) {
		payload_len = structured_len;
	} else {
		/* Fall back to random bytes */
		payload_len = rnd_modulo_u32(64);
	}

	total = NLA_ALIGN(NLA_HDRLEN + payload_len);
	if (offset + total > buflen) {
		total = buflen - offset;
		if (total < NLA_HDRLEN)
			return offset;
		payload_len = total - NLA_HDRLEN;
	}

	nla.nla_len = NLA_HDRLEN + payload_len;
	nla.nla_type = nla_type;

	/*
	 * Set NLA_F_NESTED only when the payload actually is a nested
	 * attribute chain.  For structured-but-flat payloads (RTA_DST,
	 * RTA_OIF, IFLA_MTU, …) the kernel routes on this flag into
	 * nla_validate_nested and rejects the attr on the first child
	 * header that doesn't fit, which was dropping a noticeable
	 * fraction of structured attrs before reaching the family's
	 * real handler.  Random-byte payloads (structured_len == 0) keep
	 * the unconditional 1-in-4 OR — bad-attr is intentional novelty
	 * on that path.
	 */
	if (ONE_IN(4)) {
		if (structured_len == 0 ||
		    rta_payload_is_nested(rtnl_group, nla_type))
			nla.nla_type |= NLA_F_NESTED;
	}
	if (ONE_IN(8))
		nla.nla_type |= NLA_F_NET_BYTEORDER;

	memcpy(buf + offset, &nla, NLA_HDRLEN);

	/* If we didn't do structured generation, fill with random data */
	if (structured_len == 0 && payload_len > 0)
		generate_rand_bytes(buf + offset + NLA_HDRLEN, payload_len);

	return offset + total;
}

/* NDTA_* attr types for RTM_*NEIGHTBL (rtnl group 12).  File-static
 * here rather than alongside ifla_attrs/etc. in msg-tables.c
 * to keep the rtnl_neightbl wire-up confined to the two TUs that
 * actually need it; matches the shape of the other per-group lists. */
static const unsigned short ndtbl_attrs[] = {
	NDTA_NAME, NDTA_THRESH1, NDTA_THRESH2, NDTA_THRESH3,
	NDTA_CONFIG, NDTA_PARMS, NDTA_STATS, NDTA_GC_INTERVAL,
};

/* IFLA_STATS_* attr types for RTM_*STATS (rtnl group 19).  File-static
 * here for the same reason as ndtbl_attrs above. */
static const unsigned short ifla_stats_attrs[] = {
	IFLA_STATS_LINK_64, IFLA_STATS_LINK_XSTATS,
	IFLA_STATS_LINK_XSTATS_SLAVE, IFLA_STATS_LINK_OFFLOAD_XSTATS,
	IFLA_STATS_AF_SPEC,
};

/* NETNSA_* attr types for RTM_*NSID (rtnl group 18).  File-static here
 * for the same reason as ndtbl_attrs above.  NETNSA_CURRENT_NSID is
 * reply-only in the kernel policy but is emitted so the policy
 * walker's unknown-attr arm runs alongside the live slots. */
static const unsigned short netnsa_attrs[] = {
	NETNSA_NSID, NETNSA_PID, NETNSA_FD,
	NETNSA_TARGET_NSID, NETNSA_CURRENT_NSID,
};

/* TCA_* attr types the chain handler (rtnl group 21) actually consumes.
 * tc_ctl_chain shares rtm_tca_policy with cases 5/6/7 but only reads
 * this narrow subset; the rest of tca_attrs is silently ignored, so a
 * focused hint list keeps gen_rta_chain_payload's structured arms hit
 * instead of the random fallback. */
static const unsigned short tca_chain_attrs[] = {
	TCA_KIND, TCA_OPTIONS, TCA_CHAIN, TCA_DUMP_FLAGS,
};

/* IFLA_* attr types the linkprop handler (rtnl group 23) actually
 * consumes.  rtnl_linkprop shares ifla_policy with group 0 but only
 * acts on IFLA_PROP_LIST (required) plus IFLA_IFNAME / IFLA_ALT_IFNAME
 * (used to resolve the target dev when ifm->ifi_index is 0); the rest
 * of ifla_attrs is silently parsed and dropped, so a focused hint list
 * keeps gen_rta_linkprop_payload's structured arms hit instead of the
 * random fallback. */
static const unsigned short linkprop_attrs[] = {
	IFLA_PROP_LIST, IFLA_IFNAME, IFLA_ALT_IFNAME,
};

/* Pick an nlattr type appropriate for an rtnetlink message group.
 * Returns 0 for unknown groups (caller falls back to random). */
unsigned short pick_rtnl_attr_type(unsigned short nlmsg_type)
{
	unsigned int group;

	if (nlmsg_type < RTM_BASE || nlmsg_type >= RTM_MAX)
		return 0;

	group = (nlmsg_type - RTM_BASE) / 4;
	switch (group) {
	case 0: return ifla_attrs[rnd_modulo_u32(ifla_attrs_n)];
	case 1: return ifa_attrs[rnd_modulo_u32(ifa_attrs_n)];
	case 2: return rta_attrs[rnd_modulo_u32(rta_attrs_n)];
	case 3: return nda_attrs[rnd_modulo_u32(nda_attrs_n)];
	case 4: return fra_attrs[rnd_modulo_u32(fra_attrs_n)];
	case 5:
	case 6:
	case 7: return tca_attrs[rnd_modulo_u32(tca_attrs_n)].type;
	case 12: return RAND_ARRAY(ndtbl_attrs);
	case 14: return ifal_attrs[rnd_modulo_u32(ifal_attrs_n)];
	case 15: return dcb_attrs[rnd_modulo_u32(dcb_attrs_n)];
	case 16: return netconfa_attrs[rnd_modulo_u32(netconfa_attrs_n)];
	case 17: return mdba_attrs[rnd_modulo_u32(mdba_attrs_n)];
	case 18: return RAND_ARRAY(netnsa_attrs);
	case 19: return RAND_ARRAY(ifla_stats_attrs);
	case 21: return RAND_ARRAY(tca_chain_attrs);
	case 23: return RAND_ARRAY(linkprop_attrs);
	case 24: return bridge_vlandb_attrs[rnd_modulo_u32(bridge_vlandb_attrs_n)];
	case 22:
	case 25: return nha_attrs[rnd_modulo_u32(nha_attrs_n)];
	default: return 0;
	}
}

/*
 * Emit a NLA_F_NESTED container at buf+offset.  The outer nlattr carries
 * the NLA_F_NESTED flag and an nla_len that covers a payload of N child
 * nlattrs (1-3) padded to NLA_ALIGNTO.  Each child's type is drawn from
 * the same per-family table used for flat attributes; payloads are sized
 * via the existing structured generators where applicable, falling back
 * to short random blobs.  Children are deliberately one level deep —
 * deeper recursion is left for a follow-up.
 *
 * Returns the new offset.  If there isn't room for a header plus at
 * least one child, the original offset is returned and no bytes are
 * written.  Bumps shm->stats.netlink_nested_attrs_emitted on success so
 * we can confirm in the dump that the new path is actually firing.
 */
size_t append_nested_attr_container(unsigned char *buf, size_t offset,
				    size_t buflen,
				    unsigned short outer_type,
				    int protocol,
				    unsigned short nlmsg_type,
				    unsigned char body_family,
				    int rtnl_group)
{
	struct nlattr nla;
	unsigned char *inner;
	size_t inner_avail;
	size_t inner_off = 0;
	size_t total;
	int child_count;

	/* Need outer header + at least one minimum-sized child */
	if (offset + NLA_HDRLEN + NLA_HDRLEN + 4 > buflen)
		return offset;

	inner = buf + offset + NLA_HDRLEN;
	inner_avail = buflen - offset - NLA_HDRLEN;
	/* Cap so a single nested container can't dominate the message */
	if (inner_avail > 256)
		inner_avail = 256;

	child_count = RAND_RANGE(1, 3);
	while (child_count-- > 0 && inner_off + NLA_HDRLEN + 4 <= inner_avail) {
		struct nlattr child;
		unsigned short ctype;
		size_t cpayload;
		size_t structured_len;
		size_t ctotal;

		ctype = pick_attr_hint(protocol, nlmsg_type);
		if (ctype == 0)
			ctype = rand16();

		/* Try the rtnetlink structured payload generator first; it
		 * returns 0 for non-rtnl groups and for types it doesn't know,
		 * in which case we fall back to a short random blob. */
		structured_len = gen_rta_payload(inner, inner_off + NLA_HDRLEN,
						 inner_avail, ctype,
						 body_family, rtnl_group);
		if (structured_len > 0) {
			cpayload = structured_len;
		} else {
			cpayload = RAND_RANGE(4, 32);
			if (cpayload > inner_avail - inner_off - NLA_HDRLEN)
				cpayload = inner_avail - inner_off - NLA_HDRLEN;
		}

		ctotal = NLA_ALIGN(NLA_HDRLEN + cpayload);
		if (inner_off + ctotal > inner_avail)
			break;

		child.nla_len = NLA_HDRLEN + cpayload;
		child.nla_type = ctype;
		memcpy(inner + inner_off, &child, NLA_HDRLEN);
		if (structured_len == 0 && cpayload > 0)
			generate_rand_bytes(inner + inner_off + NLA_HDRLEN,
					    cpayload);
		inner_off += ctotal;
	}

	if (inner_off == 0)
		return offset;

	nla.nla_len = NLA_HDRLEN + inner_off;
	nla.nla_type = outer_type | NLA_F_NESTED;
	memcpy(buf + offset, &nla, NLA_HDRLEN);

	total = NLA_ALIGN(NLA_HDRLEN + inner_off);
	if (offset + total > buflen)
		total = buflen - offset;

	__atomic_add_fetch(&shm->stats.netlink_nested_attrs_emitted, 1,
			   __ATOMIC_RELAXED);

	return offset + total;
}
