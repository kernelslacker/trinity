/*
 * Structured netlink message generation for fuzzing.
 *
 * Builds nlmsghdr messages with protocol-appropriate types and flags,
 * optional nlattr TLVs, and occasional deliberate corruption to test
 * both valid code paths and error handling in the kernel.
 */
#include <sys/socket.h>
#include <stddef.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if_addrlabel.h>
#include <linux/if_link.h>
#include <linux/if_bridge.h>
#include <linux/neighbour.h>
#include <linux/fib_rules.h>
#include <linux/netconf.h>
#include <linux/net_namespace.h>
#include <linux/nexthop.h>
#include <linux/dcbnl.h>
#include <linux/genetlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/xfrm.h>
#include <linux/audit.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/connector.h>
#include <string.h>
#include "net.h"
#include "netlink-attrs.h"
#include "netlink-genl-families.h"
#include "msg-internal.h"
#include "netlink-nfnl-subsystems.h"
#include "random.h"
#include "shm.h"
#include "text-payloads.h"
#include "trinity.h"
#include "rnd.h"

#include "kernel/netlink.h"
#include "kernel/nfnetlink.h"
#include "kernel/socket.h"
/* Forward declaration — called via gen_msg hook from net/proto/netlink.c */
void netlink_gen_msg(struct socket_triplet *triplet, void **buf, size_t *len);

/* Generate a random set of nlmsg flags biased toward valid combos */
static unsigned short gen_nlmsg_flags(void)
{
	unsigned short flags = NLM_F_REQUEST; /* almost always set */

	if (ONE_IN(10))
		return rand16(); /* pure chaos */

	if (RAND_BOOL())
		flags |= NLM_F_ACK;

	if (RAND_BOOL())
		flags |= NLM_F_ECHO;

	/* GET-style: dump flags */
	if (RAND_BOOL())
		flags |= NLM_F_DUMP;

	if (RAND_BOOL())
		flags |= NLM_F_ATOMIC;

	/* NEW-style: create/replace flags */
	if (RAND_BOOL()) {
		if (RAND_BOOL())
			flags |= NLM_F_CREATE;
		if (RAND_BOOL())
			flags |= NLM_F_REPLACE;
		if (RAND_BOOL())
			flags |= NLM_F_EXCL;
		if (RAND_BOOL())
			flags |= NLM_F_APPEND;
	}

	/* DELETE-style: bulk/non-recursive flags */
	if (RAND_BOOL())
		flags |= NLM_F_NONREC;
	if (RAND_BOOL())
		flags |= NLM_F_BULK;

	return flags;
}

/* Pick an nlmsg_type appropriate for the netlink protocol */
static unsigned short pick_nlmsg_type(int protocol)
{
	/* 1 in 20: completely random type to probe unknown handlers */
	if (ONE_IN(20))
		return rand16();

	switch (protocol) {
	case NETLINK_ROUTE:
		return rtnl_types[rnd_modulo_u32(rtnl_types_n)];
	case NETLINK_XFRM:
		return xfrm_types[rnd_modulo_u32(xfrm_types_n)];
	case NETLINK_AUDIT:
		return audit_types[rnd_modulo_u32(audit_types_n)];
	case NETLINK_NETFILTER: {
		/* nfnetlink: subsys << 8 | msg.
		 *
		 * Bias toward (subsys, cmd) pairs from the registry so the
		 * kernel's per-subsys nfnl_callback dispatcher actually
		 * accepts the type byte; the registered cmd set comes from
		 * net/netlink/nfnl/<subsystem>.c.  Keep an unknown-cmd path with
		 * low probability to keep exercising the
		 * dispatcher-not-registered fast-reject. */
		static const unsigned char nfnl_subsys[] = {
			NFNL_SUBSYS_CTNETLINK, NFNL_SUBSYS_CTNETLINK_EXP,
			NFNL_SUBSYS_QUEUE, NFNL_SUBSYS_ULOG,
			NFNL_SUBSYS_OSF, NFNL_SUBSYS_IPSET,
			NFNL_SUBSYS_ACCT, NFNL_SUBSYS_CTNETLINK_TIMEOUT,
			NFNL_SUBSYS_CTHELPER, NFNL_SUBSYS_NFTABLES,
			NFNL_SUBSYS_NFT_COMPAT, NFNL_SUBSYS_HOOK,
		};
		unsigned char subsys;

		if (!ONE_IN(4)) {
			const struct nfnl_subsys_grammar *sub;

			sub = nfnl_pick_subsys();
			if (sub != NULL)
				return (sub->subsys_id << 8) | nfnl_pick_cmd(sub);
		}
		if (ONE_IN(8))
			subsys = rnd_modulo_u32(16);
		else
			subsys = RAND_ARRAY(nfnl_subsys);
		return (subsys << 8) | (rnd_modulo_u32(16));
	}
	case NETLINK_GENERIC:
		/* genl: prefer a runtime-resolved family id from the
		 * grammar registry when one is available; that gets the
		 * message past the kernel's family demuxer into the
		 * actual per-family parser.  Fall back to GENL_ID_CTRL or
		 * a random nlmsg_type in the dynamic-allocation range to
		 * keep exercising the unknown-family fast-reject path. */
		if (!ONE_IN(4)) {
			struct genl_family_grammar *fam;

			genl_resolve_families();
			fam = genl_pick_resolved_family();
			if (fam != NULL)
				return fam->family_id;
		}
		if (RAND_BOOL())
			return GENL_ID_CTRL;
		return RAND_RANGE(GENL_MIN_ID, GENL_MIN_ID + 64);
	case NETLINK_SOCK_DIAG:
		/* SOCK_DIAG_BY_FAMILY=20, SOCK_DESTROY=21 are the main ones.
		 * Also cover legacy inet_diag range and INET_DIAG_GETSOCK_MAX. */
		if (RAND_BOOL())
			return RAND_BOOL() ? SOCK_DIAG_BY_FAMILY : SOCK_DESTROY;
		return RAND_RANGE(NLMSG_MIN_TYPE, INET_DIAG_GETSOCK_MAX);
	case NETLINK_CONNECTOR:
		return RAND_RANGE(0, 4);
	default:
		/* Unknown protocol: use NLMSG_MIN_TYPE or random */
		if (RAND_BOOL())
			return RAND_RANGE(NLMSG_MIN_TYPE, NLMSG_MIN_TYPE + 32);
		return rand16();
	}
}

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
static size_t append_nlattr(unsigned char *buf, size_t offset, size_t buflen,
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

	return offset + NLA_ALIGN(NLA_HDRLEN + payload_len);
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
static unsigned short pick_rtnl_attr_type(unsigned short nlmsg_type)
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
	case 7: return tca_attrs[rnd_modulo_u32(tca_attrs_n)];
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

static unsigned char rand_family(void)
{
	static const unsigned char families[] = {
		AF_INET, AF_INET6, AF_UNSPEC, AF_BRIDGE, AF_MPLS,
		AF_PACKET,
	};
	if (ONE_IN(8))
		return rnd_modulo_u32(256);
	return RAND_ARRAY(families);
}

/* RTM_*LINK: struct ifinfomsg */
static size_t gen_rtnl_body_link(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct ifinfomsg ifi;

	if (sizeof(ifi) > buflen)
		return 0;
	ifi.ifi_family = rand_family();
	ifi.__ifi_pad = 0;
	ifi.ifi_type = rand16();     /* ARPHRD_* */
	ifi.ifi_index = rnd_modulo_u32(64); /* small interface indices */
	ifi.ifi_flags = rand32();    /* IFF_* */
	ifi.ifi_change = rand32();
	*out_family = ifi.ifi_family;
	memcpy(body, &ifi, sizeof(ifi));
	return sizeof(ifi);
}

/* RTM_*ADDR: struct ifaddrmsg */
static size_t gen_rtnl_body_addr(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct ifaddrmsg ifa;

	if (sizeof(ifa) > buflen)
		return 0;
	ifa.ifa_family = rand_family();
	ifa.ifa_prefixlen = rnd_modulo_u32(129);
	ifa.ifa_flags = rnd_modulo_u32(256);
	ifa.ifa_scope = rnd_modulo_u32(256);
	ifa.ifa_index = rnd_modulo_u32(64);
	*out_family = ifa.ifa_family;
	memcpy(body, &ifa, sizeof(ifa));
	return sizeof(ifa);
}

/* RTM_*ROUTE: struct rtmsg */
static size_t gen_rtnl_body_route(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct rtmsg rtm;

	if (sizeof(rtm) > buflen)
		return 0;
	rtm.rtm_family = rand_family();
	rtm.rtm_dst_len = rnd_modulo_u32(129);
	rtm.rtm_src_len = rnd_modulo_u32(129);
	rtm.rtm_tos = rnd_modulo_u32(256);
	rtm.rtm_table = rnd_modulo_u32(256);
	rtm.rtm_protocol = rnd_modulo_u32(256);
	rtm.rtm_scope = rnd_modulo_u32(256);
	rtm.rtm_type = RAND_BOOL() ? rnd_modulo_u32(RTN_MAX + 1) : rnd_modulo_u32(256);
	rtm.rtm_flags = rand32();
	*out_family = rtm.rtm_family;
	memcpy(body, &rtm, sizeof(rtm));
	return sizeof(rtm);
}

/* RTM_*NEIGH: struct ndmsg */
static size_t gen_rtnl_body_neigh(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct ndmsg ndm;

	if (sizeof(ndm) > buflen)
		return 0;
	ndm.ndm_family = rand_family();
	ndm.ndm_pad1 = 0;
	ndm.ndm_pad2 = 0;
	ndm.ndm_ifindex = rnd_modulo_u32(64);
	ndm.ndm_state = rand16();
	ndm.ndm_flags = rnd_modulo_u32(256);
	ndm.ndm_type = rnd_modulo_u32(256);
	*out_family = ndm.ndm_family;
	memcpy(body, &ndm, sizeof(ndm));
	return sizeof(ndm);
}

/* RTM_*RULE: struct fib_rule_hdr */
static size_t gen_rtnl_body_rule(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct fib_rule_hdr frh;

	if (sizeof(frh) > buflen)
		return 0;
	frh.family = rand_family();
	frh.dst_len = rnd_modulo_u32(129);
	frh.src_len = rnd_modulo_u32(129);
	frh.tos = rnd_modulo_u32(256);
	frh.table = rnd_modulo_u32(256);
	frh.res1 = 0;
	frh.res2 = 0;
	frh.action = rnd_modulo_u32(256);
	frh.flags = rand32();
	*out_family = frh.family;
	memcpy(body, &frh, sizeof(frh));
	return sizeof(frh);
}

/* RTM_*ACTION: struct tcamsg */
static size_t gen_rtnl_body_action(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct tcamsg tca;

	if (sizeof(tca) > buflen)
		return 0;
	memset(&tca, 0, sizeof(tca));
	tca.tca_family = rand_family();
	*out_family = tca.tca_family;
	memcpy(body, &tca, sizeof(tca));
	return sizeof(tca);
}

/* RTM_*PREFIX: struct prefixmsg */
static size_t gen_rtnl_body_prefix(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct prefixmsg pmsg;

	if (sizeof(pmsg) > buflen)
		return 0;
	memset(&pmsg, 0, sizeof(pmsg));
	pmsg.prefix_family = rand_family();
	pmsg.prefix_ifindex = rnd_modulo_u32(64);
	pmsg.prefix_type = rnd_modulo_u32(256);
	pmsg.prefix_len = rnd_modulo_u32(129);
	pmsg.prefix_flags = rnd_modulo_u32(256);
	*out_family = pmsg.prefix_family;
	memcpy(body, &pmsg, sizeof(pmsg));
	return sizeof(pmsg);
}

/* RTM_*NEIGHTBL: struct ndtmsg */
static size_t gen_rtnl_body_neightbl(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct ndtmsg ndt;

	if (sizeof(ndt) > buflen)
		return 0;
	memset(&ndt, 0, sizeof(ndt));
	ndt.ndtm_family = rand_family();
	*out_family = ndt.ndtm_family;
	memcpy(body, &ndt, sizeof(ndt));
	return sizeof(ndt);
}

/* RTM_*NDUSEROPT: struct nduseroptmsg */
static size_t gen_rtnl_body_nduseropt(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct nduseroptmsg ndu;

	if (sizeof(ndu) > buflen)
		return 0;
	memset(&ndu, 0, sizeof(ndu));
	ndu.nduseropt_family = rand_family();
	ndu.nduseropt_opts_len = htons(rnd_modulo_u32(256));
	ndu.nduseropt_ifindex = rand32();
	ndu.nduseropt_icmp_type = rnd_modulo_u32(256);
	ndu.nduseropt_icmp_code = rnd_modulo_u32(256);
	*out_family = ndu.nduseropt_family;
	memcpy(body, &ndu, sizeof(ndu));
	return sizeof(ndu);
}

/* RTM_*ADDRLABEL: struct ifaddrlblmsg */
static size_t gen_rtnl_body_addrlabel(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct ifaddrlblmsg ifal;

	if (sizeof(ifal) > buflen)
		return 0;
	memset(&ifal, 0, sizeof(ifal));
	ifal.ifal_family = rand_family();
	ifal.ifal_prefixlen = rnd_modulo_u32(129);
	ifal.ifal_flags = rnd_modulo_u32(256);
	ifal.ifal_index = rand32();
	ifal.ifal_seq = rand32();
	*out_family = ifal.ifal_family;
	memcpy(body, &ifal, sizeof(ifal));
	return sizeof(ifal);
}

/* RTM_{GET,SET}DCB: struct dcbmsg */
static size_t gen_rtnl_body_dcb(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct dcbmsg dcb;

	if (sizeof(dcb) > buflen)
		return 0;
	memset(&dcb, 0, sizeof(dcb));
	dcb.dcb_family = rand_family();
	dcb.cmd = rnd_modulo_u32(256);
	dcb.dcb_pad = rand16();
	*out_family = dcb.dcb_family;
	memcpy(body, &dcb, sizeof(dcb));
	return sizeof(dcb);
}

/* RTM_*NETCONF: struct netconfmsg */
static size_t gen_rtnl_body_netconf(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct netconfmsg ncm;

	if (sizeof(ncm) > buflen)
		return 0;
	ncm.ncm_family = rand_family();
	*out_family = ncm.ncm_family;
	memcpy(body, &ncm, sizeof(ncm));
	return sizeof(ncm);
}

/* RTM_*MDB: struct br_port_msg */
static size_t gen_rtnl_body_mdb(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct br_port_msg bpm;

	if (sizeof(bpm) > buflen)
		return 0;
	bpm.family = rand_family();
	bpm.ifindex = rnd_modulo_u32(64);
	*out_family = bpm.family;
	memcpy(body, &bpm, sizeof(bpm));
	return sizeof(bpm);
}

/* RTM_*VLAN: struct br_vlan_msg */
static size_t gen_rtnl_body_vlan(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct br_vlan_msg bvm;

	if (sizeof(bvm) > buflen)
		return 0;
	bvm.family = rand_family();
	bvm.reserved1 = 0;
	bvm.reserved2 = 0;
	bvm.ifindex = rnd_modulo_u32(64);
	*out_family = bvm.family;
	memcpy(body, &bvm, sizeof(bvm));
	return sizeof(bvm);
}

/* RTM_*STATS: struct if_stats_msg */
static size_t gen_rtnl_body_stats(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct if_stats_msg smsg;

	if (sizeof(smsg) > buflen)
		return 0;
	memset(&smsg, 0, sizeof(smsg));
	smsg.family = rand_family();
	smsg.ifindex = rnd_modulo_u32(64);
	smsg.filter_mask = rand32();
	*out_family = smsg.family;
	memcpy(body, &smsg, sizeof(smsg));
	return sizeof(smsg);
}

/* RTM_*NEXTHOP / RTM_*NEXTHOPBUCKET: struct nhmsg */
static size_t gen_rtnl_body_nexthop(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct nhmsg nh;

	if (sizeof(nh) > buflen)
		return 0;
	memset(&nh, 0, sizeof(nh));
	nh.nh_family = rand_family();
	nh.nh_scope = rand32() & 0xff;
	nh.nh_protocol = rand32() & 0xff;
	nh.nh_flags = rand32();
	*out_family = nh.nh_family;
	memcpy(body, &nh, sizeof(nh));
	return sizeof(nh);
}

/* RTM_*TUNNEL: struct tunnel_msg */
static size_t gen_rtnl_body_tunnel(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct tunnel_msg tm;

	if (sizeof(tm) > buflen)
		return 0;
	tm.family = rand_family();
	tm.flags = rand32() & 0xff;
	tm.reserved2 = 0;
	tm.ifindex = rnd_modulo_u32(64);
	*out_family = tm.family;
	memcpy(body, &tm, sizeof(tm));
	return sizeof(tm);
}

/* RTM_*QDISC / RTM_*TCLASS / RTM_*TFILTER / RTM_*CHAIN: struct tcmsg */
static size_t gen_rtnl_body_tc(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct tcmsg tc;

	if (sizeof(tc) > buflen)
		return 0;
	tc.tcm_family = rand_family();
	tc.tcm__pad1 = 0;
	tc.tcm__pad2 = 0;
	tc.tcm_ifindex = rnd_modulo_u32(64);
	tc.tcm_handle = rand32();
	tc.tcm_parent = rand32();
	tc.tcm_info = rand32();
	*out_family = tc.tcm_family;
	memcpy(body, &tc, sizeof(tc));
	return sizeof(tc);
}

/* Everything else: struct rtgenmsg (1 byte) */
static size_t gen_rtnl_body_gen(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct rtgenmsg gen;

	if (sizeof(gen) > buflen)
		return 0;
	gen.rtgen_family = rand_family();
	*out_family = gen.rtgen_family;
	memcpy(body, &gen, sizeof(gen));
	return sizeof(gen);
}

/*
 * Generate a protocol-specific body for rtnetlink messages.
 * The kernel validates these structs before processing attrs, so
 * random bytes get rejected immediately. Using proper structs with
 * fuzzed fields gets past validation into interesting code paths.
 *
 * Returns the body length written. Caller must ensure buf has enough
 * room (at least sizeof(struct tcmsg) = 20 bytes).
 */
static size_t gen_rtnl_body(unsigned char *body, unsigned short nlmsg_type,
			    size_t buflen, unsigned char *out_family)
{
	/* Map RTM type to its base: RTM_*LINK=16-19, RTM_*ADDR=20-23, etc.
	 * Each group of 4 shares the same body struct. */
	unsigned int group = (nlmsg_type - RTM_BASE) / 4;

	switch (group) {
	case 0:  /* RTM_*LINK */
	case 23: /* RTM_*LINKPROP -- rtnl_linkprop shares struct ifinfomsg */
		return gen_rtnl_body_link(body, buflen, out_family);
	case 1:  return gen_rtnl_body_addr(body, buflen, out_family);
	case 2:  return gen_rtnl_body_route(body, buflen, out_family);
	case 3:  return gen_rtnl_body_neigh(body, buflen, out_family);
	case 4:  return gen_rtnl_body_rule(body, buflen, out_family);
	case 8:  return gen_rtnl_body_action(body, buflen, out_family);
	case 9:  return gen_rtnl_body_prefix(body, buflen, out_family);
	case 12: return gen_rtnl_body_neightbl(body, buflen, out_family);
	case 13: return gen_rtnl_body_nduseropt(body, buflen, out_family);
	case 14: return gen_rtnl_body_addrlabel(body, buflen, out_family);
	case 15: return gen_rtnl_body_dcb(body, buflen, out_family);
	case 16: return gen_rtnl_body_netconf(body, buflen, out_family);
	case 17: return gen_rtnl_body_mdb(body, buflen, out_family);
	case 18: return gen_rtnl_body_gen(body, buflen, out_family);
	case 24: return gen_rtnl_body_vlan(body, buflen, out_family);
	case 19: return gen_rtnl_body_stats(body, buflen, out_family);
	case 22: /* RTM_*NEXTHOP */
	case 25: /* RTM_*NEXTHOPBUCKET */
		return gen_rtnl_body_nexthop(body, buflen, out_family);
	case 26: return gen_rtnl_body_tunnel(body, buflen, out_family);
	case 5:  /* RTM_*QDISC */
	case 6:  /* RTM_*TCLASS */
	case 7:  /* RTM_*TFILTER */
	case 21: /* RTM_*CHAIN */
		return gen_rtnl_body_tc(body, buflen, out_family);
	default: return gen_rtnl_body_gen(body, buflen, out_family);
	}
}

/*
 * Generate body for NETLINK_GENERIC messages.
 * All genl messages have a genlmsghdr (4 bytes) immediately after nlmsghdr.
 * Some families (openvswitch's six, for example) declare a non-zero
 * family->hdrsize that the kernel skips past before walking attributes —
 * for those we append fam->hdrsize random bytes after the genlmsghdr so
 * the per-cmd attribute parser sees TLVs at the offset it expects.
 * For the controller (GENL_ID_CTRL), we pick from CTRL_CMD_* commands.
 * For other families, we use random cmd values since we don't know
 * which families are loaded at runtime.
 */
static size_t gen_genl_body(unsigned char *body, unsigned short nlmsg_type,
			    size_t buflen)
{
	const struct genl_family_grammar *fam = NULL;
	struct genlmsghdr genl;
	size_t len;

	if (sizeof(genl) > buflen)
		return 0;

	if (nlmsg_type == GENL_ID_CTRL) {
		/* Controller commands: GETFAMILY is the most useful */
		genl.cmd = RAND_RANGE(CTRL_CMD_UNSPEC, CTRL_CMD_MAX);
		genl.version = RAND_BOOL() ? 1 : rnd_modulo_u32(4);
	} else if ((fam = genl_lookup_by_id(nlmsg_type)) != NULL) {
		/* Resolved family: pick a known cmd from its grammar so the
		 * family's command dispatcher accepts it.  Use the family's
		 * preferred version when set so the version gate also
		 * passes; the kernel-side check is usually >= so a small
		 * version is fine. */
		genl.cmd = genl_pick_cmd(fam);
		genl.version = fam->default_version ? fam->default_version : 1;
		genl_family_bump_calls(fam);
	} else {
		/* Unknown family: random command, biased toward low values */
		if (RAND_BOOL())
			genl.cmd = rnd_modulo_u32(16);
		else
			genl.cmd = rnd_modulo_u32(256);
		genl.version = RAND_BOOL() ? 1 : rnd_modulo_u32(4);
	}
	/* reserved: usually 0, but fuzz it sometimes to test validation */
	genl.reserved = ONE_IN(4) ? rand16() : 0;

	memcpy(body, &genl, sizeof(genl));
	len = sizeof(genl);

	if (fam && fam->hdrsize) {
		if (len + fam->hdrsize > buflen)
			return len;
		generate_rand_bytes(body + len, fam->hdrsize);
		return len + fam->hdrsize;
	}
	return len;
}

/* Pick an nlattr type for genl controller messages.  Reads through the
 * ctrl_specs spec table; the legacy flat-attr code path still needs a
 * raw nla_type when nesting a NETLINK_GENERIC controller attr via
 * append_nested_attr_container().  The spec-driven path bypasses this. */
static unsigned short pick_genl_attr_type(unsigned short nlmsg_type)
{
	if (nlmsg_type == GENL_ID_CTRL)
		return ctrl_specs[rnd_modulo_u32(ctrl_specs_n)].type;
	return 0; /* unknown family: fall back to random */
}

/*
 * Generate body for NETLINK_NETFILTER messages.
 * nfnetlink messages have a nfgenmsg (4 bytes) after nlmsghdr.
 * The nlmsg_type encodes subsystem << 8 | message.  After building
 * the body, bump the per-subsys dispatch counter so the live
 * subsystem mix is visible in the periodic stats dump and end-of-run
 * summary; bump degrades to a no-op when nlmsg_type's high byte
 * doesn't match any registered subsys.
 */
static size_t gen_nfnl_body(unsigned char *body, unsigned short nlmsg_type,
			    size_t buflen)
{
	struct nfgenmsg nfg;
	static const unsigned char nf_families[] = {
		AF_INET, AF_INET6, AF_BRIDGE, AF_UNSPEC,
	};

	if (sizeof(nfg) > buflen)
		return 0;

	if (ONE_IN(8))
		nfg.nfgen_family = rnd_modulo_u32(256);
	else
		nfg.nfgen_family = RAND_ARRAY(nf_families);
	nfg.version = RAND_BOOL() ? NFNETLINK_V0 : rnd_modulo_u32(4);
	nfg.res_id = ONE_IN(4) ? rand16() : 0;

	memcpy(body, &nfg, sizeof(nfg));
	nfnl_subsys_bump_calls(nfnl_lookup_by_subsys(nlmsg_type >> 8));
	return sizeof(nfg);
}

static void xfrm_pin_family(unsigned char *body, size_t body_len,
			    unsigned short nlmsg_type)
{
	unsigned char family = RAND_BOOL() ? AF_INET : AF_INET6;
	unsigned int i;

	for (i = 0; i < xfrm_family_offsets_n; i++) {
		if (xfrm_family_offsets[i].msg_type != nlmsg_type)
			continue;
		if (xfrm_family_offsets[i].family_offset + 1 < body_len) {
			body[xfrm_family_offsets[i].family_offset] = family;
			body[xfrm_family_offsets[i].family_offset + 1] = 0;
		}
		if (xfrm_family_offsets[i].sel_family_offset != ~0u &&
		    xfrm_family_offsets[i].sel_family_offset + 1 < body_len) {
			body[xfrm_family_offsets[i].sel_family_offset] = family;
			body[xfrm_family_offsets[i].sel_family_offset + 1] = 0;
		}
		return;
	}
}

/*
 * Generate body for NETLINK_XFRM messages.
 * Body struct varies by message type. The big structs (xfrm_usersa_info
 * at 224 bytes, xfrm_userpolicy_info at 168 bytes) are filled with
 * random data of the correct size. Getting the size right is what
 * matters — it gets us past the initial copy_from_user length check
 * into the deeper validation code where the interesting bugs live.
 */
static size_t gen_xfrm_body(unsigned char *body, unsigned short nlmsg_type,
			    size_t buflen)
{
	size_t body_len;

	switch (nlmsg_type) {
	case XFRM_MSG_NEWSA:
	case XFRM_MSG_UPDSA:
		body_len = sizeof(struct xfrm_usersa_info);
		break;
	case XFRM_MSG_DELSA:
	case XFRM_MSG_GETSA:
		body_len = sizeof(struct xfrm_usersa_id);
		break;
	case XFRM_MSG_NEWPOLICY:
	case XFRM_MSG_UPDPOLICY:
		body_len = sizeof(struct xfrm_userpolicy_info);
		break;
	case XFRM_MSG_DELPOLICY:
	case XFRM_MSG_GETPOLICY:
		body_len = sizeof(struct xfrm_userpolicy_id);
		break;
	case XFRM_MSG_ALLOCSPI:
		body_len = sizeof(struct xfrm_userspi_info);
		break;
	case XFRM_MSG_ACQUIRE:
		body_len = sizeof(struct xfrm_user_acquire);
		break;
	case XFRM_MSG_EXPIRE:
		body_len = sizeof(struct xfrm_user_expire);
		break;
	case XFRM_MSG_POLEXPIRE:
		body_len = sizeof(struct xfrm_user_polexpire);
		break;
	case XFRM_MSG_FLUSHSA:
		body_len = sizeof(struct xfrm_usersa_flush);
		break;
	case XFRM_MSG_FLUSHPOLICY:
		body_len = 0; /* no body */
		break;
	case XFRM_MSG_NEWAE:
	case XFRM_MSG_GETAE:
		body_len = sizeof(struct xfrm_aevent_id);
		break;
	case XFRM_MSG_MIGRATE:
		body_len = sizeof(struct xfrm_user_migrate);
		break;
	case XFRM_MSG_GETSADINFO:
	case XFRM_MSG_GETSPDINFO:
	case XFRM_MSG_NEWSADINFO:
	case XFRM_MSG_NEWSPDINFO:
		body_len = sizeof(__u32);
		break;
	case XFRM_MSG_SETDEFAULT:
	case XFRM_MSG_GETDEFAULT:
		body_len = sizeof(struct xfrm_userpolicy_default);
		break;
	case XFRM_MSG_MAPPING:
		body_len = sizeof(struct xfrm_user_mapping);
		break;
	case XFRM_MSG_REPORT:
		body_len = sizeof(struct xfrm_user_report);
		break;
	default:
		/* Unknown xfrm type: random body */
		body_len = RAND_RANGE(4, 32);
		break;
	}

	if (body_len > buflen)
		return 0;
	if (body_len > 0) {
		generate_rand_bytes(body, body_len);
		xfrm_pin_family(body, body_len, nlmsg_type);
	}
	return body_len;
}

/*
 * Generate body for NETLINK_AUDIT messages.
 * Audit is special: it doesn't use nlattr TLVs. Message payloads are
 * either binary structs (audit_status, audit_rule_data) or raw text.
 * The caller should skip nlattr generation for audit messages.
 */
static size_t gen_audit_body(unsigned char *body, unsigned short nlmsg_type,
			     size_t buflen)
{
	size_t body_len;

	switch (nlmsg_type) {
	case AUDIT_GET:
		/* GET takes no body (kernel ignores payload) */
		return 0;
	case AUDIT_SET:
		body_len = sizeof(struct audit_status);
		break;
	case AUDIT_ADD_RULE:
	case AUDIT_DEL_RULE:
	case AUDIT_LIST_RULES: {
		/*
		 * audit_rule_data is 1040 bytes base + variable buf[].
		 * Generate the fixed part with fuzzed fields and a small
		 * random buffer extension.
		 */
		size_t extra = rnd_modulo_u32(64);
		body_len = sizeof(struct audit_rule_data) + extra;
		if (body_len > buflen)
			body_len = buflen;
		generate_rand_bytes(body, body_len);
		return body_len;
	}
	case AUDIT_USER:
	case AUDIT_LOGIN:
		/* Raw text payload */
		body_len = RAND_RANGE(4, 128);
		if (body_len > buflen)
			body_len = buflen;
		generate_rand_bytes(body, body_len);
		return body_len;
	case AUDIT_TTY_GET:
	case AUDIT_TTY_SET:
	case AUDIT_GET_FEATURE:
	case AUDIT_SET_FEATURE:
		body_len = sizeof(struct audit_status);
		break;
	case AUDIT_SIGNAL_INFO:
		return 0; /* no body for get requests */
	case AUDIT_TRIM:
		return 0; /* no body */
	case AUDIT_MAKE_EQUIV:
		/* Two paths separated by NUL */
		body_len = RAND_RANGE(4, 64);
		if (body_len > buflen)
			body_len = buflen;
		generate_rand_bytes(body, body_len);
		return body_len;
	default:
		body_len = RAND_RANGE(4, 64);
		if (body_len > buflen)
			body_len = buflen;
		generate_rand_bytes(body, body_len);
		return body_len;
	}

	if (body_len > buflen)
		body_len = buflen;
	generate_rand_bytes(body, body_len);
	return body_len;
}

/*
 * Generate body for NETLINK_SOCK_DIAG messages.
 * Two main message types:
 * - SOCK_DIAG_BY_FAMILY (20): generic sock_diag_req, then the kernel
 *   dispatches to per-family handlers based on sdiag_family.
 * - SOCK_DESTROY (21): inet_diag_req_v2 with socket identification.
 * - Legacy types (< 20): inet_diag_req_v2.
 */
static size_t gen_sockdiag_body(unsigned char *body,
				unsigned short nlmsg_type, size_t buflen)
{
	switch (nlmsg_type) {
	case SOCK_DIAG_BY_FAMILY: {
		struct sock_diag_req req;

		if (sizeof(req) > buflen)
			return 0;
		req.sdiag_family = rand_family();
		req.sdiag_protocol = rnd_modulo_u32(256);
		memcpy(body, &req, sizeof(req));
		return sizeof(req);
	}
	default: {
		/*
		 * SOCK_DESTROY and legacy inet_diag types use
		 * inet_diag_req_v2 (56 bytes). Fill with random data
		 * but set sdiag_family to something useful.
		 */
		struct inet_diag_req_v2 req;

		if (sizeof(req) > buflen)
			return 0;
		generate_rand_bytes((unsigned char *)&req, sizeof(req));
		req.sdiag_family = rand_family();
		req.sdiag_protocol = rnd_modulo_u32(256);
		memcpy(body, &req, sizeof(req));
		return sizeof(req);
	}
	}
}

/*
 * Build a structured netlink message. The caller must free *buf.
 *
 * Structure: [nlmsghdr][protocol body][nlattr...nlattr]
 *
 * Protocol bodies are generated per-family: rtnetlink uses the correct
 * struct (ifinfomsg, rtmsg, etc.), genl uses genlmsghdr, nfnetlink uses
 * nfgenmsg, xfrm uses per-type structs, audit uses binary structs or
 * text, and sock_diag uses inet_diag_req_v2. Unknown protocols fall
 * back to random bytes.
 *
 * ~1 in 4 messages are multi-message batches (2-4 nlmsghdr chained
 * together) to exercise the kernel's NLMSG_NEXT iteration path.
 */

/*
 * Pick a protocol-appropriate nlattr type for the given netlink protocol
 * and message type.  Returns 0 when the family has no curated table, in
 * which case the caller should fall back to a random type.  Centralised
 * here so both the flat append path and the nested container helper draw
 * from the same per-family tables.
 */
static unsigned short pick_attr_hint(int protocol, unsigned short nlmsg_type)
{
	switch (protocol) {
	case NETLINK_ROUTE:
		return pick_rtnl_attr_type(nlmsg_type);
	case NETLINK_GENERIC:
		return pick_genl_attr_type(nlmsg_type);
	default:
		/* XFRM, SOCK_DIAG, ctnetlink, nftables, genl-ctrl now have
		 * dedicated nla_attr_spec tables consulted directly by
		 * build_one_nlmsg, so they no longer need a raw type pick
		 * here.  Anything that lands in this default returns 0 and
		 * the caller falls back to a random type. */
		return 0;
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
static size_t append_nested_attr_container(unsigned char *buf, size_t offset,
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

/*
 * Compute payload length implied by an nla_attr_spec.  Variable-length
 * kinds (STRING, BINARY) draw a length in [4, max_len], or just take
 * max_len when it's already <= 4.
 */
static size_t spec_payload_len(const struct nla_attr_spec *spec)
{
	switch (spec->kind) {
	case NLA_KIND_U8:	return 1;
	case NLA_KIND_U16:	return 2;
	case NLA_KIND_U32:	return 4;
	case NLA_KIND_U64:	return 8;
	case NLA_KIND_FLAG:	return 0;
	case NLA_KIND_STRING:
	case NLA_KIND_STRING_CPULIST:
	case NLA_KIND_BINARY: {
		unsigned int lo = spec->min_len > 4 ? spec->min_len : 4;

		if (spec->max_len > lo)
			return RAND_RANGE(lo, spec->max_len);
		return spec->max_len;
	}
	case NLA_KIND_BINARY_FIXED2:
		return ONE_IN(2) ? spec->min_len : spec->max_len;
	case NLA_KIND_NESTED:
		/* Caller decides — nested kinds get a recursive emission */
		return 0;
	default:
		return 0;
	}
}

/*
 * Fill a payload buffer per spec kind: STRING gets NUL-terminated random
 * lowercase ASCII (the typical shape of names like NFTA_TABLE_NAME or
 * IFLA_INFO_KIND), everything else gets random bytes.
 */
static void spec_fill_payload(unsigned char *p, size_t len,
			      const struct nla_attr_spec *spec)
{
	if (len == 0)
		return;
	if (spec->kind == NLA_KIND_STRING) {
		size_t i;

		for (i = 0; i + 1 < len; i++)
			p[i] = 'a' + (rnd_modulo_u32(26));
		p[len - 1] = '\0';
	} else if (spec->kind == NLA_KIND_STRING_CPULIST) {
		gen_cpu_list_string((char *)p, (unsigned int)len);
		/* Force NUL termination inside the on-wire payload so
		 * cpulist_parse() can't run past the attribute. */
		p[len - 1] = '\0';
	} else {
		generate_rand_bytes(p, len);
	}
}

/*
 * Emit a single attribute described by a freshly picked spec, treating
 * NESTED as a small binary payload.  Used inside append_specced_nested
 * so children stay one level deep — matches the depth limit set by
 * commit "net/netlink: add nested NLA_F_NESTED attribute support".
 */
static size_t append_specced_flat(unsigned char *buf, size_t offset,
				  size_t buflen,
				  const struct nla_attr_spec *table,
				  size_t nr_specs)
{
	const struct nla_attr_spec *spec;
	struct nlattr nla;
	size_t payload_len;
	size_t total;

	if (!table || nr_specs == 0)
		return offset;
	if (offset + NLA_HDRLEN > buflen)
		return offset;

	spec = &table[rnd_modulo_u32(nr_specs)];

	if (spec->kind == NLA_KIND_NESTED)
		payload_len = 16;	/* placeholder bytes — no recursion */
	else
		payload_len = spec_payload_len(spec);

	/* Cap any single child inside a nested container at 64 bytes so
	 * one greedy STRING/BINARY can't push out the rest of the
	 * children.  The kernel-side nla_strlen / max_len gates only care
	 * about the upper bound of each individual attr, not the sum. */
	if (payload_len > 64)
		payload_len = 64;

	total = NLA_ALIGN(NLA_HDRLEN + payload_len);
	if (offset + total > buflen) {
		if (buflen - offset < NLA_HDRLEN)
			return offset;
		total = buflen - offset;
		payload_len = total - NLA_HDRLEN;
	}

	nla.nla_len = NLA_HDRLEN + payload_len;
	nla.nla_type = spec->type;
	memcpy(buf + offset, &nla, NLA_HDRLEN);
	spec_fill_payload(buf + offset + NLA_HDRLEN, payload_len, spec);

	return offset + total;
}

/*
 * Emit a NLA_F_NESTED outer attr whose payload is 1-3 children drawn
 * from the same spec table.  Mirrors append_nested_attr_container() but
 * walks a typed spec table for kind/max_len information.  Increments
 * the same nested counter so the dump output stays consistent across
 * spec-driven and pick_attr_hint-driven nesting.
 */
static size_t append_specced_nested(unsigned char *buf, size_t offset,
				    size_t buflen,
				    unsigned short outer_type,
				    const struct nla_attr_spec *table,
				    size_t nr_specs)
{
	struct nlattr nla;
	unsigned char *inner;
	size_t inner_avail;
	size_t inner_off = 0;
	size_t total;
	int child_count;

	if (offset + NLA_HDRLEN + NLA_HDRLEN + 4 > buflen)
		return offset;

	inner = buf + offset + NLA_HDRLEN;
	inner_avail = buflen - offset - NLA_HDRLEN;
	if (inner_avail > 256)
		inner_avail = 256;

	child_count = RAND_RANGE(1, 3);
	while (child_count-- > 0) {
		size_t new_off = append_specced_flat(inner, inner_off,
						     inner_avail,
						     table, nr_specs);
		if (new_off == inner_off)
			break;
		inner_off = new_off;
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

/*
 * Top-level entry for spec-driven attribute emission.  Picks a random
 * spec and delegates to the nested or flat path as appropriate.  Used
 * exclusively by build_one_nlmsg for families with a curated
 * nla_attr_spec table; the legacy random-payload append_nlattr() path
 * still serves families without specs.
 */
static size_t append_specced_nlattr(unsigned char *buf, size_t offset,
				    size_t buflen,
				    const struct nla_attr_spec *table,
				    size_t nr_specs)
{
	const struct nla_attr_spec *spec;
	struct nlattr nla;
	size_t payload_len;
	size_t total;

	if (!table || nr_specs == 0)
		return offset;
	if (offset + NLA_HDRLEN > buflen)
		return offset;

	spec = &table[rnd_modulo_u32(nr_specs)];

	if (spec->kind == NLA_KIND_NESTED)
		return append_specced_nested(buf, offset, buflen, spec->type,
					     table, nr_specs);

	payload_len = spec_payload_len(spec);

	total = NLA_ALIGN(NLA_HDRLEN + payload_len);
	if (offset + total > buflen) {
		if (buflen - offset < NLA_HDRLEN)
			return offset;
		total = buflen - offset;
		payload_len = total - NLA_HDRLEN;
	}

	nla.nla_len = NLA_HDRLEN + payload_len;
	nla.nla_type = spec->type;
	memcpy(buf + offset, &nla, NLA_HDRLEN);
	spec_fill_payload(buf + offset + NLA_HDRLEN, payload_len, spec);

	return offset + total;
}

/*
 * Return the nla_attr_spec table for a given protocol/nlmsg_type pair,
 * setting *nr_out to its element count.  NULL means the family is not
 * spec-aware and the caller should fall back to the legacy flat-attr
 * generator.  Netfilter dispatches by NFNL_SUBSYS_x nibble of
 * nlmsg_type via the per-subsys grammar registry; generic netlink
 * dispatches by runtime-resolved family_id via the genl registry.
 */
static const struct nla_attr_spec *pick_spec_table(int protocol,
						   unsigned short nlmsg_type,
						   size_t *nr_out)
{
	switch (protocol) {
	case NETLINK_GENERIC: {
		const struct genl_family_grammar *fam;

		if (nlmsg_type == GENL_ID_CTRL) {
			*nr_out = ctrl_specs_n;
			return ctrl_specs;
		}
		fam = genl_lookup_by_id(nlmsg_type);
		if (fam != NULL && fam->n_attrs > 0) {
			*nr_out = fam->n_attrs;
			return fam->attrs;
		}
		return NULL;
	}
	case NETLINK_XFRM:
		*nr_out = xfrma_specs_n;
		return xfrma_specs;
	case NETLINK_NETFILTER: {
		const struct nfnl_subsys_grammar *sub;

		sub = nfnl_lookup_by_subsys(nlmsg_type >> 8);
		if (sub != NULL && sub->n_attrs > 0) {
			*nr_out = sub->n_attrs;
			return sub->attrs;
		}
		return NULL;
	}
	case NETLINK_SOCK_DIAG:
		*nr_out = inet_diag_specs_n;
		return inet_diag_specs;
	default:
		return NULL;
	}
}

/* Build a single nlmsghdr at msg+offset. Returns new offset (NLMSG_ALIGN'd). */
/*
 * Single iteration of build_one_nlmsg()'s inner attr-append loop.
 * Returns the new offset, or 0 to signal "no progress, caller break".
 * 0 is an unambiguous sentinel here because the caller has already
 * advanced offset past NLMSG_HDRLEN before the loop runs.
 */
static size_t iter_nlmsg_attr(unsigned char *msg, size_t offset, size_t buflen,
			      const struct nla_attr_spec *spec_table,
			      size_t nr_specs,
			      struct socket_triplet *triplet,
			      unsigned short nlmsg_type,
			      unsigned char body_family,
			      int rtnl_group)
{
	unsigned short attr_hint;
	size_t new_off;

	/* Spec-driven path: families with a curated nla_attr_spec table
	 * (XFRM, ctnetlink, nftables, genl-ctrl, sock_diag) emit attrs
	 * sized to their per-type kind.  This dramatically lowers the
	 * EINVAL rejection rate at the family's nla_policy gate. */
	if (spec_table) {
		new_off = append_specced_nlattr(msg, offset, buflen,
						spec_table, nr_specs);
		if (new_off == offset)
			return 0;
		return new_off;
	}

	/* Legacy random-payload path for families without a spec table —
	 * currently NETLINK_ROUTE (which has its own structured per-group
	 * payload generators) and unknown families. */
	attr_hint = pick_attr_hint(triplet->protocol, nlmsg_type);

	if (ONE_IN(7)) {
		unsigned short outer = attr_hint ? attr_hint : rand16();

		new_off = append_nested_attr_container(msg, offset, buflen,
						       outer,
						       triplet->protocol,
						       nlmsg_type, body_family,
						       rtnl_group);
		if (new_off > offset)
			return new_off;
	}

	return append_nlattr(msg, offset, buflen, attr_hint,
			     body_family, rtnl_group);
}

static size_t build_one_nlmsg(unsigned char *msg, size_t offset, size_t buflen,
			      struct socket_triplet *triplet)
{
	struct nlmsghdr *nlh;
	unsigned short nlmsg_type;
	size_t body_len;
	size_t msg_start = offset;
	unsigned char body_family = AF_UNSPEC;
	int rtnl_group = -1;
	int num_attrs;

	/* Floor: nlmsghdr + genlmsghdr + a small per-family fixed header.
	 * Real buffers are >=1280 bytes so this is just a sanity gate. */
	if (offset + NLMSG_HDRLEN + 8 > buflen)
		return offset;

	nlmsg_type = pick_nlmsg_type(triplet->protocol);

	nlh = (struct nlmsghdr *) (msg + offset);
	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_flags = gen_nlmsg_flags();
	nlh->nlmsg_seq = rand32();
	nlh->nlmsg_pid = RAND_BOOL() ? 0 : rand32();

	offset += NLMSG_HDRLEN;

	/* Generate protocol-appropriate body struct */
	if (triplet->protocol == NETLINK_ROUTE &&
	    nlmsg_type >= RTM_BASE && nlmsg_type < RTM_MAX) {
		body_len = gen_rtnl_body(msg + offset, nlmsg_type,
					 buflen - offset, &body_family);
		rtnl_group = (nlmsg_type - RTM_BASE) / 4;
	} else if (triplet->protocol == NETLINK_GENERIC) {
		body_len = gen_genl_body(msg + offset, nlmsg_type,
					 buflen - offset);
	} else if (triplet->protocol == NETLINK_NETFILTER) {
		body_len = gen_nfnl_body(msg + offset, nlmsg_type,
					 buflen - offset);
	} else if (triplet->protocol == NETLINK_XFRM) {
		body_len = gen_xfrm_body(msg + offset, nlmsg_type,
					 buflen - offset);
	} else if (triplet->protocol == NETLINK_AUDIT) {
		body_len = gen_audit_body(msg + offset, nlmsg_type,
					  buflen - offset);
	} else if (triplet->protocol == NETLINK_SOCK_DIAG) {
		body_len = gen_sockdiag_body(msg + offset, nlmsg_type,
					     buflen - offset);
	} else {
		body_len = RAND_RANGE(4, 64);
		if (offset + body_len > buflen)
			body_len = buflen - offset;
		generate_rand_bytes(msg + offset, body_len);
	}
	offset += body_len;

	/* Append nlattr TLVs with protocol-appropriate types.
	 * Audit messages don't use nlattr — skip for that protocol. */
	num_attrs = (triplet->protocol == NETLINK_AUDIT) ? 0 : rnd_modulo_u32(8);
	if (num_attrs > 0) {
		const struct nla_attr_spec *spec_table;
		size_t nr_specs = 0;

		spec_table = pick_spec_table(triplet->protocol, nlmsg_type,
					     &nr_specs);

		while (num_attrs-- > 0 && offset < buflen) {
			size_t new_off = iter_nlmsg_attr(msg, offset, buflen,
							 spec_table, nr_specs,
							 triplet, nlmsg_type,
							 body_family,
							 rtnl_group);
			if (new_off == 0)
				break;
			offset = new_off;
		}
	}

	/* Set nlmsg_len — usually correct, sometimes corrupted */
	if (ONE_IN(10)) {
		switch (rnd_modulo_u32(5)) {
		case 0: nlh->nlmsg_len = 0; break;
		case 1: nlh->nlmsg_len = NLMSG_HDRLEN - 1; break;
		case 2: nlh->nlmsg_len = (offset - msg_start) * 2; break;
		case 3: nlh->nlmsg_len = rand32(); break;
		case 4: /* understate by K — leave K trailing bytes for the next NLMSG_NEXT walk */
			nlh->nlmsg_len = (offset - msg_start) - RAND_RANGE(NLMSG_HDRLEN, 64);
			break;
		}
	} else {
		nlh->nlmsg_len = offset - msg_start;
	}

	/* NLMSG_ALIGN for chaining; clamp at buflen so a downstream
	 * memcpy(gen_buf, gen_len) can never over-read the allocation when
	 * total_len is not a multiple of NLMSG_ALIGNTO. */
	size_t aligned = NLMSG_ALIGN(offset);
	return aligned > buflen ? buflen : aligned;
}

void netlink_gen_msg(struct socket_triplet *triplet, void **buf, size_t *len)
{
	size_t total_len;
	size_t offset;
	unsigned char *msg;
	int num_msgs;

	/* Total buffer: room for messages with protocol body + attrs.
	 * XFRM bodies can be up to 280 bytes, audit_rule_data is 1040 bytes,
	 * so base size must accommodate the largest possible body. */
	total_len = NLMSG_HDRLEN + 1280 + (rnd_modulo_u32(512));
	/* Multi-message batches need more space */
	if (ONE_IN(4)) {
		num_msgs = RAND_RANGE(2, 4);
		total_len *= num_msgs;
	} else {
		num_msgs = 1;
	}
	if (total_len > 8192)
		total_len = 8192;

	msg = zmalloc(total_len);

	offset = 0;
	while (num_msgs-- > 0 && offset < total_len)
		offset = build_one_nlmsg(msg, offset, total_len, triplet);

	*buf = msg;
	*len = offset;
}
