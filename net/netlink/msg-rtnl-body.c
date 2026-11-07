/*
 * Rtnetlink body-struct builders: the fixed struct each RTM_* group carries
 * after the nlmsghdr (ifinfomsg, rtmsg, ndmsg, ...), filled with fuzzed
 * fields of the right size so the kernel's length and family checks pass and
 * the message reaches the attribute walker.
 */
#include <sys/socket.h>
#include <stddef.h>
#include <string.h>
#include <netinet/ip.h>
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
#include "msg-internal.h"
#include "random.h"
#include "rnd.h"
#include "utils.h"

unsigned char rand_family(void)
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

/*
 * RTM_*ADDR: struct ifaddrmsg.  On a socket that asks for strict checking,
 * the IPv4 and IPv6 address dumps and the IPv6 doit refuse a GET with a
 * nonzero prefixlen, flags or scope, and the dumps one whose index names no
 * device; without strict checking a GET reads none of the three.  So a GET
 * has them 0 seven times in eight, and an index for every device, lo or a
 * small one, as the multicast dump does.
 */
static size_t gen_rtnl_body_addr(unsigned char *body, size_t buflen, bool get,
				 unsigned char *out_family)
{
	struct ifaddrmsg ifa = { 0 };

	if (sizeof(ifa) > buflen)
		return 0;
	ifa.ifa_family = rand_family();
	if (!get || ONE_IN(8)) {
		ifa.ifa_prefixlen = rnd_modulo_u32(129);
		ifa.ifa_flags = rnd_modulo_u32(256);
		ifa.ifa_scope = rnd_modulo_u32(256);
	}
	if (get)
		ifa.ifa_index = RAND_BOOL() ? 0 : RAND_BOOL() ? 1 : rnd_modulo_u32(64);
	else
		ifa.ifa_index = rnd_modulo_u32(64);
	/* An add or a delete has a handler under AF_INET and AF_INET6, and
	 * phonet's and MCTP's, which answer an index that names no device
	 * -ENODEV, and inet_validate_rtm() refuses an IPv4 add with a prefix
	 * past 32 bits.  It keeps to that seven times in eight, and names lo
	 * half of those. */
	if (!get && !ONE_IN(8)) {
		ifa.ifa_family = RAND_BOOL() ? AF_INET : AF_INET6;
		if (ifa.ifa_family == AF_INET)
			ifa.ifa_prefixlen = rnd_modulo_u32(33);
		ifa.ifa_index = RAND_BOOL() ? 1 : rnd_modulo_u32(64);
	}
	*out_family = ifa.ifa_family;
	memcpy(body, &ifa, sizeof(ifa));
	return sizeof(ifa);
}

/*
 * RTM_*MULTICAST and RTM_*ANYCAST: the struct ifaddrmsg of an address dump.
 * Both are dumps with no doit.  RTM_GETMULTICAST has a dumpit for PF_INET,
 * PF_INET6 and PF_PACKET, whose dev_mc_dump() in net/core/dev_addr_lists.c
 * answers a header with a nonzero prefixlen, flags or scope -EINVAL and
 * dumps the one device ifa_index names, or all of them for 0, and
 * RTM_GETANYCAST one for PF_INET6 alone.  So a request names AF_PACKET
 * three times in four for the first, the other two a quarter between them,
 * and AF_INET6 for the second, but one in sixteen takes any family.  The
 * prefixlen, flags and scope are 0 seven times in eight.
 */
static size_t gen_rtnl_body_addr_dump(unsigned char *body, size_t buflen, bool anycast,
				      unsigned char *out_family)
{
	struct ifaddrmsg ifa = { 0 };

	if (sizeof(ifa) > buflen)
		return 0;
	if (ONE_IN(16))
		ifa.ifa_family = rand_family();
	else if (anycast)
		ifa.ifa_family = AF_INET6;
	else if (ONE_IN(4))
		ifa.ifa_family = RAND_BOOL() ? AF_INET : AF_INET6;
	else
		ifa.ifa_family = AF_PACKET;
	if (ONE_IN(8)) {
		ifa.ifa_prefixlen = rnd_modulo_u32(129);
		ifa.ifa_flags = rnd_modulo_u32(256);
		ifa.ifa_scope = rnd_modulo_u32(256);
	}
	/* Every device, or lo, which every netns has, or a small index. */
	ifa.ifa_index = RAND_BOOL() ? 0 : RAND_BOOL() ? 1 : rnd_modulo_u32(64);
	*out_family = ifa.ifa_family;
	memcpy(body, &ifa, sizeof(ifa));
	return sizeof(ifa);
}

/* RTM_*ROUTE: struct rtmsg */
static size_t gen_rtnl_body_route(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	/* The scopes a route has, narrowest last. */
	static const unsigned char scopes[] = {
		RT_SCOPE_UNIVERSE, RT_SCOPE_SITE, RT_SCOPE_LINK, RT_SCOPE_HOST,
	};
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
	/* rtm_to_fib_config() refuses an IPv4 route with an ECN bit in its
	 * tos or a prefix past 32 bits, and rtm_to_fib6_config() an IPv6 one
	 * with any tos, before reading an attribute.  fib_create_info() then
	 * refuses an IPv4 route whose scope is narrower than its type's
	 * (fib_props[]: host for a local route, link for broadcast and
	 * anycast, and no scope at all for UNSPEC, NAT and XRESOLVE) or wider
	 * than host, or whose flags hold DEAD or LINKDOWN, and
	 * fib6_config_validate() an IPv6 one whose type is past RTN_MAX or
	 * whose flags hold RTM_F_CLONED, or, without CONFIG_IPV6_SUBTREES,
	 * with a source prefix, which half of them leave out.  The rtmsg
	 * stays random one time in eight. */
	if (!ONE_IN(8)) {
		if (rtm.rtm_family == AF_INET) {
			unsigned int narrowest;

			rtm.rtm_tos &= ~IPTOS_ECN_MASK;
			rtm.rtm_dst_len = rnd_modulo_u32(33);
			rtm.rtm_type = RAND_RANGE(RTN_UNICAST, RTN_THROW);
			narrowest = rtm.rtm_type == RTN_LOCAL ? 3 :
				    rtm.rtm_type == RTN_BROADCAST ||
				    rtm.rtm_type == RTN_ANYCAST ? 2 : 0;
			rtm.rtm_scope = scopes[RAND_RANGE(narrowest, ARRAY_SIZE(scopes) - 1)];
			rtm.rtm_flags &= ~(RTNH_F_DEAD | RTNH_F_LINKDOWN);
		} else if (rtm.rtm_family == AF_INET6) {
			rtm.rtm_tos = 0;
			rtm.rtm_type = rnd_modulo_u32(RTN_MAX + 1);
			rtm.rtm_flags &= ~RTM_F_CLONED;
			if (RAND_BOOL())
				rtm.rtm_src_len = 0;
		}
	}
	*out_family = rtm.rtm_family;
	memcpy(body, &rtm, sizeof(rtm));
	return sizeof(rtm);
}

/*
 * RTM_*NEIGH: struct ndmsg.  Only AF_INET and AF_INET6 have a neighbour
 * table, and AF_BRIDGE's requests go to the fdb handlers; any other family
 * is answered -EAFNOSUPPORT.  The index has to name a device, or be 0 for a
 * proxy entry or a dump, and neigh_get() and rtnl_fdb_get() refuse a
 * nonzero state or type and a flag but NTF_PROXY, or NTF_MASTER and
 * NTF_SELF for the fdb, on every socket, as the dumps do on a socket that
 * asks for strict checking.  So a request names one of the three families
 * and a GET keeps to that header seven times in eight, and the index is
 * every device, lo or a small one.
 */
static size_t gen_rtnl_body_neigh(unsigned char *body, size_t buflen, bool get,
				  unsigned char *out_family)
{
	static const unsigned char families[] = { AF_INET, AF_INET6, AF_BRIDGE };
	struct ndmsg ndm = { 0 };

	if (sizeof(ndm) > buflen)
		return 0;
	ndm.ndm_family = ONE_IN(8) ? rand_family() : RAND_ARRAY(families);
	ndm.ndm_ifindex = RAND_BOOL() ? 0 : RAND_BOOL() ? 1 : rnd_modulo_u32(64);
	if (!get || ONE_IN(8)) {
		ndm.ndm_state = rand16();
		ndm.ndm_flags = rnd_modulo_u32(256);
		ndm.ndm_type = rnd_modulo_u32(256);
	} else if (RAND_BOOL()) {
		ndm.ndm_flags = ndm.ndm_family != AF_BRIDGE ? NTF_PROXY :
				RAND_BOOL() ? NTF_MASTER : NTF_SELF;
	}
	*out_family = ndm.ndm_family;
	memcpy(body, &ndm, sizeof(ndm));
	return sizeof(ndm);
}

/* RTM_*RULE: struct fib_rule_hdr */
static size_t gen_rtnl_body_rule(unsigned char *body, size_t buflen, bool get,
				 unsigned char *out_family)
{
	/* The families with rules ops, then AF_UNSPEC, which only a dump of
	 * every family's rules takes. */
	static const unsigned char families[] = {
		AF_INET, AF_INET6, RTNL_FAMILY_IPMR, RTNL_FAMILY_IP6MR, AF_UNSPEC,
	};
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
	/* fib_newrule() and fib_delrule() answer a family with no rules ops
	 * -EAFNOSUPPORT, and fib_nl2rule() refuses a nonzero src_len or
	 * dst_len without the FRA_SRC or FRA_DST it needs, which a request
	 * carries about one time in ten.  The IPv4 and IPv6 rules refuse a
	 * tos with an ECN bit, IPv4 also one outside IPTOS_TOS_MASK, and the
	 * dump, on a socket that asks for strict checking, anything in the
	 * header but the family.  The header stays random one time in
	 * eight. */
	if (!ONE_IN(8)) {
		if (get) {
			memset(&frh, 0, sizeof(frh));
			frh.family = RAND_ARRAY(families);
		} else {
			frh.family = families[rnd_modulo_u32(ARRAY_SIZE(families) - 1)];
			frh.dst_len = 0;
			frh.src_len = 0;
			frh.tos &= ~IPTOS_ECN_MASK;
			if (frh.family == AF_INET)
				frh.tos &= IPTOS_TOS_MASK;
		}
	}
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

/* RTM_*ADDRLABEL: struct ifaddrlblmsg */
static size_t gen_rtnl_body_addrlabel(unsigned char *body, size_t buflen, bool get,
				      unsigned char *out_family)
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
	/* net/ipv6/addrlabel.c registers the three types for PF_INET6 alone,
	 * and an add and the GET doit refuse an index that names no device.
	 * The GET doit wants a prefix of 128 and, on a socket that asks for
	 * strict checking, no flags or seq, and the dump a header of zeros.
	 * The header stays random one time in eight. */
	if (!ONE_IN(8)) {
		ifal.ifal_family = AF_INET6;
		ifal.ifal_index = RAND_BOOL() ? 0 : RAND_BOOL() ? 1 : rnd_modulo_u32(64);
		if (get) {
			ifal.ifal_prefixlen = RAND_BOOL() ? 128 : 0;
			ifal.ifal_flags = 0;
			ifal.ifal_seq = 0;
		}
	}
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
static size_t gen_rtnl_body_stats(unsigned char *body, size_t buflen, bool set,
				  unsigned char *out_family)
{
	struct if_stats_msg smsg;

	if (sizeof(smsg) > buflen)
		return 0;
	memset(&smsg, 0, sizeof(smsg));
	smsg.family = rand_family();
	smsg.ifindex = rnd_modulo_u32(64);
	smsg.filter_mask = rand32();
	/* rtnl_stats_get() and rtnl_stats_set() answer an index that names no
	 * device -ENODEV, or -EINVAL for 0.  The GET and the dump refuse a
	 * filter mask of 0, and on a socket that asks for strict checking one
	 * past the IFLA_STATS_* bits, the dump then an index but 0 too; the
	 * SET refuses any filter mask and a family but AF_UNSPEC.  The header
	 * stays random one time in eight. */
	if (!ONE_IN(8)) {
		if (set) {
			smsg.family = AF_UNSPEC;
			smsg.ifindex = RAND_BOOL() ? 1 : rnd_modulo_u32(64);
			smsg.filter_mask = 0;
		} else {
			smsg.ifindex = RAND_BOOL() ? 0 : RAND_BOOL() ? 1 : rnd_modulo_u32(64);
			smsg.filter_mask = RAND_RANGE(1, IFLA_STATS_FILTER_BIT(IFLA_STATS_MAX + 1) - 1);
		}
	}
	*out_family = smsg.family;
	memcpy(body, &smsg, sizeof(smsg));
	return sizeof(smsg);
}

/*
 * RTM_*NEXTHOP / RTM_*NEXTHOPBUCKET: struct nhmsg.  rtm_to_nh_config()
 * refuses a nexthop add whose scope is nonzero, whose flags hold any but
 * RTNH_F_ONLINK or whose family is not AF_INET or AF_INET6, or AF_UNSPEC
 * for a group, and nh_valid_get_del_req() and the dumps refuse a delete or
 * a GET whose protocol, scope or flags are nonzero, on every socket.  So
 * the header keeps to that seven times in eight.
 */
static size_t gen_rtnl_body_nexthop(unsigned char *body, size_t buflen, bool add,
				    unsigned char *out_family)
{
	static const unsigned char families[] = { AF_INET, AF_INET6, AF_UNSPEC };
	struct nhmsg nh;

	if (sizeof(nh) > buflen)
		return 0;
	memset(&nh, 0, sizeof(nh));
	if (ONE_IN(8)) {
		nh.nh_family = rand_family();
		nh.nh_scope = rand32() & 0xff;
		nh.nh_protocol = rand32() & 0xff;
		nh.nh_flags = rand32();
	} else if (add) {
		nh.nh_family = RAND_ARRAY(families);
		nh.nh_protocol = rand32() & 0xff;
		nh.nh_flags = RAND_BOOL() ? RTNH_F_ONLINK : 0;
	} else {
		nh.nh_family = rand_family();
	}
	*out_family = nh.nh_family;
	memcpy(body, &nh, sizeof(nh));
	return sizeof(nh);
}

/*
 * RTM_*TUNNEL: struct tunnel_msg.  vxlan_vnifilter.c registers the three
 * types for PF_BRIDGE alone, and rtnetlink_rcv_msg() answers any other
 * family -EOPNOTSUPP; the dump refuses a flag but TUNNEL_MSG_FLAG_STATS and
 * walks every device for ifindex 0.  So a request names AF_BRIDGE but one
 * in sixteen, holds valid flags seven times in eight, and an index for
 * every device, lo or a small one.
 */
static size_t gen_rtnl_body_tunnel(unsigned char *body, size_t buflen, unsigned char *out_family)
{
	struct tunnel_msg tm;

	if (sizeof(tm) > buflen)
		return 0;
	tm.family = ONE_IN(16) ? rand_family() : AF_BRIDGE;
	tm.flags = ONE_IN(8) ? rand32() & 0xff :
		   RAND_BOOL() ? TUNNEL_MSG_FLAG_STATS : 0;
	tm.reserved2 = 0;
	tm.ifindex = RAND_BOOL() ? 0 : RAND_BOOL() ? 1 : rnd_modulo_u32(64);
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
size_t gen_rtnl_body(unsigned char *body, unsigned short nlmsg_type,
		     size_t buflen, unsigned char *out_family)
{
	/* Map RTM type to its base: RTM_*LINK=16-19, RTM_*ADDR=20-23, etc.
	 * Each group of 4 shares the same body struct. */
	unsigned int group = (nlmsg_type - RTM_BASE) / 4;

	switch (group) {
	case 0:  /* RTM_*LINK */
	case 23: /* RTM_*LINKPROP -- rtnl_linkprop shares struct ifinfomsg */
		return gen_rtnl_body_link(body, buflen, out_family);
	case 1:
		return gen_rtnl_body_addr(body, buflen, nlmsg_type == RTM_GETADDR,
					  out_family);
	case 2:  return gen_rtnl_body_route(body, buflen, out_family);
	case 3:
		return gen_rtnl_body_neigh(body, buflen, nlmsg_type == RTM_GETNEIGH,
					   out_family);
	case 4:
		return gen_rtnl_body_rule(body, buflen, nlmsg_type == RTM_GETRULE,
					  out_family);
	case 8:  return gen_rtnl_body_action(body, buflen, out_family);
	case 10: /* RTM_*MULTICAST */
	case 11: /* RTM_*ANYCAST */
		return gen_rtnl_body_addr_dump(body, buflen, group == 11, out_family);
	case 12: return gen_rtnl_body_neightbl(body, buflen, out_family);
	case 14:
		return gen_rtnl_body_addrlabel(body, buflen,
					       nlmsg_type == RTM_GETADDRLABEL,
					       out_family);
	case 15: return gen_rtnl_body_dcb(body, buflen, out_family);
	case 16: return gen_rtnl_body_netconf(body, buflen, out_family);
	case 17: return gen_rtnl_body_mdb(body, buflen, out_family);
	case 18: return gen_rtnl_body_gen(body, buflen, out_family);
	case 24: return gen_rtnl_body_vlan(body, buflen, out_family);
	case 19:
		return gen_rtnl_body_stats(body, buflen, nlmsg_type == RTM_SETSTATS,
					   out_family);
	case 22: /* RTM_*NEXTHOP */
	case 25: /* RTM_*NEXTHOPBUCKET */
		return gen_rtnl_body_nexthop(body, buflen,
					     nlmsg_type == RTM_NEWNEXTHOP,
					     out_family);
	case 26: return gen_rtnl_body_tunnel(body, buflen, out_family);
	case 5:  /* RTM_*QDISC */
	case 6:  /* RTM_*TCLASS */
	case 7:  /* RTM_*TFILTER */
	case 21: /* RTM_*CHAIN */
		return gen_rtnl_body_tc(body, buflen, out_family);
	default: return gen_rtnl_body_gen(body, buflen, out_family);
	}
}
