/*
 * Rtnetlink body-struct builders split out of net/netlink/msg.c.
 *
 * Each RTM_* message group carries a small fixed struct (ifinfomsg,
 * rtmsg, ndmsg, ...) immediately after the nlmsghdr; the kernel
 * validates its length and family byte before parsing attributes.
 * The per-group builders here fill each struct with fuzzed field
 * values of the correct size so validation lets us through into the
 * attribute walker where the interesting bugs live.
 *
 * rand_family() is shared with the sock_diag body builder in
 * msg-proto-body.c, so its declaration lives in msg-internal.h with
 * external linkage; the router gen_rtnl_body() is also declared in
 * msg-internal.h and dispatched from build_one_nlmsg() in msg.c.
 */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <string.h>
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
