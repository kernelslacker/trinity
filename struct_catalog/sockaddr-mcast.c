/*
 * struct_catalog/sockaddr-mcast.c -- IPv4 / IPv6 multicast setsockopt
 * optval struct field tables (ip_mreqn / ip_mreq_source / ipv6_mreq)
 * plus the well-known multicast address pools those tables reference.
 *
 * Tables are `const` (not `static const`) so the spine's designated-init
 * `.fields =` references resolve via the externs in struct_catalog-internal.h.
 */

#include <stddef.h>
#include <netinet/in.h>
/*
 * linux/fs.h defines FILE_ATTR_SIZE_VER0 + struct file_attr; bring it
 * in before the kernel fallback header so that header's older-headers fallback for
 * struct file_attr stays inactive.  This TU does not use the type,
 * but struct_catalog.h pulls <linux/aio_abi.h> -> <linux/fs.h> below
 * and a duplicate definition would -Werror.
 */
#include <linux/fs.h>

#include "config.h"

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"
#include "utils.h"

#include "kernel/fs.h"
/*
 * struct ip_mreqn -- IPPROTO_IP / IP_{ADD,DROP}_MEMBERSHIP and
 * IP_MULTICAST_IF.  imr_multiaddr is __be32 selecting the multicast
 * group; FT_MAGIC carries a curated set of well-known IPv4 multicast
 * destinations (all-hosts, all-routers, IGMPv3, mDNS, NTP, SSM, SSDP)
 * in network byte order, so the join/leave path names a real
 * 224.0.0.0/4 group on every dispatch.  ip_mc_find_dev() takes the
 * device from a nonzero imr_ifindex, which must exist (-ENODEV), else
 * from a nonzero imr_address, which must be local, else from the
 * group's route; so the ifindex is 0 or lo's 1, which every netns
 * has, and the address unset or lo's.
 */

/* 224.0.0.1 -- all-hosts */
const unsigned char ipv4_mcast_all_hosts[4] = {
	0xe0, 0x00, 0x00, 0x01,
};

/* 224.0.0.2 -- all-routers */
const unsigned char ipv4_mcast_all_routers[4] = {
	0xe0, 0x00, 0x00, 0x02,
};

/* 224.0.0.22 -- IGMPv3 */
const unsigned char ipv4_mcast_igmpv3[4] = {
	0xe0, 0x00, 0x00, 0x16,
};

/* 224.0.0.251 -- mDNS */
const unsigned char ipv4_mcast_mdns[4] = {
	0xe0, 0x00, 0x00, 0xfb,
};

/* 224.0.1.1 -- NTP */
const unsigned char ipv4_mcast_ntp[4] = {
	0xe0, 0x00, 0x01, 0x01,
};

/* 232.0.0.1 -- SSM (source-specific multicast) sample */
const unsigned char ipv4_mcast_ssm[4] = {
	0xe8, 0x00, 0x00, 0x01,
};

/* 239.255.255.250 -- SSDP */
const unsigned char ipv4_mcast_ssdp[4] = {
	0xef, 0xff, 0xff, 0xfa,
};

const unsigned char *const ipv4_mcast_vocab[] = {
	ipv4_mcast_all_hosts,
	ipv4_mcast_all_routers,
	ipv4_mcast_igmpv3,
	ipv4_mcast_mdns,
	ipv4_mcast_ntp,
	ipv4_mcast_ssm,
	ipv4_mcast_ssdp,
};

/* 0.0.0.0 -- no address: the ifindex or the group's route picks */
const unsigned char ipv4_iface_any[4] = {
	0x00, 0x00, 0x00, 0x00,
};

/* 127.0.0.1 -- lo's */
const unsigned char ipv4_iface_lo[4] = {
	0x7f, 0x00, 0x00, 0x01,
};

const unsigned char *const ipv4_iface_vocab[] = {
	ipv4_iface_any,
	ipv4_iface_lo,
};

const struct struct_field ip_mreqn_fields[] = {
	FIELDX(struct ip_mreqn, imr_multiaddr, FT_MAGIC,
	       .u.magic = { ipv4_mcast_vocab,
			    ARRAY_SIZE(ipv4_mcast_vocab),
			    sizeof(((struct ip_mreqn *)NULL)->imr_multiaddr) }),
	FIELDX(struct ip_mreqn, imr_address, FT_MAGIC,
	       .u.magic = { ipv4_iface_vocab,
			    ARRAY_SIZE(ipv4_iface_vocab),
			    sizeof(((struct ip_mreqn *)NULL)->imr_address) }),
	FIELDX(struct ip_mreqn, imr_ifindex, FT_RANGE,
	       .u.range = { 0, 1 }),
};

/*
 * struct ip_mreq_source -- IPPROTO_IP / IP_{ADD,DROP}_SOURCE_MEMBERSHIP
 * and IP_{BLOCK,UNBLOCK}_SOURCE.  The IPv4 source-multicast sibling of
 * ip_mreqn: imr_multiaddr selects the multicast group, imr_interface
 * the local interface address, imr_sourceaddr the unicast source whose
 * membership is being added / dropped / blocked / unblocked.  These
 * calls pass ip_mc_find_dev() no ifindex, so imr_interface alone picks
 * the device, from ip_mreqn's unset-or-lo addresses; imr_sourceaddr
 * stays FT_RAW, as ip_mc_source() files any source.
 */
const struct struct_field ip_mreq_source_fields[] = {
	FIELDX(struct ip_mreq_source, imr_multiaddr, FT_MAGIC,
	       .u.magic = { ipv4_mcast_vocab,
			    ARRAY_SIZE(ipv4_mcast_vocab),
			    sizeof(((struct ip_mreq_source *)NULL)->imr_multiaddr) }),
	FIELDX(struct ip_mreq_source, imr_interface, FT_MAGIC,
	       .u.magic = { ipv4_iface_vocab,
			    ARRAY_SIZE(ipv4_iface_vocab),
			    sizeof(((struct ip_mreq_source *)NULL)->imr_interface) }),
	FIELD(struct ip_mreq_source, imr_sourceaddr),
};

/*
 * struct ipv6_mreq -- IPPROTO_IPV6 / IPV6_{ADD,DROP}_MEMBERSHIP.
 * Bespoke build_ipv6_mreq() set ipv6mr_multiaddr to a link-local
 * solicited-node address (ff02::xx) and zeroed ipv6mr_interface.
 * ipv6mr_multiaddr is struct in6_addr (16 bytes), wider than the
 * 1/2/4 widths fill_field_raw() handles, so a plain FT_RAW slot is
 * left at the zmalloc zero fill -- the IPv6 "any" address rather
 * than a real multicast group.  FT_MAGIC carries a curated set of
 * well-known IPv6 multicast destinations (all-nodes, all-routers,
 * MLDv2, solicited-node, site-local routers) in network byte order;
 * the pass-1 dispatch memcpy's one chosen 16-byte entry into the
 * field so the join/leave path names a real ff0x:: group.
 * ipv6mr_interface is 0 or lo's 1, as ip_mreqn's ifindex is:
 * ip6_mc_find_dev() takes a nonzero one as the device, which must
 * exist (-ENODEV), and zero as the group's route.
 */
const unsigned char ipv6_mcast_all_nodes[16] = {
	0xff, 0x02, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x01,
};

const unsigned char ipv6_mcast_all_routers[16] = {
	0xff, 0x02, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x02,
};

const unsigned char ipv6_mcast_mldv2_reports[16] = {
	0xff, 0x02, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x16,
};

/* ff02::1:ff00:0001 -- solicited-node prefix sample */
const unsigned char ipv6_mcast_solicited_node[16] = {
	0xff, 0x02, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01,  0xff, 0x00, 0x00, 0x01,
};

/* ff05::2 -- all-routers, site-local scope */
const unsigned char ipv6_mcast_site_routers[16] = {
	0xff, 0x05, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x02,
};

const unsigned char *const ipv6_mreq_multiaddr_vocab[] = {
	ipv6_mcast_all_nodes,
	ipv6_mcast_all_routers,
	ipv6_mcast_mldv2_reports,
	ipv6_mcast_solicited_node,
	ipv6_mcast_site_routers,
};

const struct struct_field ipv6_mreq_fields[] = {
	FIELDX(struct ipv6_mreq, ipv6mr_multiaddr, FT_MAGIC,
	       .u.magic = { ipv6_mreq_multiaddr_vocab,
			    ARRAY_SIZE(ipv6_mreq_multiaddr_vocab),
			    sizeof(((struct ipv6_mreq *)NULL)->ipv6mr_multiaddr) }),
	FIELDX(struct ipv6_mreq, ipv6mr_interface, FT_RANGE,
	       .u.range = { 0, 1 }),
};
