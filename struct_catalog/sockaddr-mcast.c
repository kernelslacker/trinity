/*
 * struct_catalog/sockaddr-mcast.c -- IPv4 / IPv6 multicast setsockopt
 * optval struct field tables (ip_mreqn / ip_mreq_source / ipv6_mreq)
 * together with the curated well-known multicast address pools those
 * tables reference.
 *
 * Carved out of struct_catalog/sockaddr.c: sockaddr_storage per-AF
 * variants stay in sockaddr-af.c and the non-multicast optval shapes
 * (linger / packet_mreq / group_req / group_source_req) live in
 * sockaddr-sockopt.c; this TU owns only the IPv4/IPv6 multicast
 * optval field tables plus their FT_MAGIC address vocabularies.
 * Symbols are const (not static const) so the spine's designated
 * initialisers .fields = ip_mreqn_fields (and friends) resolve via
 * the externs in struct_catalog-internal.h.
 *
 * See sockaddr-sockopt.c for the shared "schema-aware FILL only"
 * contract that governs every optval row here.
 */

#include <stddef.h>
#include <netinet/in.h>
/*
 * linux/fs.h defines FILE_ATTR_SIZE_VER0 + struct file_attr; bring it
 * in before compat.h so compat.h's older-headers fallback for
 * struct file_attr stays inactive.  This TU does not use the type,
 * but struct_catalog.h pulls <linux/aio_abi.h> -> <linux/fs.h> below
 * and a duplicate definition would -Werror.
 */
#include <linux/fs.h>

#include "config.h"
#include "compat.h"

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"
#include "utils.h"

/*
 * struct ip_mreqn -- IPPROTO_IP / IP_{ADD,DROP}_MEMBERSHIP and
 * IP_MULTICAST_IF.  imr_multiaddr is __be32 selecting the multicast
 * group; FT_MAGIC carries a curated set of well-known IPv4 multicast
 * destinations (all-hosts, all-routers, IGMPv3, mDNS, NTP, SSM, SSDP)
 * in network byte order, so the join/leave path names a real
 * 224.0.0.0/4 group on every dispatch.  imr_address and imr_ifindex
 * stay FT_RAW: the bespoke builder zeroed both and the kernel accepts
 * any small ifindex (or zero = default interface).
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

const struct struct_field ip_mreqn_fields[] = {
	FIELDX(struct ip_mreqn, imr_multiaddr, FT_MAGIC,
	       .u.magic = { ipv4_mcast_vocab,
			    ARRAY_SIZE(ipv4_mcast_vocab),
			    sizeof(((struct ip_mreqn *)NULL)->imr_multiaddr) }),
	FIELD(struct ip_mreqn, imr_address),
	FIELD(struct ip_mreqn, imr_ifindex),
};

/*
 * struct ip_mreq_source -- IPPROTO_IP / IP_{ADD,DROP}_SOURCE_MEMBERSHIP
 * and IP_{BLOCK,UNBLOCK}_SOURCE.  The IPv4 source-multicast sibling of
 * ip_mreqn: imr_multiaddr selects the multicast group, imr_interface
 * the local interface address (zero = kernel default), imr_sourceaddr
 * the unicast source whose membership is being added / dropped /
 * blocked / unblocked.  imr_multiaddr tags FT_MAGIC -- the natural tag
 * for curated be32 multicast vocab -- though the schema fill switch
 * still falls through to FT_RAW for it today; the other two fields
 * stay FT_RAW.  Same multicast-bias regression vs the bespoke builder
 * applies, with the same FT_MAGIC follow-up restoring it.
 */
const struct struct_field ip_mreq_source_fields[] = {
	FIELDX(struct ip_mreq_source, imr_multiaddr, FT_MAGIC),
	FIELD(struct ip_mreq_source, imr_interface),
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
 * ipv6mr_interface stays FT_RAW: the bespoke builder zeroed it and
 * the kernel accepts any small ifindex (or zero = default).
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
	FIELD(struct ipv6_mreq, ipv6mr_interface),
};
