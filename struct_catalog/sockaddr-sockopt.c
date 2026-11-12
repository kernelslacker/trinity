/*
 * struct_catalog/sockaddr-sockopt.c -- setsockopt optval struct field
 * tables (linger / packet_mreq / group_req / group_source_req), reached
 * through setsockopt's (level, optname) lookup for a schema-aware fill.
 *
 * Tables are `const` (not `static const`) so the spine's designated-init
 * `.fields =` references resolve via the externs in struct_catalog-internal.h.
 */

#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
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

#include "kernel/in.h"
#include "kernel/fs.h"
/*
 * struct linger -- SOL_SOCKET / SO_LINGER.  l_onoff is a boolean
 * (kernel masks to 0/1); l_linger is a small positive lingertime in
 * seconds (bespoke build_linger() drew 0..59).  Both pin cleanly to
 * FT_RANGE so the schema fill produces values inside the legal window
 * the bespoke builder did.
 */
const struct struct_field linger_fields[] = {
	FIELDX(struct linger, l_onoff, FT_RANGE,
	       .u.range = { 0, 1 },
	       .mutate_weight = 60),
	FIELDX(struct linger, l_linger, FT_RANGE,
	       .u.range = { 0, 60 },
	       .mutate_weight = 60),
};

/*
 * struct packet_mreq -- SOL_PACKET / PACKET_{ADD,DROP}_MEMBERSHIP.
 * FT_ENUM pins mr_type to the four valid PACKET_MR_* values.
 * mr_ifindex and mr_alen go FT_RANGE over a small window matching
 * the bespoke builder.  mr_address[8] stays FT_RAW: the meaningful
 * vocab is the 6-byte Ethernet multicast MAC (01:00:5e:xx:xx:xx),
 * which has no clean stride-8 encoding, and the FT_MAGIC fill path
 * requires the vocab stride to equal the field size.  A 6-byte-aware
 * tag is a follow-up.
 */
const unsigned long packet_mreq_type_values[] = {
	PACKET_MR_MULTICAST,
	PACKET_MR_PROMISC,
	PACKET_MR_ALLMULTI,
	PACKET_MR_UNICAST,
};

const struct struct_field packet_mreq_fields[] = {
	FIELDX(struct packet_mreq, mr_ifindex, FT_RANGE,
	       .u.range = { 0, 4 },
	       .mutate_weight = 60),
	FIELDX(struct packet_mreq, mr_type, FT_ENUM,
	       .u.enum_ = { packet_mreq_type_values,
			    ARRAY_SIZE(packet_mreq_type_values) },
	       .mutate_weight = 80),
	FIELDX(struct packet_mreq, mr_alen, FT_RANGE,
	       .u.range = { 0, 8 },
	       .mutate_weight = 40),
	FIELD(struct packet_mreq, mr_address),
};

/*
 * struct group_req / group_source_req -- MCAST_{JOIN,LEAVE}_GROUP and
 * MCAST_{JOIN,LEAVE}_SOURCE_GROUP / MCAST_{BLOCK,UNBLOCK}_SOURCE, taken at
 * IPPROTO_IP and at IPPROTO_IPV6.  Each level reads every sockaddr in them
 * as its own family and refuses the other (-EINVAL for an IPv4 join or
 * leave, -EADDRNOTAVAIL otherwise), so each level has its own rows, whose
 * sockaddrs are that family's multicast rows in sockaddr-mcast.c.  The
 * source comes from the group vocabulary too: ip_mc_source() and
 * ip6_mc_source() file any address as a source, and a small vocabulary
 * lets a drop or unblock find the source an earlier add or block filed.
 * The ifindex is 0 or lo's 1, for the reason ip_mreqn's is.
 */
const struct struct_field group_req_ip_fields[] = {
	FIELDX(struct group_req, gr_interface, FT_RANGE,
	       .u.range = { 0, 1 },
	       .mutate_weight = 60),
	FIELDX(struct group_req, gr_group, FT_EMBEDDED_STRUCT,
	       .u.embedded_struct = { .elem_struct_name = "sockaddr_in_mcast" }),
};

const struct struct_field group_req_ipv6_fields[] = {
	FIELDX(struct group_req, gr_interface, FT_RANGE,
	       .u.range = { 0, 1 },
	       .mutate_weight = 60),
	FIELDX(struct group_req, gr_group, FT_EMBEDDED_STRUCT,
	       .u.embedded_struct = { .elem_struct_name = "sockaddr_in6_mcast" }),
};

const struct struct_field group_source_req_ip_fields[] = {
	FIELDX(struct group_source_req, gsr_interface, FT_RANGE,
	       .u.range = { 0, 1 },
	       .mutate_weight = 60),
	FIELDX(struct group_source_req, gsr_group, FT_EMBEDDED_STRUCT,
	       .u.embedded_struct = { .elem_struct_name = "sockaddr_in_mcast" }),
	FIELDX(struct group_source_req, gsr_source, FT_EMBEDDED_STRUCT,
	       .u.embedded_struct = { .elem_struct_name = "sockaddr_in_mcast" }),
};

const struct struct_field group_source_req_ipv6_fields[] = {
	FIELDX(struct group_source_req, gsr_interface, FT_RANGE,
	       .u.range = { 0, 1 },
	       .mutate_weight = 60),
	FIELDX(struct group_source_req, gsr_group, FT_EMBEDDED_STRUCT,
	       .u.embedded_struct = { .elem_struct_name = "sockaddr_in6_mcast" }),
	FIELDX(struct group_source_req, gsr_source, FT_EMBEDDED_STRUCT,
	       .u.embedded_struct = { .elem_struct_name = "sockaddr_in6_mcast" }),
};
