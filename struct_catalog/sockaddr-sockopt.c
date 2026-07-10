/*
 * struct_catalog/sockaddr-sockopt.c -- setsockopt optval struct field
 * tables (linger / packet_mreq / group_req / group_source_req).
 *
 * Tables are `const` (not `static const`) so the spine's designated-init
 * `.fields =` references resolve via the externs in struct_catalog-internal.h.
 *
 * setsockopt optval shapes -- proof batch for the two-key
 * (level, optname) discriminator.  Five shapes already owned by
 * bespoke build_*() functions in syscalls/setsockopt.c, registered
 * here so apply_sockopt_entry()'s explicit-key lookup resolves them
 * and struct_field_fill_schema_aware() takes over the fill.  Bespoke
 * builders stay in code as the miss-fallback for the int / bool /
 * string scalar entries (no struct shape to catalog) and for the
 * higher-leverage shapes that have not been migrated yet (sctp /
 * mptcp / tcp_repair / can_filter[] etc.); coverage on those paths
 * is byte-identical to before until their rows land.
 *
 * Scope of every row in this TU (and in the sockaddr-mcast.c
 * sibling): schema-aware FILL only.  There is NO field-scoped CMP
 * attribution for the setsockopt optval -- the optval slot's argtype
 * is ARG_UNDEFINED, and the field-scoped CMP machinery
 * (cmp_hints_field_scan_record() -> field_pools[]) is gated on
 * ARG_STRUCT_PTR_IN / ARG_STRUCT_PTR_INOUT, so it never visits
 * optval.  The FT_ tags below shape the live values via the schema
 * fill; they do not steer struct_field_for_cmp() at runtime for
 * these rows.  Wiring field-scoped CMP for ARG_UNDEFINED is out of
 * scope here and waits on the broader field-scoped-steering lift.
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
 * the bespoke builder did.  Schema-aware FILL only: per the section
 * header above, the setsockopt optval gets no field-scoped CMP
 * attribution.
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
 * struct group_req -- IPPROTO_IP / IPPROTO_IPV6 / MCAST_{JOIN,LEAVE}_GROUP.
 * The protocol-independent MCAST_JOIN_GROUP / MCAST_LEAVE_GROUP optnames
 * accept the same payload at both levels: a small unsigned ifindex plus a
 * sockaddr_storage carrying the multicast group address (AF_INET sin_addr
 * in 224.0.0.0/4 or AF_INET6 sin6_addr in ff00::/8).  gr_interface tags
 * FT_RANGE over a small ifindex window, mirroring packet_mreq's
 * mr_ifindex.  gr_group resolves as an embedded sockaddr_storage via the
 * cataloged SC_SOCKADDR_STORAGE tagged-union, so its ss_family and the
 * per-AF address bytes are populated by the schema-aware fill.  The
 * variant set spans all cataloged families rather than biasing toward
 * multicast addresses, so MCAST_JOIN kernel validation will still reject
 * a fraction of draws; a multicast-addr bias is a follow-up.
 */
const struct struct_field group_req_fields[] = {
	FIELDX(struct group_req, gr_interface, FT_RANGE,
	       .u.range = { 0, 4 },
	       .mutate_weight = 60),
	FIELDX(struct group_req, gr_group, FT_EMBEDDED_STRUCT,
	       .u.embedded_struct = { .elem_struct_name = "sockaddr_storage" }),
};

/*
 * struct group_source_req -- IPPROTO_IP / IPPROTO_IPV6 /
 * MCAST_{JOIN,LEAVE}_SOURCE_GROUP / MCAST_{BLOCK,UNBLOCK}_SOURCE.
 * Source-filter sibling of group_req: same ifindex + group-address
 * payload, with an additional sockaddr_storage carrying the source
 * address (AF_INET sin_addr / AF_INET6 sin6_addr in the unicast
 * source range).  The protocol-independent MCAST_*_SOURCE optnames
 * accept the same payload under both IPv4 and IPv6 levels.
 * gsr_interface tags FT_RANGE over the same small ifindex window
 * used for gr_interface / mr_ifindex; gsr_group and gsr_source both
 * resolve as embedded sockaddr_storage via the cataloged
 * SC_SOCKADDR_STORAGE tagged-union, so ss_family and the per-AF
 * address bytes come from the schema-aware fill.  As with group_req
 * the variant set spans all cataloged families and does not bias
 * toward multicast (on gsr_group) or unicast (on gsr_source), so
 * MCAST_*_SOURCE kernel validation will still reject a fraction of
 * draws; addr-class biases are a follow-up.
 */
const struct struct_field group_source_req_fields[] = {
	FIELDX(struct group_source_req, gsr_interface, FT_RANGE,
	       .u.range = { 0, 4 },
	       .mutate_weight = 60),
	FIELDX(struct group_source_req, gsr_group, FT_EMBEDDED_STRUCT,
	       .u.embedded_struct = { .elem_struct_name = "sockaddr_storage" }),
	FIELDX(struct group_source_req, gsr_source, FT_EMBEDDED_STRUCT,
	       .u.embedded_struct = { .elem_struct_name = "sockaddr_storage" }),
};
