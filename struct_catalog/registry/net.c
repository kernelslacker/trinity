/*
 * Network struct-catalog registrations.
 *
 * Covers the sockaddr / msghdr / mmsghdr rows on bind, connect,
 * sendto, accept, accept4, sendmsg, recvmsg, sendmmsg, recvmmsg,
 * plus the setsockopt / getsockopt (level, optname) two-key rows
 * and their discriminator vocabularies (SO_LINGER, SO_{RCV,SND}TIMEO,
 * IP_ADD_MEMBERSHIP + siblings, IPV6_*, PACKET_*, MCAST_JOIN /
 * MCAST_SOURCE families, and every cataloged SCTP optval when
 * USE_SCTP is on).
 *
 * The struct_catalog/registry.c composition root wires the array
 * declared here into syscall_struct_arg_groups[].
 */

#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>

#include "config.h"

#ifdef USE_SCTP
#include <linux/sctp.h>
#endif
#ifdef USE_TCP_REPAIR_OPT
#include <linux/tcp.h>
#endif

#include "struct_catalog.h"
#include "trinity.h"

#include "kernel/in.h"

/*
 * setsockopt (level, optname) discriminator vocab -- proof batch for
 * the two-key extension.  Each list enumerates the optnames inside a
 * single level that share an optval struct shape, so one
 * syscall_struct_args[] row covers every (level, this-vocab) tuple
 * without cloning the entry.  Same pattern as cgroup link_create's
 * 20-attach-type discrim_values list.
 *
 * Symbol comes from setsockopt.c's sockopt_table[] vocabulary; the
 * lookup matches on the raw integer value, not the symbolic name.
 */
static const unsigned long setsockopt_timeval_optnames[] = {
	SO_RCVTIMEO,
	SO_SNDTIMEO,
};

static const unsigned long setsockopt_ip_mreqn_optnames[] = {
	IP_ADD_MEMBERSHIP,
	IP_DROP_MEMBERSHIP,
	IP_MULTICAST_IF,
};

static const unsigned long setsockopt_ip_mreq_source_optnames[] = {
	IP_ADD_SOURCE_MEMBERSHIP,
	IP_DROP_SOURCE_MEMBERSHIP,
	IP_BLOCK_SOURCE,
	IP_UNBLOCK_SOURCE,
};

static const unsigned long setsockopt_ipv6_mreq_optnames[] = {
	IPV6_ADD_MEMBERSHIP,
	IPV6_DROP_MEMBERSHIP,
};

static const unsigned long setsockopt_packet_mreq_optnames[] = {
	PACKET_ADD_MEMBERSHIP,
	PACKET_DROP_MEMBERSHIP,
};

/*
 * Protocol-independent MCAST_* setsockopt family: the same optname
 * payload is accepted under both IPPROTO_IP and IPPROTO_IPV6.  The
 * two-key map entry uses both lists so one row covers the full
 * (level, optname) cross product without cloning the entry.
 */
static const unsigned long setsockopt_mcast_levels[] = {
	IPPROTO_IP,
	IPPROTO_IPV6,
};

static const unsigned long setsockopt_mcast_join_optnames[] = {
	MCAST_JOIN_GROUP,
	MCAST_LEAVE_GROUP,
};

/*
 * Source-filter optnames in the same protocol-independent MCAST_*
 * family, sharing setsockopt_mcast_levels[] with the join/leave row.
 * Sibling list for the group_source_req payload shape.
 */
static const unsigned long setsockopt_mcast_source_optnames[] = {
	MCAST_JOIN_SOURCE_GROUP,
	MCAST_LEAVE_SOURCE_GROUP,
	MCAST_BLOCK_SOURCE,
	MCAST_UNBLOCK_SOURCE,
};

#ifdef USE_SCTP
static const unsigned long setsockopt_sctp_assoc_value_optnames[] = {
	SCTP_CONTEXT,
	SCTP_MAXSEG,
	SCTP_MAX_BURST,
	SCTP_STREAM_SCHEDULER,
};

static const unsigned long setsockopt_sctp_authkeyid_optnames[] = {
	SCTP_AUTH_ACTIVE_KEY,
	SCTP_AUTH_DELETE_KEY,
	SCTP_AUTH_DEACTIVATE_KEY,
};

static const unsigned long setsockopt_sctp_prim_optnames[] = {
	SCTP_PRIMARY_ADDR,
	SCTP_SET_PEER_PRIMARY_ADDR,
};
#endif

const struct syscall_struct_arg struct_catalog_registry_net[] = {
	/* sendmsg(int, const struct msghdr *, int) */
	{ "sendmsg",		2, &struct_catalog[SC_MSGHDR] },
	/* recvmsg(int, struct msghdr *, int) */
	{ "recvmsg",		2, &struct_catalog[SC_MSGHDR] },
	/* sendmmsg(int, struct mmsghdr *, unsigned int, unsigned int) */
	{ "sendmmsg",		2, &struct_catalog[SC_MMSGHDR] },
	/* recvmmsg(int, struct mmsghdr *, unsigned int, unsigned int, struct timespec *) */
	{ "recvmmsg",		2, &struct_catalog[SC_MMSGHDR] },
	/* bind(int, struct sockaddr *, socklen_t) */
	{ "bind",		2, &struct_catalog[SC_SOCKADDR_STORAGE] },
	/* connect(int, struct sockaddr *, socklen_t) */
	{ "connect",		2, &struct_catalog[SC_SOCKADDR_STORAGE] },
	/* sendto(int, const void *, size_t, int, struct sockaddr *, socklen_t) */
	{ "sendto",		5, &struct_catalog[SC_SOCKADDR_STORAGE] },
	/*
	 * accept(int, struct sockaddr *upeer_sockaddr, int *upeer_addrlen)
	 * accept4(int, struct sockaddr *upeer_sockaddr, int *upeer_addrlen,
	 *         int flags)
	 * a2 is the peer-address OUTPUT slot: sanitise_accept_addrlen()
	 * publishes a writable-region sockaddr_storage (or a NULL/NULL pair)
	 * and the kernel writes the peer address back via move_addr_to_user().
	 * argtype[1] is ARG_SOCKADDR, not ARG_STRUCT_PTR_*, so the schema-aware
	 * fill never resolves these rows -- attribution-only registration lets
	 * struct_field_for_cmp() steer KCOV-CMP-learned constants at the named
	 * ss_family / port / addr fields of sockaddr_storage_variants[] rather
	 * than at a coincidentally-same-width slot on the accept path.  Mirrors
	 * bind / connect / sendto above; same descriptor covers both accept
	 * arms since the sockaddr shape is family-tagged by ss_family and does
	 * not depend on the extra accept4 flags arg.
	 */
	{ "accept",		2, &struct_catalog[SC_SOCKADDR_STORAGE] },
	{ "accept4",		2, &struct_catalog[SC_SOCKADDR_STORAGE] },
	/*
	 * setsockopt a4 (optval): two-key (level, optname) rows resolved
	 * via struct_arg_lookup_two_key() from apply_sockopt_entry().
	 * Attribution-only; bespoke build_*() in syscalls/setsockopt.c
	 * owns selection / optlen / BPF replacement.
	 * See Documentation/struct_catalog.md.
	 */
	{
		"setsockopt", 4, &struct_catalog[SC_LINGER],
		.discrim_arg_idx	= 2,
		.discrim_value		= SOL_SOCKET,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SO_LINGER,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_TIMEVAL],
		.discrim_arg_idx	= 2,
		.discrim_value		= SOL_SOCKET,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_timeval_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_timeval_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_IP_MREQN],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_IP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_ip_mreqn_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_ip_mreqn_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_IP_MREQ_SOURCE],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_IP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_ip_mreq_source_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_ip_mreq_source_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_IPV6_MREQ],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_IPV6,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_ipv6_mreq_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_ipv6_mreq_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_PACKET_MREQ],
		.discrim_arg_idx	= 2,
		.discrim_value		= SOL_PACKET,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_packet_mreq_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_packet_mreq_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_GROUP_REQ],
		.discrim_arg_idx	= 2,
		.discrim_values		= setsockopt_mcast_levels,
		.num_discrim_values	= ARRAY_SIZE(setsockopt_mcast_levels),
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_mcast_join_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_mcast_join_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_GROUP_SOURCE_REQ],
		.discrim_arg_idx	= 2,
		.discrim_values		= setsockopt_mcast_levels,
		.num_discrim_values	= ARRAY_SIZE(setsockopt_mcast_levels),
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_mcast_source_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_mcast_source_optnames),
	},
#ifdef USE_TCP_REPAIR_OPT
	{
		"setsockopt", 4, &struct_catalog[SC_TCP_REPAIR_OPT],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_TCP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= TCP_REPAIR_OPTIONS,
	},
#endif
#ifdef USE_SCTP
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_INITMSG],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_INITMSG,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_RTOINFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_RTOINFO,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_ASSOCPARAMS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_ASSOCINFO,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_SETADAPTATION],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_ADAPTATION_LAYER,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_ASSOC_VALUE],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_sctp_assoc_value_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_sctp_assoc_value_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_SNDINFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_DEFAULT_SNDINFO,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_SNDRCVINFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_DEFAULT_SEND_PARAM,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_EVENT_SUBSCRIBE],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_EVENTS,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_AUTHCHUNK],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_AUTH_CHUNK,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_SACK_INFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_DELAYED_SACK,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_AUTHKEYID],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_sctp_authkeyid_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_sctp_authkeyid_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_DEFAULT_PRINFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_DEFAULT_PRINFO,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_ADD_STREAMS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_ADD_STREAMS,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_STREAM_VALUE],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_STREAM_SCHEDULER_VALUE,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_EVENT],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_EVENT,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PADDRTHLDS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_PEER_ADDR_THLDS,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PADDRTHLDS_V2],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_PEER_ADDR_THLDS_V2,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_UDPENCAPS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_REMOTE_UDP_ENCAPS_PORT,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PADDRPARAMS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_PEER_ADDR_PARAMS,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PROBEINTERVAL],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_PLPMTUD_PROBE_INTERVAL,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PRIM],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_sctp_prim_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_sctp_prim_optnames),
	},
#endif
	/*
	 * getsockopt a4 (optval): mirrors the setsockopt two-key rows
	 * for gettable (level, optname) pairs; attribution-only.
	 * Set-only optnames not mirrored (kernel does not return their
	 * payload struct on the get path).
	 * See Documentation/struct_catalog.md.
	 */
	{
		"getsockopt", 4, &struct_catalog[SC_LINGER],
		.discrim_arg_idx	= 2,
		.discrim_value		= SOL_SOCKET,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SO_LINGER,
	},
	{
		"getsockopt", 4, &struct_catalog[SC_TIMEVAL],
		.discrim_arg_idx	= 2,
		.discrim_value		= SOL_SOCKET,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_timeval_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_timeval_optnames),
	},
	/* sentinel */
	{ NULL, 0, NULL },
};
