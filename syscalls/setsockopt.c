/*
 * SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, char __user *, optval, int, optlen)
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include "config.h"
#ifdef USE_SCTP
#include <linux/sctp.h>
#endif
#include "arch.h"
#include "bpf.h"
#include "deferred-free.h"
#include "net.h"
/*
 * struct_catalog.h transitively pulls <linux/fs.h> (via linux/aio_abi.h),
 * which defines struct file_attr.  compat.h's fallback definition of the
 * same struct guards on FILE_ATTR_SIZE_VER0 from the kernel header, so
 * struct_catalog.h must come first or compat.h's unguarded fallback fires
 * and the kernel header then redefines the type.
 */
#include "struct_catalog.h"
#include "compat.h"
#include "random.h"
#include "rnd.h"
#include "setsockopt-internal.h"
#include "shm.h"
#include "utils.h"	// RAND_ARRAY

static const unsigned int socket_opts[] = {
	SO_DEBUG, SO_REUSEADDR, SO_TYPE, SO_ERROR,
	SO_DONTROUTE, SO_BROADCAST, SO_SNDBUF, SO_RCVBUF,
	SO_SNDBUFFORCE, SO_RCVBUFFORCE, SO_KEEPALIVE, SO_OOBINLINE,
	SO_NO_CHECK, SO_PRIORITY, SO_LINGER, SO_BSDCOMPAT,
	SO_REUSEPORT, SO_PASSCRED, SO_PEERCRED, SO_RCVLOWAT, SO_SNDLOWAT,
	SO_RCVTIMEO, SO_SNDTIMEO, SO_SECURITY_AUTHENTICATION, SO_SECURITY_ENCRYPTION_TRANSPORT,
	SO_SECURITY_ENCRYPTION_NETWORK, SO_BINDTODEVICE, SO_ATTACH_FILTER, SO_DETACH_FILTER,
	SO_PEERNAME, SO_TIMESTAMP, SO_ACCEPTCONN, SO_PEERSEC,
	SO_PASSSEC, SO_TIMESTAMPNS, SO_MARK, SO_TIMESTAMPING,
	SO_PROTOCOL, SO_DOMAIN, SO_RXQ_OVFL, SO_WIFI_STATUS,
	SO_PEEK_OFF, SO_NOFCS, SO_LOCK_FILTER, SO_SELECT_ERR_QUEUE,
	SO_BUSY_POLL, SO_MAX_PACING_RATE, SO_BPF_EXTENSIONS, SO_INCOMING_CPU,
	SO_ATTACH_BPF, SO_ATTACH_REUSEPORT_CBPF, SO_ATTACH_REUSEPORT_EBPF,
	SO_CNX_ADVICE, SCM_TIMESTAMPING_OPT_STATS, SO_MEMINFO, SO_INCOMING_NAPI_ID,
	SO_COOKIE, SCM_TIMESTAMPING_PKTINFO, SO_PEERGROUPS, SO_ZEROCOPY,
	SO_TXTIME, SO_BINDTOIFINDEX, SO_TIMESTAMP_NEW, SO_TIMESTAMPNS_NEW,
	SO_TIMESTAMPING_NEW, SO_RCVTIMEO_NEW, SO_SNDTIMEO_NEW,
	SO_DETACH_REUSEPORT_BPF, SO_PREFER_BUSY_POLL, SO_BUSY_POLL_BUDGET,
	SO_NETNS_COOKIE, SO_BUF_LOCK,
	SO_RESERVE_MEM, SO_TXREHASH, SO_RCVMARK,
	SO_PASSPIDFD, SO_PEERPIDFD,
	SO_DEVMEM_LINEAR, SO_DEVMEM_DMABUF, SO_DEVMEM_DONTNEED,
	SO_RCVPRIORITY, SO_PASSRIGHTS, SO_INQ,
#ifdef SCM_TS_OPT_ID
	SCM_TS_OPT_ID,
#endif
};

struct sockopt_entry {
	int level;
	int optname;
	socklen_t (*build)(void *buf);
};

static const struct sockopt_entry sockopt_table[] = {
	/* SOL_SOCKET — int-shaped flags & buffers, struct linger, struct timeval, string ifname */
	{ SOL_SOCKET, SO_REUSEADDR,     build_int_bool },
	{ SOL_SOCKET, SO_KEEPALIVE,     build_int_bool },
	{ SOL_SOCKET, SO_BROADCAST,     build_int_bool },
	{ SOL_SOCKET, SO_OOBINLINE,     build_int_bool },
	{ SOL_SOCKET, SO_SNDBUF,        build_int_rand },
	{ SOL_SOCKET, SO_RCVBUF,        build_int_rand },
	{ SOL_SOCKET, SO_PRIORITY,      build_int_small_positive },
	{ SOL_SOCKET, SO_LINGER,        build_linger },
	{ SOL_SOCKET, SO_RCVTIMEO,      build_timeval },
	{ SOL_SOCKET, SO_SNDTIMEO,      build_timeval },
	{ SOL_SOCKET, SO_MARK,          build_int_rand },
	{ SOL_SOCKET, SO_PASSCRED,      build_int_bool },
	{ SOL_SOCKET, SO_TIMESTAMP,     build_int_bool },
	{ SOL_SOCKET, SO_TIMESTAMPNS,   build_int_bool },
	{ SOL_SOCKET, SO_BINDTODEVICE,  build_string_ifname },
	{ SOL_SOCKET, SO_REUSEPORT,     build_int_bool },
	{ SOL_SOCKET, SO_BUSY_POLL,     build_int_small_positive },
	{ SOL_SOCKET, SO_INCOMING_CPU,  build_int_small_positive },

	/* IPPROTO_IP */
	{ IPPROTO_IP,   IP_TTL,                build_int_small_positive },
	{ IPPROTO_IP,   IP_TOS,                build_int_small_positive },
	{ IPPROTO_IP,   IP_MTU_DISCOVER,       build_int_small_positive },
	{ IPPROTO_IP,   IP_PKTINFO,            build_int_bool },
	{ IPPROTO_IP,   IP_RECVERR,            build_int_bool },
	{ IPPROTO_IP,   IP_HDRINCL,            build_int_bool },
	{ IPPROTO_IP,   IP_ADD_MEMBERSHIP,     build_ip_mreqn },
	{ IPPROTO_IP,   IP_DROP_MEMBERSHIP,    build_ip_mreqn },
	{ IPPROTO_IP,   IP_MULTICAST_IF,       build_ip_mreqn },
	{ IPPROTO_IP,   IP_MULTICAST_TTL,      build_int_small_positive },
	{ IPPROTO_IP,   IP_MULTICAST_LOOP,     build_int_bool },
	{ IPPROTO_IP,   IP_FREEBIND,           build_int_bool },
	{ IPPROTO_IP,   IP_TRANSPARENT,        build_int_bool },

	/* IPPROTO_IPV6 */
	{ IPPROTO_IPV6, IPV6_V6ONLY,           build_int_bool },
	{ IPPROTO_IPV6, IPV6_UNICAST_HOPS,     build_int_small_positive },
	{ IPPROTO_IPV6, IPV6_MULTICAST_HOPS,   build_int_small_positive },
	{ IPPROTO_IPV6, IPV6_MULTICAST_LOOP,   build_int_bool },
	{ IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,   build_ipv6_mreq },
	{ IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,  build_ipv6_mreq },
	{ IPPROTO_IPV6, IPV6_RECVPKTINFO,      build_int_bool },
	{ IPPROTO_IPV6, IPV6_TCLASS,           build_int_small_positive },

	/* IPPROTO_TCP */
	{ IPPROTO_TCP,  TCP_NODELAY,           build_int_bool },
	{ IPPROTO_TCP,  TCP_MAXSEG,            build_int_small_positive },
	{ IPPROTO_TCP,  TCP_CORK,              build_int_bool },
	{ IPPROTO_TCP,  TCP_KEEPIDLE,          build_int_small_positive },
	{ IPPROTO_TCP,  TCP_KEEPINTVL,         build_int_small_positive },
	{ IPPROTO_TCP,  TCP_KEEPCNT,           build_int_small_positive },
	{ IPPROTO_TCP,  TCP_SYNCNT,            build_int_small_positive },
	{ IPPROTO_TCP,  TCP_LINGER2,           build_int_small_positive },
	{ IPPROTO_TCP,  TCP_DEFER_ACCEPT,      build_int_small_positive },
	{ IPPROTO_TCP,  TCP_QUICKACK,          build_int_bool },
	{ IPPROTO_TCP,  TCP_FASTOPEN,          build_int_small_positive },
	{ IPPROTO_TCP,  TCP_USER_TIMEOUT,      build_int_small_positive },

	/* IPPROTO_UDP */
	{ IPPROTO_UDP,  UDP_CORK,              build_int_bool },
#ifdef UDP_GRO
	{ IPPROTO_UDP,  UDP_GRO,               build_int_bool },
#endif
#ifdef UDP_SEGMENT
	{ IPPROTO_UDP,  UDP_SEGMENT,           build_int_small_positive },
#endif

	/* SOL_NETLINK */
	{ SOL_NETLINK,  NETLINK_ADD_MEMBERSHIP,   build_int_small_positive },
	{ SOL_NETLINK,  NETLINK_DROP_MEMBERSHIP,  build_int_small_positive },
	{ SOL_NETLINK,  NETLINK_PKTINFO,          build_int_bool },
	{ SOL_NETLINK,  NETLINK_BROADCAST_ERROR,  build_int_bool },
	{ SOL_NETLINK,  NETLINK_NO_ENOBUFS,       build_int_bool },
	{ SOL_NETLINK,  NETLINK_CAP_ACK,          build_int_bool },
	{ SOL_NETLINK,  NETLINK_EXT_ACK,          build_int_bool },

	/* SOL_PACKET */
	{ SOL_PACKET,   PACKET_ADD_MEMBERSHIP,    build_packet_mreq },
	{ SOL_PACKET,   PACKET_DROP_MEMBERSHIP,   build_packet_mreq },
	{ SOL_PACKET,   PACKET_VERSION,           build_int_small_positive },
	{ SOL_PACKET,   PACKET_LOSS,              build_int_bool },
	{ SOL_PACKET,   PACKET_AUXDATA,           build_int_bool },
	{ SOL_PACKET,   PACKET_RESERVE,           build_int_small_positive },
	{ SOL_PACKET,   PACKET_FANOUT,            build_int_rand },

#ifdef USE_SCTP
	/* IPPROTO_SCTP */
	{ IPPROTO_SCTP, SCTP_INITMSG,             build_sctp_initmsg },
	{ IPPROTO_SCTP, SCTP_RTOINFO,             build_sctp_rtoinfo },
	{ IPPROTO_SCTP, SCTP_ASSOCINFO,           build_sctp_assocparams },
	{ IPPROTO_SCTP, SCTP_ADAPTATION_LAYER,    build_sctp_setadaptation },
	{ IPPROTO_SCTP, SCTP_CONTEXT,             build_sctp_assoc_value },
	{ IPPROTO_SCTP, SCTP_MAXSEG,              build_sctp_assoc_value },
	{ IPPROTO_SCTP, SCTP_MAX_BURST,           build_sctp_assoc_value },
	{ IPPROTO_SCTP, SCTP_STREAM_SCHEDULER,    build_sctp_assoc_value },
	{ IPPROTO_SCTP, SCTP_DEFAULT_SNDINFO,     build_sctp_sndinfo },
	{ IPPROTO_SCTP, SCTP_DEFAULT_SEND_PARAM,  build_sctp_sndrcvinfo },
	{ IPPROTO_SCTP, SCTP_EVENTS,              build_sctp_events },
	{ IPPROTO_SCTP, SCTP_AUTH_CHUNK,          build_sctp_authchunk },
	{ IPPROTO_SCTP, SCTP_DELAYED_SACK,        build_sctp_sackinfo },
	{ IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY,     build_sctp_authkeyid },
	{ IPPROTO_SCTP, SCTP_AUTH_DELETE_KEY,     build_sctp_authkeyid },
	{ IPPROTO_SCTP, SCTP_AUTH_DEACTIVATE_KEY, build_sctp_authkeyid },
	{ IPPROTO_SCTP, SCTP_DEFAULT_PRINFO,      build_sctp_default_prinfo },
	{ IPPROTO_SCTP, SCTP_ADD_STREAMS,         build_sctp_add_streams },
	{ IPPROTO_SCTP, SCTP_STREAM_SCHEDULER_VALUE, build_sctp_stream_value },
	{ IPPROTO_SCTP, SCTP_EVENT,               build_sctp_event },
	{ IPPROTO_SCTP, SCTP_PEER_ADDR_THLDS,     build_sctp_paddrthlds },
	{ IPPROTO_SCTP, SCTP_PEER_ADDR_THLDS_V2,  build_sctp_paddrthlds_v2 },
	{ IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, build_sctp_udpencaps },
	{ IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,    build_sctp_paddrparams },
	{ IPPROTO_SCTP, SCTP_PLPMTUD_PROBE_INTERVAL, build_sctp_probeinterval },
	{ IPPROTO_SCTP, SCTP_PRIMARY_ADDR,        build_sctp_prim },
	{ IPPROTO_SCTP, SCTP_SET_PEER_PRIMARY_ADDR, build_sctp_prim },
#endif
};

/*
 * Per-fd history of the most recent setsockopt (level, optname) picked
 * by sanitise_setsockopt().  Open-addressing hash keyed on fd number;
 * each slot stores a single prior pick (no chaining).  Process-local --
 * trinity children fork their own copy, which is the intended granularity
 * because each child drives its own fd churn.  A pre-existing entry for
 * a different fd at the same slot is simply overwritten; the table is
 * a lossy MRU, not an exact log.
 *
 * The history exists so the picker below can spot "this fd just received
 * SO_KEEPALIVE -- now follow it with TCP_KEEPIDLE on the same fd" without
 * having to plumb per-fd obj `data` blobs through the fd subsystem.
 */
#define SSO_HIST_SIZE	256u	/* power of two; cheap modulo via & mask */

struct sso_history_entry {
	int fd;		/* -1 sentinel = empty slot */
	int level;
	int optname;
};

static struct sso_history_entry sso_history[SSO_HIST_SIZE] = {
	[0 ... SSO_HIST_SIZE - 1] = { .fd = -1 },
};

static inline unsigned int sso_history_slot(int fd)
{
	return ((unsigned int) fd) & (SSO_HIST_SIZE - 1u);
}

static void sso_history_record(int fd, int level, int optname)
{
	struct sso_history_entry *e;

	if (fd < 0)
		return;

	e = &sso_history[sso_history_slot(fd)];
	e->fd = fd;
	e->level = level;
	e->optname = optname;
}

static bool sso_history_lookup(int fd, int *level, int *optname)
{
	const struct sso_history_entry *e;

	if (fd < 0)
		return false;

	e = &sso_history[sso_history_slot(fd)];
	if (e->fd != fd)
		return false;

	*level = e->level;
	*optname = e->optname;
	return true;
}

/*
 * Pair table.  Each row encodes "if the prior setsockopt on this fd was
 * (prev_level, prev_optname), then a reasonable follow-up is
 * (level, optname, build)".  The builders are the same exact-size
 * payload helpers used by sockopt_table[], so the kernel sees
 * well-formed inputs and the per-protocol option-dispatch code gets
 * the dependent-state coverage that single-shot fuzzing misses.
 *
 * Multiple rows may share a prev key; the picker draws uniformly
 * among matches so the TCP keepalive triplet exercises all three
 * follow-ups over time.
 */
struct sockopt_pair {
	int prev_level;
	int prev_optname;
	int level;
	int optname;
	socklen_t (*build)(void *buf);
};

/*
 * Floor for the so->optval buffer try_paired_setsockopt() is willing to
 * write into.  socket_setsockopt() may have shrunk the page_size buffer
 * out from under us before pairing fires: SO_ATTACH_FILTER replaces it
 * with a 16-byte sock_fprog; SO_ATTACH_BPF / SO_ATTACH_REUSEPORT_EBPF /
 * SO_DETACH_REUSEPORT_BPF replace it with sizeof(int).  A subsequent
 * pair builder (build_timeval=16, build_ip_mreqn=12, build_ipv6_mreq=20)
 * would then overrun the shrunken allocation into the next glibc chunk
 * and trip MALLOC_CHECK_.  Gate on alloc_track_lookup_size() and bail
 * when the live extent is below this floor.
 *
 * MUST cover the largest pair-builder output -- update if a bigger
 * pair lands in sockopt_pairs[].
 */
#define MAX_PAIR_BUILDER_SIZE	sizeof(struct ipv6_mreq)

static const struct sockopt_pair sockopt_pairs[] = {
	/* SO_KEEPALIVE -> TCP keepalive triplet on the same fd. */
	{ SOL_SOCKET,   SO_KEEPALIVE,         IPPROTO_TCP,  TCP_KEEPIDLE,         build_int_small_positive },
	{ SOL_SOCKET,   SO_KEEPALIVE,         IPPROTO_TCP,  TCP_KEEPINTVL,        build_int_small_positive },
	{ SOL_SOCKET,   SO_KEEPALIVE,         IPPROTO_TCP,  TCP_KEEPCNT,          build_int_small_positive },

	/* Receive/send timeout pairing. */
	{ SOL_SOCKET,   SO_RCVTIMEO,          SOL_SOCKET,   SO_SNDTIMEO,          build_timeval },
	{ SOL_SOCKET,   SO_SNDTIMEO,          SOL_SOCKET,   SO_RCVTIMEO,          build_timeval },

	/* Privileged-force buffer set followed by the unprivileged sibling
	 * exercises the per-buffer ceiling/floor recalculation path. */
	{ SOL_SOCKET,   SO_RCVBUFFORCE,       SOL_SOCKET,   SO_RCVBUF,            build_int_rand },
	{ SOL_SOCKET,   SO_SNDBUFFORCE,       SOL_SOCKET,   SO_SNDBUF,            build_int_rand },

	/* IPv4 multicast: set interface / loop, then join / drop a group. */
	{ IPPROTO_IP,   IP_MULTICAST_IF,      IPPROTO_IP,   IP_ADD_MEMBERSHIP,    build_ip_mreqn },
	{ IPPROTO_IP,   IP_MULTICAST_LOOP,    IPPROTO_IP,   IP_MULTICAST_IF,      build_ip_mreqn },
	{ IPPROTO_IP,   IP_ADD_MEMBERSHIP,    IPPROTO_IP,   IP_DROP_MEMBERSHIP,   build_ip_mreqn },

	/* IPv6 multicast mirror. */
	{ IPPROTO_IPV6, IPV6_MULTICAST_LOOP,  IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,  build_ipv6_mreq },
	{ IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,  IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, build_ipv6_mreq },

	/* TCP_CORK vs TCP_NODELAY: mutually exclusive in the kernel; pairing
	 * exercises the conflict-resolution path. */
	{ IPPROTO_TCP,  TCP_CORK,             IPPROTO_TCP,  TCP_NODELAY,          build_int_bool },
	{ IPPROTO_TCP,  TCP_NODELAY,          IPPROTO_TCP,  TCP_CORK,             build_int_bool },

	/* TCP Fast Open server queue -> client-side connect opt-in. */
	{ IPPROTO_TCP,  TCP_FASTOPEN,         IPPROTO_TCP,  TCP_FASTOPEN_CONNECT, build_int_bool },
};

/*
 * Count matches for (prev_level, prev_optname) and pick one uniformly.
 * Two-pass: count, then sample.  Linear scan is fine for ~12-20 entries.
 */
static const struct sockopt_pair *lookup_sockopt_pair(int prev_level, int prev_optname)
{
	unsigned int i, matches = 0, pick;

	for (i = 0; i < ARRAY_SIZE(sockopt_pairs); i++) {
		if (sockopt_pairs[i].prev_level == prev_level &&
		    sockopt_pairs[i].prev_optname == prev_optname)
			matches++;
	}
	if (matches == 0)
		return NULL;

	pick = rnd_modulo_u32(matches);
	for (i = 0; i < ARRAY_SIZE(sockopt_pairs); i++) {
		if (sockopt_pairs[i].prev_level == prev_level &&
		    sockopt_pairs[i].prev_optname == prev_optname) {
			if (pick == 0)
				return &sockopt_pairs[i];
			pick--;
		}
	}
	return NULL;	/* unreachable */
}

/*
 * Apply a paired follow-up: write the secondary option's payload into
 * so->optval (already a zmalloc page) and fill out level / optname /
 * optlen.  Bumps the telemetry counter on success so -v runs can confirm
 * the picker is firing.  Returns true if the pair was emitted.
 */
static bool try_paired_setsockopt(struct sockopt *so, int fd)
{
	const struct sockopt_pair *pair;
	int prev_level, prev_optname;
	socklen_t exact;

	if (so->optval == 0)
		return false;
	if (!sso_history_lookup(fd, &prev_level, &prev_optname))
		return false;

	pair = lookup_sockopt_pair(prev_level, prev_optname);
	if (pair == NULL)
		return false;

	/*
	 * socket_setsockopt() can replace the page_size buffer with a much
	 * smaller allocation (SO_ATTACH_FILTER: 16-byte sock_fprog;
	 * SO_ATTACH_BPF / SO_ATTACH_REUSEPORT_EBPF / SO_DETACH_REUSEPORT_BPF:
	 * sizeof(int)).  Writing a pair-builder payload into that buffer
	 * would overrun into the next chunk.  alloc_track_lookup_size()
	 * returns the recorded extent for the live optval allocation, or 0
	 * if it was never tracked / consumed / rotated out -- treat unknown
	 * as below the floor and bail (benign: pairing skips this round).
	 */
	if (alloc_track_lookup_size((void *) so->optval) < MAX_PAIR_BUILDER_SIZE)
		return false;

	exact = pair->build((void *) so->optval);
	so->level = pair->level;
	so->optname = pair->optname;
	so->optlen = exact;

	__atomic_add_fetch(&shm->stats.setsockopt_pairing_paired_emitted, 1,
			   __ATOMIC_RELAXED);
	return true;
}

/*
 * Pick a structured entry, write its payload into so->optval, and (when
 * `mismatch_len` is true) deliberately scramble so->optlen to land in
 * the per-option size-validation rejection path.  Returns true on a
 * successful build.
 */
static bool apply_sockopt_entry(struct sockopt *so, bool mismatch_len)
{
	const struct sockopt_entry *e;
	const struct struct_desc *desc;
	socklen_t exact;

	if (ARRAY_SIZE(sockopt_table) == 0)
		return false;
	if (so->optval == 0)
		return false;

	e = &sockopt_table[rnd_modulo_u32(ARRAY_SIZE(sockopt_table))];

	/*
	 * Catalog-first: if syscall_struct_args[] carries a
	 * (level, optname) two-key row for ("setsockopt", arg 4) matching
	 * the row we just picked, fill optval via the schema-aware path so
	 * the per-field FT_ tags own the bytes.  optlen is set from
	 * desc->struct_size; the proof batch is fixed-size
	 * shapes only.  Variable-length tails (sctp / can_filter[]) keep
	 * their bespoke builders until the catalog grows length-derivation
	 * for them, at which point this fast path will start firing on
	 * them too.
	 *
	 * Discriminator source is the freshly-picked (e->level, e->optname),
	 * not rec->a2/a3: do_setsockopt() has not yet published the values
	 * to rec and may still mangle optname on the random/legacy arm
	 * (so->optname |= 1 << rand at line ~664), so the explicit-key
	 * lookup reads the authoritative picked state directly.
	 *
	 * Catalog miss: fall back to the bespoke build_*() in the row.
	 * That keeps the int/bool/string/scalar entries (no struct shape,
	 * no catalog row to register) and any struct-shaped optnames not
	 * yet migrated working byte-identically -- coverage never drops as
	 * rows are added incrementally.
	 */
	desc = struct_arg_lookup_two_key("setsockopt", 4,
					 (unsigned long) e->level,
					 (unsigned long) e->optname);
	if (desc != NULL) {
		struct_field_fill_schema_aware((unsigned char *) so->optval,
					       desc->struct_size, desc, NULL);
		exact = (socklen_t) desc->struct_size;
	} else {
		exact = e->build((void *) so->optval);
	}

	so->level = e->level;
	so->optname = e->optname;
	so->optlen = exact;

	if (mismatch_len) {
		switch (rnd_modulo_u32(5)) {
		case 0:
			so->optlen = 0;
			break;
		case 1:
			so->optlen = (exact >= 1) ? exact - 1 : 0;
			break;
		case 2:
			so->optlen = exact + 1;
			break;
		case 3:
			so->optlen = exact + (socklen_t) rnd_modulo_u32(64);
			break;
		case 4:
			so->optlen = (socklen_t)(1u + rnd_modulo_u32(4096));
			break;
		}
	}

	return true;
}

static void socket_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_SOCKET;

	so->optname = RAND_ARRAY(socket_opts);

	/* Adjust length according to operation set. */
	switch (so->optname) {

	case SO_LINGER:
		so->optlen = sizeof(struct linger);
		break;

	case SO_RCVTIMEO:
	case SO_SNDTIMEO:
		so->optlen = sizeof(struct timeval);
		break;

	case SO_ATTACH_FILTER: {
		unsigned long *optval = NULL, optlen = 0;

		/* Free any optval allocated by the caller (do_setsockopt)
		 * before we replace it with the BPF filter. */
		tracked_free_now((void *) so->optval);
		so->optval = 0;

#ifdef USE_BPF
		bpf_gen_filter(&optval, &optlen);
#endif

		so->optval = (unsigned long) optval;
		so->optlen = optlen;
		break;
	}

	case SO_ATTACH_BPF:
	case SO_ATTACH_REUSEPORT_EBPF:
	case SO_DETACH_REUSEPORT_BPF: {
#ifdef USE_BPF
		int prog_fd = get_rand_bpf_prog_fd();
		if (prog_fd >= 0) {
			int *buf = zmalloc_tracked(sizeof(int));
			*buf = prog_fd;
			tracked_free_now((void *) so->optval);
			so->optval = (unsigned long) buf;
			so->optlen = sizeof(int);
		}
#endif
		break;
	}

	default:
		break;
	}
}
/*
 * If we have a .len set, use it.
 * If not, pick some random size.
 */
unsigned int sockoptlen(unsigned int len)
{
	if (len != 0)
		return len;

	if (RAND_BOOL())
		return sizeof(char);
	else
		return sizeof(int);
}

/*
 * We do this if for eg, we've ended up being passed
 * an fd that isn't a socket (ie, triplet==NULL).
 * It can also happen if we land on an sso func that
 * isn't implemented for a particular family yet.
 */
static void do_random_sso(struct sockopt *so, struct socket_triplet *triplet)
{
	unsigned int i;
	const struct netproto *proto;

retry:
	switch (rnd_modulo_u32(4)) {
	case 0:	/* do a random protocol, even if it doesn't match this socket. */
		i = rnd_modulo_u32(TRINITY_PF_MAX);
		proto = net_protocols[i].proto;
		if (proto != NULL) {
			if (proto->setsockopt != NULL) {
				proto->setsockopt(so, triplet);
				return;
			}
		}
		goto retry;

	case 1:	/* protocol-specific setsockopt for this socket's family. */
		if (triplet == NULL)
			break;
		if (triplet->family < TRINITY_PF_MAX) {
			proto = net_protocols[triplet->family].proto;
			if (proto != NULL && proto->setsockopt != NULL)
				proto->setsockopt(so, triplet);
		}
		break;

	case 2:	/* Last resort: Generic socket options. */
		socket_setsockopt(so, triplet);
		break;

	case 3:	/* completely random operation. */
		so->level = rnd_u32();
		so->optname = RAND_BYTE();
		break;
	}
}

static void call_sso_ptr(struct sockopt *so, struct socket_triplet *triplet)
{
	const struct netproto *proto;

	proto = net_protocols[triplet->family].proto;

	if (proto != NULL) {
		if (proto->setsockopt != NULL) {
			proto->setsockopt(so, triplet);
			return;
		}
	}

	do_random_sso(so, triplet);
}

/*
 * Call a proto specific setsockopt routine from the table above.
 *
 * Called from random setsockopt() syscalls, and also during socket
 * creation on startup from sso_socket()
 *
 */
void do_setsockopt(struct sockopt *so, struct socket_triplet *triplet)
{
	unsigned int roll;
	bool from_random_path = false;

	so->optname = 0;

	/* get a page for the optval to live in.
	 * Pushing this into per-proto .setsockopt calls is deferred because
	 * each protocol would need its own function pointer and allocation
	 * strategy, and most protocols are fine with a single page.
	 */
	/* Mostly released via deferred_freeptr(&rec->post_state) in
	 * post_setsockopt(); a RAND_BOOL fallback below may direct-free.
	 * Opt in to the alloc tracker: the rare direct-free path leaves
	 * a stale slot to be evicted (benign leak), which is the safer
	 * failure mode per the 2026-05-19 alloc-tracking audit. */
	so->optval = (unsigned long) zmalloc_tracked(page_size);

	/* At the minimum, we want len to be a char or int.
	 * It gets overridden below in the per-proto sso->func / per-entry
	 * builder, so this is just a safe default for the unannotated
	 * fallback paths.
	 */
	so->optlen = sockoptlen(0);

	/* Without per-fd triplet provenance the protocol-specific dispatch
	 * cannot pick a meaningful (level, optname); fall back to the
	 * SOL_SOCKET path which is correct on any socket fd. */
	if (triplet == NULL) {
		socket_setsockopt(so, triplet);
		goto disable_maybe;
	}

	/*
	 * Selection bias across the three coverage shapes:
	 *   [ 0..69]  curated (level, optname, exact-size payload) entry
	 *   [70..89]  legacy random per-protocol setsockopt path, retaining
	 *             the 1-in-100 fully-random (level, optname) probe
	 *   [90..99]  curated entry paired with an intentionally-wrong
	 *             optlen to keep the per-option size-validation
	 *             rejection path warm
	 */
	roll = rnd_modulo_u32(100);
	if (roll < 70) {
		if (!apply_sockopt_entry(so, false))
			call_sso_ptr(so, triplet);
	} else if (roll < 90) {
		from_random_path = true;
		if (ONE_IN(100))
			do_random_sso(so, triplet);
		else
			call_sso_ptr(so, triplet);
	} else {
		if (!apply_sockopt_entry(so, true))
			call_sso_ptr(so, triplet);
	}

	/*
	 * 10% of the time mangle the optname bits.  Restrict this to the
	 * random / legacy path; mangling a curated entry just defeats its
	 * purpose and pushes the draw straight back into the EOPNOTSUPP
	 * rejection path the curated table is meant to skip past.
	 */
	if (from_random_path && ONE_IN(10))
		so->optname |= (1UL << (rnd_modulo_u32(32)));

disable_maybe:
	/* optval should be nonzero to enable a boolean option, or zero if
	 * the option is to be disabled.  Disable it half the time.
	 */
	if (RAND_BOOL()) {
		tracked_free_now((void *) so->optval);
		so->optval = 0;
	}
}

/*
 * Synchronous release of so->optval allocated by do_setsockopt().  Mirrors
 * the optname dispatch in post_setsockopt(): the SO_ATTACH_FILTER branch
 * in socket_setsockopt() replaces the page_size buffer with a sock_fprog
 * wrapper whose inner filter is a separate zmalloc_tracked() allocation
 * (bpf_gen_filter), so a plain tracked_free_now() on the outer wrapper
 * would leak the inner buffer.  Every other optname holds a single
 * tracked allocation (the page_size buffer, or the int-sized buf used by
 * the SO_ATTACH_BPF / SO_ATTACH_REUSEPORT_EBPF / SO_DETACH_REUSEPORT_BPF
 * cases) which tracked_free_now() handles directly.  Zeros so->optval so
 * retry callers do not double-free.
 */
void release_sockopt_optval(struct sockopt *so)
{
	if (so->optval == 0)
		return;
#ifdef USE_BPF
	if (so->optname == SO_ATTACH_FILTER) {
		bpf_free_filter((struct sock_fprog *) so->optval);
	} else
#endif
	{
		tracked_free_now((void *) so->optval);
	}
	so->optval = 0;
}

/*
 * Snapshot of the optname alongside the heap optval the post handler
 * frees.  rec->a3 (optname) and rec->a4 (optval) are both ABI-exposed
 * and a sibling syscall can scribble either between syscall return and
 * post entry; the old post handler treated post_state as a bare optval
 * and dispatched freeing through a single path, so a scribble of a4
 * had to be defended against by the snapshot and a scribble of a3 was
 * irrelevant because no per-optname dispatch existed.  The classic-BPF
 * SO_ATTACH_FILTER path needs that dispatch: its optval is a
 * two-tier sock_fprog wrapper (outer + inner filter) and a plain
 * deferred_freeptr() on the wrapper leaks the inner buffer.  Store
 * optname here so the post handler picks the right cleanup independent
 * of a3 corruption, and keep a magic cookie to reject foreign
 * allocations that pose as a snap via post_state stomp.
 */
#define SETSOCKOPT_POST_STATE_MAGIC	0x534F505453544154UL	/* "SOPTSTAT" */
struct setsockopt_post_state {
	unsigned long magic;
	int optname;
	void *optval;
};

static void sanitise_setsockopt(struct syscallrecord *rec)
{
	struct sockopt so = { 0, 0, 0, 0 };
	struct setsockopt_post_state *snap;
	struct socketinfo *si;
	struct socket_triplet *triplet = NULL;
	int fd;

	rec->post_state = 0;

	si = (struct socketinfo *) rec->a1;
	if (si == NULL) {
		rec->a1 = get_random_fd();
		rec->a4 = 0;
		return;
	}

	if (ONE_IN(1000)) {
		fd = get_random_fd();
	} else {
		fd = si->fd;
		triplet = &si->triplet;
	}

	rec->a1 = fd;

	do_setsockopt(&so, triplet);

	/*
	 * Dependent-option pairing: 1-in-4, override the just-picked
	 * (level, optname, optval, optlen) with a follow-up that targets
	 * the SAME fd's last-seen option.  do_setsockopt() already did the
	 * zmalloc'd optval allocation we need; try_paired_setsockopt()
	 * reuses that buffer for the secondary payload, so the post-handler
	 * snapshot machinery below sees a normal heap optval to free.
	 *
	 * The RAND_BOOL "disable" branch in do_setsockopt() may have freed
	 * optval and zeroed it; try_paired_setsockopt() bails on that case
	 * so the disable semantics survive.  Skip pairing entirely when fd
	 * was the random-fd fallback above (no triplet) -- pairing on a
	 * non-socket fd is just noise.
	 */
	if (triplet != NULL && rnd_modulo_u32(4) == 0)
		try_paired_setsockopt(&so, fd);

	/* copy the generated values to the shm. */
	rec->a2 = so.level;
	rec->a3 = so.optname;
	rec->a4 = so.optval;
	rec->a5 = so.optlen;

	/* Record what we picked so a later sanitise_setsockopt() on the
	 * same fd can chain a dependent follow-up.  Bypass paths that
	 * scribbled a random optname / level into so are still recorded;
	 * lookup_sockopt_pair() simply finds no match on garbage keys. */
	sso_history_record(fd, so.level, so.optname);

	/* Snap only when there is a heap optval to free.  The RAND_BOOL
	 * disable path in do_setsockopt() already freed and zeroed optval,
	 * so post_state stays NULL and the post handler returns early. */
	if (so.optval == 0)
		return;

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = SETSOCKOPT_POST_STATE_MAGIC;
	snap->optname = so.optname;
	snap->optval = (void *) so.optval;
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);
}

static void post_setsockopt(struct syscallrecord *rec)
{
	struct setsockopt_post_state *snap = (void *) rec->post_state;

	rec->a4 = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_setsockopt: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * Ownership-table check: shape passed but the magic cookie below
	 * only proves "looks like struct setsockopt_post_state", not "is
	 * the snapshot we produced for this attempt".  A sibling scribble
	 * that redirects rec->post_state at a stale same-type snap still
	 * resident on the deferred-free queue carries the matching cookie
	 * by construction, so a cookie-only gate would trust it and route
	 * the SO_ATTACH_FILTER optname dispatch into bpf_free_filter() with
	 * a foreign sock_fprog *, or hand snap->optval to
	 * deferred_free_enqueue() despite never having allocated it.
	 * sanitise_setsockopt() registers each snap in the post_state
	 * ownership table immediately after the rec->post_state assignment;
	 * a value that fails the lookup is not the live snap for this record
	 * and must not be dereferenced.  Mirrors prctl.c / execve.c / pipe.c.
	 * Bail without freeing -- the pointer is suspect.
	 */
	if (!post_state_is_owned(snap)) {
		outputerr("post_setsockopt: rejected post_state=%p not in "
			  "ownership table (post_state-redirected?)\n", snap);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: a sibling scribble of rec->post_state with a
	 * heap-shaped pointer to a foreign allocation would survive the
	 * shape gate above and let post_setsockopt parse arbitrary bytes
	 * as a setsockopt_post_state, then route the optname dispatch into
	 * bpf_free_filter() with a wild sock_fprog *.  Abandon without
	 * freeing on mismatch; the pointer is suspect and may not be heap.
	 */
	if (snap->magic != SETSOCKOPT_POST_STATE_MAGIC) {
		outputerr("post_setsockopt: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	/*
	 * Defense in depth: snap survived the gates but the inner optval
	 * pointer may have been scribbled.  Leak rather than hand garbage
	 * to free() / bpf_free_filter().  Snap itself is still safe to
	 * release through the post_state slot.
	 */
	if (looks_like_corrupted_ptr(rec, snap->optval)) {
		outputerr("post_setsockopt: rejected suspicious snap optval=%p (post_state-scribbled?)\n",
			  snap->optval);
		post_state_unregister(snap);
		deferred_freeptr(&rec->post_state);
		return;
	}

#ifdef USE_BPF
	if (snap->optname == SO_ATTACH_FILTER) {
		/*
		 * Wrapper-side gate before bpf_free_filter() dereferences
		 * bpf->filter: looks_like_corrupted_ptr() above is shape-only
		 * (heap-band + alignment), so a heap-shaped but unmapped
		 * snap->optval would survive that gate and fault inside the
		 * inner-pointer read.  Require the wrapper to be a tracked
		 * allocation (definitively one we produced via bpf_gen_filter)
		 * or readable for a sock_fprog-sized window.  When neither
		 * holds, skip the inner-free dispatch and fall back to outer-
		 * only enqueue (same path as the non-ATTACH_FILTER branch);
		 * mirrors the bpf_free_filter() inner-filter gate added in
		 * 64f659289041.
		 */
		struct sock_fprog *bpf = (struct sock_fprog *) snap->optval;

		if (alloc_track_lookup(bpf) ||
		    range_readable_user(bpf, sizeof(struct sock_fprog)))
			bpf_free_filter(bpf);
		else
			deferred_free_enqueue(snap->optval);
	} else
#endif
	{
		deferred_free_enqueue(snap->optval);
	}

	post_state_unregister(snap);
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_setsockopt = {
	.name = "setsockopt",
	.num_args = 5,
	.argtype = { [0] = ARG_SOCKETINFO, [4] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "level", [2] = "optname", [3] = "optval", [4] = "optlen" },
	.sanitise = sanitise_setsockopt,
	.post = post_setsockopt,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.rettype = RET_ZERO_SUCCESS,
};
