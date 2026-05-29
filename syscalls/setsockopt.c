/*
 * SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, char __user *, optval, int, optlen)
 */

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include "arch.h"
#include "bpf.h"
#include "deferred-free.h"
#include "net.h"
#include "compat.h"
#include "random.h"
#include "rnd.h"
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

/*
 * Structured payload builders for the common (level, optname) shapes.
 *
 * Each builder writes a sane-ish value of the optname's documented
 * ABI shape into `buf` (always backed by the page_size allocation
 * created in do_setsockopt) and returns the byte length the kernel
 * expects.  Biasing draws toward these entries lets per-protocol
 * copy_from_user / option-dispatch code run on well-formed inputs
 * instead of failing at the size check.
 *
 * RNG comes from trinity's rnd_* helpers exclusively; libc rand() is
 * not used.
 */
static socklen_t build_int_bool(void *buf)
{
	*(int *)buf = (int)(rnd_u32() & 1);
	return sizeof(int);
}

static socklen_t build_int_rand(void *buf)
{
	*(int *)buf = (int) rnd_u32();
	return sizeof(int);
}

static socklen_t build_int_small_positive(void *buf)
{
	*(int *)buf = 1 + (int) rnd_modulo_u32(255);
	return sizeof(int);
}

static socklen_t build_linger(void *buf)
{
	struct linger *l = buf;

	l->l_onoff = (int)(rnd_u32() & 1);
	l->l_linger = (int) rnd_modulo_u32(60);
	return sizeof(struct linger);
}

static socklen_t build_timeval(void *buf)
{
	struct timeval *tv = buf;

	tv->tv_sec = (long) rnd_modulo_u32(30);
	tv->tv_usec = (long) rnd_modulo_u32(1000000);
	return sizeof(struct timeval);
}

static socklen_t build_ip_mreqn(void *buf)
{
	struct ip_mreqn *m = buf;

	/* 224.0.0.x range — locally-scoped multicast. */
	m->imr_multiaddr.s_addr = htonl(0xe0000000 | rnd_modulo_u32(0x0fffffff));
	m->imr_address.s_addr = htonl(INADDR_ANY);
	m->imr_ifindex = 0;
	return sizeof(struct ip_mreqn);
}

static socklen_t build_ipv6_mreq(void *buf)
{
	struct ipv6_mreq *m = buf;
	uint8_t *addr = (uint8_t *) &m->ipv6mr_multiaddr;

	memset(addr, 0, 16);
	addr[0] = 0xff;
	addr[1] = 0x02;
	addr[15] = (uint8_t)(1u + rnd_modulo_u32(0xfe));
	m->ipv6mr_interface = 0;
	return sizeof(struct ipv6_mreq);
}

static socklen_t build_packet_mreq(void *buf)
{
	struct packet_mreq *m = buf;
	unsigned int i;

	m->mr_ifindex = 1;
	m->mr_type = (unsigned short)(1u + rnd_modulo_u32(4));
	m->mr_alen = 6;
	for (i = 0; i < sizeof(m->mr_address); i++)
		m->mr_address[i] = (unsigned char)(rnd_u32() & 0xff);
	return sizeof(struct packet_mreq);
}

static socklen_t build_string_ifname(void *buf)
{
	static const char *names[] = { "lo", "eth0", "wlan0", "" };
	const char *n = names[rnd_modulo_u32(ARRAY_SIZE(names))];
	size_t len = strlen(n);

	memcpy(buf, n, len);
	((char *)buf)[len] = '\0';
	return (socklen_t)(len + 1);
}

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
};

/*
 * Pick a structured entry, write its payload into so->optval, and (when
 * `mismatch_len` is true) deliberately scramble so->optlen to land in
 * the per-option size-validation rejection path.  Returns true on a
 * successful build.
 */
static bool apply_sockopt_entry(struct sockopt *so, bool mismatch_len)
{
	const struct sockopt_entry *e;
	socklen_t exact;

	if (ARRAY_SIZE(sockopt_table) == 0)
		return false;
	if (so->optval == 0)
		return false;

	e = &sockopt_table[rnd_modulo_u32(ARRAY_SIZE(sockopt_table))];
	exact = e->build((void *) so->optval);

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

	/* copy the generated values to the shm. */
	rec->a2 = so.level;
	rec->a3 = so.optname;
	rec->a4 = so.optval;
	rec->a5 = so.optlen;

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
		deferred_freeptr(&rec->post_state);
		return;
	}

#ifdef USE_BPF
	if (snap->optname == SO_ATTACH_FILTER) {
		bpf_free_filter((struct sock_fprog *) snap->optval);
	} else
#endif
	{
		deferred_free_enqueue(snap->optval);
	}

	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_setsockopt = {
	.name = "setsockopt",
	.num_args = 5,
	.argtype = { [0] = ARG_SOCKETINFO },
	.argname = { [0] = "fd", [1] = "level", [2] = "optname", [3] = "optval", [4] = "optlen" },
	.sanitise = sanitise_setsockopt,
	.post = post_setsockopt,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.rettype = RET_ZERO_SUCCESS,
};
