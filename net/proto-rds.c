#ifdef USE_RDS
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "net.h"
#include "compat.h"
#include "random.h"
#include "socket-family-grammar.h"
#include "trinity.h"
#include "utils.h"
#include <linux/rds.h>

#ifndef SO_RDS_TRANSPORT
#define SO_RDS_TRANSPORT	8
#endif

static void rds_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	if (RAND_BOOL()) {
		struct sockaddr_in *rds;

		rds = zmalloc_tracked(sizeof(struct sockaddr_in));
		rds->sin_family = AF_INET;
		rds->sin_addr.s_addr = random_ipv4_address();
		rds->sin_port = htons(rand() % 65536);
		*addr = (struct sockaddr *) rds;
		*addrlen = sizeof(struct sockaddr_in);
	} else {
		struct sockaddr_in6 *rds6;

		rds6 = zmalloc_tracked(sizeof(struct sockaddr_in6));
		rds6->sin6_family = AF_INET6;
		/* 90% of the time, just do localhost */
		if (ONE_IN(10))
			inet_pton(AF_INET6, "fe80::", &rds6->sin6_addr);
		else
			inet_pton(AF_INET6, "::1", &rds6->sin6_addr);
		rds6->sin6_port = htons(rand() % 65536);
		*addr = (struct sockaddr *) rds6;
		*addrlen = sizeof(struct sockaddr_in6);
	}
}

static const unsigned int rds_opts[] = {
	RDS_CANCEL_SENT_TO, RDS_GET_MR, RDS_FREE_MR,
	4, /* deprecated RDS_BARRIER 4 */
	RDS_RECVERR, RDS_CONG_MONITOR, RDS_GET_MR_FOR_DEST,
	SO_RDS_TRANSPORT,
};

#define SOL_RDS 276

static void rds_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_RDS;
	so->optname = RAND_ARRAY(rds_opts);
	so->optlen = sizeof(unsigned int);
}

static struct socket_triplet rds_triplet[] = {
	{ .family = PF_RDS, .protocol = 0, .type = SOCK_SEQPACKET },
};

const struct netproto proto_rds = {
	.name = "rds",
	.setsockopt = rds_setsockopt,
	.gen_sockaddr = rds_gen_sockaddr,
	.valid_triplets = rds_triplet,
	.nr_triplets = ARRAY_SIZE(rds_triplet),
};

/*
 * grammar_rds — coherent walk for AF_RDS (Reliable Datagram Sockets,
 * the SEQPACKET datagram family historically driven over IB / iWARP
 * verbs and an in-kernel TCP transport fallback).
 *
 * Random per-syscall fuzzing essentially never assembles the full
 * AF_RDS sequence required to land on the cmsg parser + RDMA MR
 * lifecycle surfaces.  Tag allocation, per-message refcount cycles,
 * and the cong_map bitmap installation are the historic CVE axes
 * (the Oct 2019 stable backports around rds_tcp_kill_sock and the
 * 2018 rds_atomic_free_op double-free were both reachable only
 * through this kind of multi-step setup):
 *
 *   socket(AF_RDS, SOCK_SEQPACKET, 0)
 *     -> RDS_RECVERR / SO_RDS_TRANSPORT / RDS_CONG_MONITOR pre-bind
 *        churn — installs the per-socket congestion bitmap and pins a
 *        transport so rds_bind takes the fast TCP path
 *     -> bind() to sockaddr_in or sockaddr_in6 loopback (port 0; the
 *        kernel assigns).  The v4/v6 split per walk drives both
 *        rds_bind_inet4 and rds_bind_inet6 paths over the run.
 *     -> post-bind setsockopt churn to walk the option dispatcher's
 *        bound-state arm
 *     -> sendmsg() with one of two cmsg shapes randomised per walk:
 *          A) raw datagram (no SOL_RDS cmsg) — drives the bare
 *             rds_sendmsg path through rds_send_xmit
 *          B) RDMA arm: RDS_CMSG_RDMA_MAP carrying a synthetic
 *             rds_get_mr_args (RDS_RDMA_USE_ONCE | READWRITE so the
 *             MR registration walks both lifecycle ends in one msg)
 *             plus an optional RDS_CMSG_RDMA_DEST cookie
 *     -> non-blocking recvmsg() to drain RDS_CMSG_CONG_UPDATE /
 *        RDS_CMSG_RDMA_STATUS notifications
 *     -> close()
 *
 * RDMA hardware reality.  The fuzz box almost certainly has no IB or
 * iWARP wired up — the loaded transport is rds_tcp.  rds_rdma_map()
 * checks rs->rs_transport->get_mr early; TCP's transport ops leave
 * get_mr NULL and the call returns -EOPNOTSUPP without touching the
 * user buffer.  The cmsg parser (rds_cmsg_send → rds_cmsg_rdma_map)
 * has already dispatched by then, which is the surface this grammar
 * is for.  No runtime probe needed; both arms are reachable on any
 * RDS-enabled kernel and the RDMA arm gracefully degrades to a
 * parser-only walk on TCP-only boxes.
 *
 * needs_listen_accept = false.  RDS has no listen()/accept() — the
 * SEQPACKET semantics are datagram-style on top of an in-kernel
 * connection that the transport manages on first sendmsg.
 *
 * can_run probes socket(AF_RDS, SOCK_SEQPACKET, 0) once per process.
 * CONFIG_RDS=n latches rds_supported=0 and the grammar gets filtered
 * out at sfg_pick_random_active() time without tainting any
 * per-family unsupported latch shared with other grammars.
 */

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0x4000
#endif

/* Per-process probe cache.  -1 untested, 0 unsupported, 1 supported. */
static int rds_supported = -1;

/* Per-walk: family the kernel actually bound (AF_INET / AF_INET6).
 * Set by rds_bind_or_connect, read by rds_data_leg to build a
 * same-family peer sockaddr for sendmsg.  Each child runs grammar
 * walks serially so a file-static is collision-free here. */
static sa_family_t rds_bound_family;

static bool rds_can_run(void)
{
	int fd;

	if (rds_supported >= 0)
		return rds_supported == 1;

	fd = socket(PF_RDS, SOCK_SEQPACKET, 0);
	if (fd < 0) {
		rds_supported = 0;
		return false;
	}
	close(fd);
	rds_supported = 1;
	return true;
}

static void rds_pick_triplet(struct socket_triplet *out)
{
	out->family = PF_RDS;
	out->type = SOCK_SEQPACKET;
	out->protocol = 0;
}

/*
 * Pre-bind option churn.  RDS_RECVERR arms the rs_recverr error-queue
 * delivery; SO_RDS_TRANSPORT pins a transport (TCP is the one the
 * fuzz box has wired up; IB/iWARP need hardware); RDS_CONG_MONITOR
 * installs a 64-bit port mask, walking the cong_map allocation path.
 */
static void rds_configure_pre_bind(int fd, __unused__ struct socket_triplet *triplet)
{
	int recverr = RAND_BOOL();
	int trans = RAND_BOOL() ? RDS_TRANS_TCP : (int) RDS_TRANS_NONE;
	unsigned long long cong_mask =
		((unsigned long long) rand() << 32) | (unsigned int) rand();

	(void) setsockopt(fd, SOL_RDS, RDS_RECVERR, &recverr, sizeof(recverr));
	(void) setsockopt(fd, SOL_RDS, SO_RDS_TRANSPORT, &trans, sizeof(trans));
	(void) setsockopt(fd, SOL_RDS, RDS_CONG_MONITOR,
			  &cong_mask, sizeof(cong_mask));
}

static int rds_bind_or_connect(int fd, __unused__ struct socket_triplet *triplet)
{
	if (RAND_BOOL()) {
		struct sockaddr_in sin;

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sin.sin_port = 0;
		if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)) < 0)
			return -1;
		rds_bound_family = AF_INET;
	} else {
		struct sockaddr_in6 sin6;

		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr.s6_addr[15] = 1;		/* ::1 */
		sin6.sin6_port = 0;
		if (bind(fd, (struct sockaddr *) &sin6, sizeof(sin6)) < 0)
			return -1;
		rds_bound_family = AF_INET6;
	}
	return 0;
}

static bool rds_needs_listen_accept(__unused__ struct socket_triplet *triplet)
{
	/* RDS has no listen()/accept() — SEQPACKET is datagram-style on
	 * top of a transport-managed in-kernel connection. */
	return false;
}

/*
 * Post-bind option churn.  RDS_RECVERR is reachable post-bind;
 * RDS_CONG_MONITOR re-toggle exercises rds_cong_set_filter mid-life.
 */
static void rds_walk_setsockopts(int fd, __unused__ struct socket_triplet *triplet,
				 unsigned int n)
{
	unsigned int i;
	int v;
	unsigned long long cong_mask;

	for (i = 0; i < n; i++) {
		if (i & 1) {
			cong_mask = ((unsigned long long) rand() << 32) |
				    (unsigned int) rand();
			(void) setsockopt(fd, SOL_RDS, RDS_CONG_MONITOR,
					  &cong_mask, sizeof(cong_mask));
		} else {
			v = (i >> 1) & 1;
			(void) setsockopt(fd, SOL_RDS, RDS_RECVERR,
					  &v, sizeof(v));
		}
	}
}

static socklen_t rds_fill_peer(void *out)
{
	if (rds_bound_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = out;

		memset(sin6, 0, sizeof(*sin6));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr.s6_addr[15] = 1;
		sin6->sin6_port = htons(1024 + (rand() % 60000));
		return sizeof(*sin6);
	} else {
		struct sockaddr_in *sin = out;

		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sin->sin_port = htons(1024 + (rand() % 60000));
		return sizeof(*sin);
	}
}

/*
 * Build an RDMA-arm cmsg burst: RDS_CMSG_RDMA_MAP with synthesised
 * rds_get_mr_args (RDS_RDMA_USE_ONCE | READWRITE walks both ends of
 * the MR lifecycle in one sendmsg) plus an optional RDS_CMSG_RDMA_DEST
 * carrying a bogus rdma cookie.
 *
 * On a TCP-transport box rds_rdma_map returns -EOPNOTSUPP early
 * (transport->get_mr is NULL); the user buffer is never touched
 * because get_mr is checked before rds_pin_pages.  The parser
 * dispatch (rds_cmsg_send → rds_cmsg_rdma_map / rds_cmsg_rdma_dest)
 * already ran, which is the surface this arm exists for.
 */
static size_t rds_build_rdma_cmsgs(unsigned char *buf, size_t buflen,
				   unsigned char *user_buf, size_t user_len,
				   rds_rdma_cookie_t *cookie_out)
{
	struct cmsghdr *cmsg;
	struct rds_get_mr_args mr_args;
	rds_rdma_cookie_t bogus;
	size_t used = 0;
	size_t need;

	memset(&mr_args, 0, sizeof(mr_args));
	mr_args.vec.addr = (uintptr_t) user_buf;
	mr_args.vec.bytes = user_len;
	mr_args.cookie_addr = (uintptr_t) cookie_out;
	mr_args.flags = RDS_RDMA_USE_ONCE | RDS_RDMA_READWRITE;

	need = CMSG_SPACE(sizeof(mr_args));
	if (used + need > buflen)
		return used;
	cmsg = (struct cmsghdr *) (buf + used);
	cmsg->cmsg_level = SOL_RDS;
	cmsg->cmsg_type = RDS_CMSG_RDMA_MAP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(mr_args));
	memcpy(CMSG_DATA(cmsg), &mr_args, sizeof(mr_args));
	used += need;

	if (RAND_BOOL()) {
		bogus = ((rds_rdma_cookie_t) rand() << 32) |
			(unsigned int) rand();
		need = CMSG_SPACE(sizeof(bogus));
		if (used + need > buflen)
			return used;
		cmsg = (struct cmsghdr *) (buf + used);
		cmsg->cmsg_level = SOL_RDS;
		cmsg->cmsg_type = RDS_CMSG_RDMA_DEST;
		cmsg->cmsg_len = CMSG_LEN(sizeof(bogus));
		memcpy(CMSG_DATA(cmsg), &bogus, sizeof(bogus));
		used += need;
	}

	return used;
}

static void rds_data_leg(int parent_fd, __unused__ int child_fd,
			 __unused__ struct socket_triplet *triplet)
{
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} peer;
	struct msghdr msg, rmsg;
	struct iovec iov, riov;
	unsigned char payload[64];
	unsigned char user_buf[256];
	unsigned char rcvbuf[256];
	unsigned char rcvcmsg[CMSG_SPACE(256)];
	unsigned char cmsgbuf[CMSG_SPACE(sizeof(struct rds_get_mr_args))
			      + CMSG_SPACE(sizeof(rds_rdma_cookie_t))];
	rds_rdma_cookie_t mr_cookie = 0;
	socklen_t peerlen;
	size_t cmsg_used = 0;

	peerlen = rds_fill_peer(&peer);

	generate_rand_bytes(payload, sizeof(payload));
	iov.iov_base = payload;
	iov.iov_len = sizeof(payload);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &peer;
	msg.msg_namelen = peerlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* RDMA arm vs raw arm: 50/50 per walk.  Both reach rds_sendmsg's
	 * cmsg parser; the RDMA arm additionally walks the MR-lookup and
	 * cookie-validation paths even when the underlying transport
	 * doesn't implement them (-EOPNOTSUPP after parser dispatch). */
	if (RAND_BOOL()) {
		memset(cmsgbuf, 0, sizeof(cmsgbuf));
		memset(user_buf, 0, sizeof(user_buf));
		cmsg_used = rds_build_rdma_cmsgs(cmsgbuf, sizeof(cmsgbuf),
						 user_buf, sizeof(user_buf),
						 &mr_cookie);
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = cmsg_used;
	}

	(void) sendmsg(parent_fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);

	memset(&rmsg, 0, sizeof(rmsg));
	riov.iov_base = rcvbuf;
	riov.iov_len = sizeof(rcvbuf);
	rmsg.msg_iov = &riov;
	rmsg.msg_iovlen = 1;
	rmsg.msg_control = rcvcmsg;
	rmsg.msg_controllen = sizeof(rcvcmsg);
	(void) recvmsg(parent_fd, &rmsg, MSG_DONTWAIT);
}

const struct socket_family_grammar grammar_rds = {
	.family			= PF_RDS,
	.name			= "rds",
	.can_run		= rds_can_run,
	.pick_triplet		= rds_pick_triplet,
	.configure_pre_bind	= rds_configure_pre_bind,
	.bind_or_connect	= rds_bind_or_connect,
	.needs_listen_accept	= rds_needs_listen_accept,
	.walk_setsockopts	= rds_walk_setsockopts,
	.data_leg		= rds_data_leg,
};
#endif	/* USE_RDS */
