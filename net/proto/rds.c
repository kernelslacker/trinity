#ifdef USE_RDS
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "net.h"
#include "kernel/rds.h"
#include "random.h"
#include "socket-family-grammar.h"
#include "trinity.h"
#include "utils.h"
#include "rnd.h"

#include "kernel/socket.h"
static void rds_gen_sockaddr(__unused__ struct socket_triplet *triplet, struct sockaddr **addr, socklen_t *addrlen)
{
	if (RAND_BOOL()) {
		struct sockaddr_in *rds;

		rds = zmalloc_tracked(sizeof(struct sockaddr_in));
		rds->sin_family = AF_INET;
		rds->sin_addr.s_addr = random_ipv4_address();
		rds->sin_port = htons(rnd_modulo_u32(65536));
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
		rds6->sin6_port = htons(rnd_modulo_u32(65536));
		*addr = (struct sockaddr *) rds6;
		*addrlen = sizeof(struct sockaddr_in6);
	}
}

static const unsigned int rds_opts[] = {
	RDS_CANCEL_SENT_TO, RDS_GET_MR, RDS_FREE_MR,
	4, /* deprecated RDS_BARRIER 4 */
	RDS_RECVERR, RDS_CONG_MONITOR, RDS_GET_MR_FOR_DEST,
	SO_RDS_TRANSPORT, SO_RDS_MSG_RXPATH_LATENCY,
	SO_TIMESTAMP_OLD, SO_TIMESTAMP_NEW,
};

static void rds_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_RDS;
	so->optname = RAND_ARRAY(rds_opts);

	switch (so->optname) {
	case RDS_CONG_MONITOR:
		so->optlen = sizeof(uint64_t);
		break;
	case RDS_CANCEL_SENT_TO:
		so->optlen = sizeof(struct sockaddr_in);
		break;
	case RDS_GET_MR:
		so->optlen = sizeof(struct rds_get_mr_args);
		break;
	case RDS_FREE_MR:
		so->optlen = sizeof(struct rds_free_mr_args);
		break;
	case RDS_GET_MR_FOR_DEST:
		so->optlen = sizeof(struct rds_get_mr_for_dest_args);
		break;
	default:
		so->optlen = sizeof(unsigned int);
		break;
	}
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
 *     -> sendmsg() with one of five cmsg shapes randomised per walk:
 *          A) raw datagram (no SOL_RDS cmsg) — drives the bare
 *             rds_sendmsg path through rds_send_xmit
 *          B) RDMA-MAP arm: RDS_CMSG_RDMA_MAP carrying a synthetic
 *             rds_get_mr_args (RDS_RDMA_USE_ONCE | READWRITE so the
 *             MR registration walks both lifecycle ends in one msg)
 *             plus an optional RDS_CMSG_RDMA_DEST cookie and an
 *             optional RDS_CMSG_ZCOPY_COOKIE (u32)
 *          C) RDMA-ARGS arm: RDS_CMSG_RDMA_ARGS with nr_local + a
 *             real local_vec_addr iovec array; gates the
 *             rds_rdma_extra_size() int-truncation path
 *          D) Atomic pair: RDS_CMSG_ATOMIC_FADD / CSWP and masked
 *             variants in the same msghdr; hits the op_active re-entry
 *             reject and the sg-leak-on-error shape
 *          E) cmsg-group conflict: RDMA_MAP + RDMA_ARGS in one
 *             msghdr; trips cmsg_groups == 3 (net/rds/send.c:1026)
 *     -> non-blocking recvmsg() to drain RDS_CMSG_CONG_UPDATE /
 *        RDS_CMSG_RDMA_STATUS notifications
 *     -> close()
 *
 * RDMA hardware reality.  A box with no IB or iWARP wired up uses
 * rds_tcp as its transport.  rds_rdma_map() checks
 * rs->rs_transport->get_mr early; TCP's transport ops leave get_mr
 * NULL and the call returns -EOPNOTSUPP without touching the user
 * buffer.  The cmsg parser (rds_cmsg_send → rds_cmsg_rdma_map /
 * rds_cmsg_rdma_args / rds_cmsg_atomic_*) has already dispatched by
 * then, which is the surface this grammar exists for.  All five arms
 * are reachable on any RDS-enabled kernel; the RDMA and atomic arms
 * gracefully degrade to parser-only walks on TCP-only boxes.
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
		((unsigned long long) rnd_u32() << 32) | rnd_u32();

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
	/*
	 * Length set drawn for the RDS_INFO_* getsockopt arm.  0 and 1
	 * exercise the -ENOSPC length-probe protocol (kernel writes the
	 * required size into optlen and returns -ENOSPC when the buffer is
	 * too small).  32 and 4096 drive the normal read path.  INT_MAX
	 * probes the int-overflow shape in net/rds/info.c:230 where the
	 * per-entry size multiplication can wrap a signed int.
	 */
	static const socklen_t info_lens[] = { 0, 1, 32, 4096,
					       (socklen_t) INT_MAX };
	unsigned char info_buf[4096];
	unsigned int i;
	int v;
	unsigned long long cong_mask;

	for (i = 0; i < n; i++) {
		switch (i % 3) {
		case 0:
			cong_mask = ((unsigned long long) rnd_u32() << 32) |
				    rnd_u32();
			(void) setsockopt(fd, SOL_RDS, RDS_CONG_MONITOR,
					  &cong_mask, sizeof(cong_mask));
			break;
		case 1:
			v = (i >> 1) & 1;
			(void) setsockopt(fd, SOL_RDS, RDS_RECVERR,
					  &v, sizeof(v));
			break;
		default: {
			/*
			 * RDS_INFO_* getsockopt arm.  optname drawn from
			 * [RDS_INFO_FIRST..RDS_INFO_LAST] (10000-10017);
			 * unreachable via RAND_BYTE() (max 255) so must be
			 * drawn explicitly here.  Uses a capped copy of len
			 * so we never overflow info_buf, while still passing
			 * the raw drawn value into the kernel via the
			 * pointer-aliased socklen_t so it sees the INT_MAX
			 * probe value before the kernel clamps it.
			 */
			unsigned int optname = RDS_INFO_FIRST +
				rnd_modulo_u32(RDS_INFO_LAST -
					       RDS_INFO_FIRST + 1);
			socklen_t len = RAND_ARRAY(info_lens);
			socklen_t safe = (len > sizeof(info_buf)) ?
					 sizeof(info_buf) : len;
			(void) getsockopt(fd, SOL_RDS, (int) optname,
					  info_buf, &safe);
			break;
		}
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
		sin6->sin6_port = htons(1024 + (rnd_modulo_u32(60000)));
		return sizeof(*sin6);
	} else {
		struct sockaddr_in *sin = out;

		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sin->sin_port = htons(1024 + (rnd_modulo_u32(60000)));
		return sizeof(*sin);
	}
}

/*
 * Build an RDMA-MAP cmsg burst: RDS_CMSG_RDMA_MAP with synthesised
 * rds_get_mr_args (RDS_RDMA_USE_ONCE | READWRITE walks both ends of
 * the MR lifecycle in one sendmsg), plus an optional RDMA_DEST cookie
 * and an optional ZCOPY_COOKIE (u32, unblocked alongside the zcopy
 * send path).
 *
 * On a TCP-transport box rds_rdma_map returns -EOPNOTSUPP early
 * (transport->get_mr is NULL); the user buffer is never touched
 * because get_mr is checked before rds_pin_pages.  The parser
 * dispatch (rds_cmsg_send → rds_cmsg_rdma_map / rds_cmsg_rdma_dest /
 * rds_cmsg_zcopy_cookie) already ran, which is the surface this arm
 * exists for.
 */
static size_t rds_build_rdma_cmsgs(unsigned char *buf, size_t buflen,
				   unsigned char *user_buf, size_t user_len,
				   rds_rdma_cookie_t *cookie_out)
{
	struct cmsghdr *cmsg;
	struct rds_get_mr_args mr_args;
	rds_rdma_cookie_t bogus;
	uint32_t zcookie;
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
		bogus = ((rds_rdma_cookie_t) rnd_u32() << 32) |
			rnd_u32();
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

	if (RAND_BOOL()) {
		zcookie = rnd_u32();
		need = CMSG_SPACE(sizeof(zcookie));
		if (used + need > buflen)
			return used;
		cmsg = (struct cmsghdr *) (buf + used);
		cmsg->cmsg_level = SOL_RDS;
		cmsg->cmsg_type = RDS_CMSG_ZCOPY_COOKIE;
		cmsg->cmsg_len = CMSG_LEN(sizeof(zcookie));
		memcpy(CMSG_DATA(cmsg), &zcookie, sizeof(zcookie));
		used += need;
	}

	return used;
}

/*
 * Build an RDMA-ARGS cmsg: RDS_CMSG_RDMA_ARGS carrying a
 * struct rds_rdma_args with a non-zero nr_local and a real
 * local_vec_addr pointer into caller-owned stack memory.
 *
 * This gates the rds_rdma_extra_size() path (net/rds/rdma.c) which
 * computes the extra page-list size from nr_local; the int-truncation
 * shape there is only reachable when nr_local is large, but even
 * small values drive the copy_from_user of the iovec array.
 */
static size_t rds_build_rdma_args_cmsg(unsigned char *buf, size_t buflen,
				       struct rds_iovec *lvec,
				       unsigned int nr_local)
{
	struct cmsghdr *cmsg;
	struct rds_rdma_args rdma_args;
	size_t need;

	memset(&rdma_args, 0, sizeof(rdma_args));
	rdma_args.cookie        = ((rds_rdma_cookie_t) rnd_u32() << 32) |
				 rnd_u32();
	rdma_args.remote_vec.addr  = (uint64_t) rnd_u64();
	rdma_args.remote_vec.bytes = rnd_modulo_u32(4096) + 1;
	rdma_args.local_vec_addr   = (uint64_t)(uintptr_t) lvec;
	rdma_args.nr_local         = nr_local;
	rdma_args.flags            = rnd_modulo_u32(16);
	rdma_args.user_token       = rnd_u64();

	need = CMSG_SPACE(sizeof(rdma_args));
	if (need > buflen)
		return 0;
	cmsg = (struct cmsghdr *) buf;
	cmsg->cmsg_level = SOL_RDS;
	cmsg->cmsg_type  = RDS_CMSG_RDMA_ARGS;
	cmsg->cmsg_len   = CMSG_LEN(sizeof(rdma_args));
	memcpy(CMSG_DATA(cmsg), &rdma_args, sizeof(rdma_args));
	return need;
}

/*
 * Build an atomic cmsg pair in one msghdr.  One plain op
 * (FADD or CSWP) followed by one masked op (MASKED_FADD or
 * MASKED_CSWP).  The second atomic in the same msghdr hits the
 * op_active re-entry reject in rds_cmsg_send(); emitting both plain
 * and masked variants in alternation also walks the sg-leak-on-error
 * unwind shape.
 */
static size_t rds_build_atomic_cmsgs(unsigned char *buf, size_t buflen)
{
	static const int plain_types[2]  = { RDS_CMSG_ATOMIC_FADD,
					    RDS_CMSG_ATOMIC_CSWP };
	static const int masked_types[2] = { RDS_CMSG_MASKED_ATOMIC_FADD,
					    RDS_CMSG_MASKED_ATOMIC_CSWP };
	struct cmsghdr *cmsg;
	struct rds_atomic_args aargs;
	size_t used = 0, need;
	int t0 = plain_types[rnd_modulo_u32(2)];
	int t1 = masked_types[rnd_modulo_u32(2)];

	memset(&aargs, 0, sizeof(aargs));
	aargs.cookie      = ((rds_rdma_cookie_t) rnd_u32() << 32) | rnd_u32();
	aargs.local_addr  = rnd_u64();
	aargs.remote_addr = rnd_u64();
	aargs.fadd.add    = rnd_u64();
	aargs.flags       = rnd_modulo_u32(8);
	aargs.user_token  = rnd_u64();

	need = CMSG_SPACE(sizeof(aargs));
	if (used + need > buflen)
		return used;
	cmsg = (struct cmsghdr *) (buf + used);
	cmsg->cmsg_level = SOL_RDS;
	cmsg->cmsg_type  = t0;
	cmsg->cmsg_len   = CMSG_LEN(sizeof(aargs));
	memcpy(CMSG_DATA(cmsg), &aargs, sizeof(aargs));
	used += need;

	/* second atomic — hits the op_active re-entry reject */
	aargs.local_addr  = rnd_u64();
	aargs.remote_addr = rnd_u64();
	aargs.m_fadd.add         = rnd_u64();
	aargs.m_fadd.nocarry_mask = rnd_u64();
	need = CMSG_SPACE(sizeof(aargs));
	if (used + need > buflen)
		return used;
	cmsg = (struct cmsghdr *) (buf + used);
	cmsg->cmsg_level = SOL_RDS;
	cmsg->cmsg_type  = t1;
	cmsg->cmsg_len   = CMSG_LEN(sizeof(aargs));
	memcpy(CMSG_DATA(cmsg), &aargs, sizeof(aargs));
	used += need;

	return used;
}

/*
 * Build a cmsg-group conflict: one RDMA_MAP (group 1) plus one
 * RDMA_ARGS (group 2) in the same msghdr.  The kernel's
 * rds_cmsg_send() validates cmsg_groups and rejects the combination
 * with EINVAL when both group bits are set (net/rds/send.c:1026 —
 * "Ensure (DEST, MAP) are never used with (ARGS, ATOMIC)").  That
 * validation path is otherwise dead in random per-syscall fuzzing.
 */
static size_t rds_build_group_conflict_cmsgs(unsigned char *buf, size_t buflen,
					     unsigned char *user_buf,
					     size_t user_len,
					     struct rds_iovec *lvec,
					     unsigned int nr_local,
					     rds_rdma_cookie_t *cookie_out)
{
	size_t used = 0, n;

	n = rds_build_rdma_cmsgs(buf, buflen, user_buf, user_len, cookie_out);
	used += n;

	n = rds_build_rdma_args_cmsg(buf + used, buflen - used, lvec, nr_local);
	used += n;

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
	/*
	 * Buffer sized for the largest combination we emit: the group
	 * conflict arm (RDMA_MAP + optional RDMA_DEST + optional
	 * ZCOPY_COOKIE) followed by RDMA_ARGS, or two atomic ops.
	 */
	unsigned char cmsgbuf[CMSG_SPACE(sizeof(struct rds_get_mr_args))
			      + CMSG_SPACE(sizeof(rds_rdma_cookie_t))
			      + CMSG_SPACE(sizeof(uint32_t))
			      + CMSG_SPACE(sizeof(struct rds_rdma_args))
			      + 2 * CMSG_SPACE(sizeof(struct rds_atomic_args))];
	/* Stack iovec array used by RDMA_ARGS arms; valid across sendmsg. */
	struct rds_iovec local_vecs[4];
	rds_rdma_cookie_t mr_cookie = 0;
	socklen_t peerlen;
	size_t cmsg_used = 0;
	unsigned int nr_local;
	unsigned int arm;

	peerlen = rds_fill_peer(&peer);

	generate_rand_bytes(payload, sizeof(payload));
	iov.iov_base = payload;
	iov.iov_len = sizeof(payload);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &peer;
	msg.msg_namelen = peerlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/*
	 * Five arms, each targeting a distinct cmsg parser path:
	 *   0 — raw datagram (no cmsgs)
	 *   1 — RDMA_MAP + optional RDMA_DEST + optional ZCOPY_COOKIE
	 *   2 — RDMA_ARGS (rds_rdma_extra_size / iovec copy_from_user)
	 *   3 — atomic pair: plain op + masked op (op_active re-entry)
	 *   4 — group conflict: RDMA_MAP + RDMA_ARGS (cmsg_groups == 3)
	 */
	memset(cmsgbuf, 0, sizeof(cmsgbuf));
	memset(user_buf, 0, sizeof(user_buf));

	nr_local = 1 + rnd_modulo_u32(ARRAY_SIZE(local_vecs));
	memset(local_vecs, 0, sizeof(local_vecs));
	local_vecs[0].addr  = (uint64_t)(uintptr_t) user_buf;
	local_vecs[0].bytes = sizeof(user_buf);

	arm = rnd_modulo_u32(5);
	switch (arm) {
	case 0:
		/* raw datagram — no cmsgs */
		break;
	case 1:
		/* RDMA_MAP + optional RDMA_DEST + optional ZCOPY_COOKIE */
		cmsg_used = rds_build_rdma_cmsgs(cmsgbuf, sizeof(cmsgbuf),
						 user_buf, sizeof(user_buf),
						 &mr_cookie);
		break;
	case 2:
		/* RDMA_ARGS — gates rds_rdma_extra_size() */
		cmsg_used = rds_build_rdma_args_cmsg(cmsgbuf, sizeof(cmsgbuf),
						      local_vecs, nr_local);
		break;
	case 3:
		/* atomic pair — op_active re-entry + sg-leak-on-error */
		cmsg_used = rds_build_atomic_cmsgs(cmsgbuf, sizeof(cmsgbuf));
		break;
	case 4:
		/* cmsg-group conflict — trips cmsg_groups == 3 */
		cmsg_used = rds_build_group_conflict_cmsgs(
				cmsgbuf, sizeof(cmsgbuf),
				user_buf, sizeof(user_buf),
				local_vecs, nr_local, &mr_cookie);
		break;
	}

	if (cmsg_used > 0) {
		msg.msg_control    = cmsgbuf;
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
