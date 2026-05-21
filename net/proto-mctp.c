#ifdef USE_MCTP
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <linux/mctp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "net.h"
#include "random.h"
#include "socket-family-grammar.h"
#include "compat.h"
#include "rnd.h"

#ifndef MCTP_NET_ANY
#define MCTP_NET_ANY		0x0
#endif
#ifndef MCTP_ADDR_NULL
#define MCTP_ADDR_NULL		0x00
#endif
#ifndef MCTP_ADDR_ANY
#define MCTP_ADDR_ANY		0xff
#endif
#ifndef MCTP_TAG_MASK
#define MCTP_TAG_MASK		0x07
#endif
#ifndef MCTP_TAG_OWNER
#define MCTP_TAG_OWNER		0x08
#endif
#ifndef MCTP_OPT_ADDR_EXT
#define MCTP_OPT_ADDR_EXT	1
#endif
#ifndef SIOCMCTPALLOCTAG
#define SIOCMCTPALLOCTAG	(SIOCPROTOPRIVATE + 0)
#define SIOCMCTPDROPTAG		(SIOCPROTOPRIVATE + 1)
struct mctp_ioc_tag_ctl {
	mctp_eid_t	peer_addr;
	__u8		tag;
	__u16		flags;
};
#endif

static void mctp_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_mctp *mctp;

	mctp = zmalloc_tracked(sizeof(struct sockaddr_mctp));
	mctp->smctp_family = AF_MCTP;
	mctp->smctp_network = RAND_BOOL() ? MCTP_NET_ANY : rnd_u32();
	mctp->smctp_addr.s_addr = RAND_BOOL() ? MCTP_ADDR_ANY : rnd_u32();
	mctp->smctp_type = rnd_u32();
	mctp->smctp_tag = rnd_u32() & (MCTP_TAG_MASK | MCTP_TAG_OWNER);

	*addr = (struct sockaddr *) mctp;
	*addrlen = sizeof(struct sockaddr_mctp);
}

static const unsigned int mctp_opts[] = { MCTP_OPT_ADDR_EXT };

static void mctp_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_MCTP;
	so->optname = RAND_ARRAY(mctp_opts);
	*(unsigned int *) so->optval = RAND_BOOL();
	so->optlen = sizeof(unsigned int);
}

static struct socket_triplet mctp_triplets[] = {
	{ .family = PF_MCTP, .protocol = 0, .type = SOCK_DGRAM },
};

const struct netproto proto_mctp = {
	.name = "mctp",
	.gen_sockaddr = mctp_gen_sockaddr,
	.setsockopt = mctp_setsockopt,
	.valid_triplets = mctp_triplets,
	.nr_triplets = ARRAY_SIZE(mctp_triplets),
};

/*
 * grammar_mctp — coherent walk for AF_MCTP (Management Component
 * Transport Protocol, the BMC-to-NIC sideband bus exposed as a
 * datagram socket family since 5.15).
 *
 * Random per-syscall fuzzing rarely assembles the full MCTP shape
 * required to land on the interesting surfaces.  The kernel side
 * splits cleanly into three axes the grammar walks deterministically:
 *
 *   socket(AF_MCTP, SOCK_DGRAM, 0)
 *     -> MCTP_OPT_ADDR_EXT toggle pre-bind (arms the extended-address
 *        socket flag so subsequent sendmsg/recvmsg hit the
 *        sockaddr_mctp_ext code path on the same fd)
 *     -> bind() to sockaddr_mctp with smctp_addr = MCTP_ADDR_NULL
 *        (the conventional "any local EID" bind) on a randomised
 *        network id (MCTP_NET_ANY or a small synthetic net id)
 *     -> post-bind setsockopt churn cycling MCTP_OPT_ADDR_EXT and
 *        SO_RCVTIMEO/SO_SNDTIMEO so the option dispatcher's bound-
 *        state arm runs each walk
 *     -> tag allocation lifecycle is the interesting axis.  Two arms
 *        randomised per walk:
 *          A) SIOCMCTPALLOCTAG ioctl to pre-allocate a key against a
 *             specific peer EID, sendmsg using the returned tag, then
 *             SIOCMCTPDROPTAG to release it after recvmsg.  Walks the
 *             mctp_alloc_local_tag / mctp_lookup_prealloc_tag /
 *             mctp_lookup_key release path end-to-end.
 *          B) Skip preallocation; sendmsg with smctp_tag carrying
 *             MCTP_TAG_OWNER (kernel auto-allocates an outgoing tag
 *             via mctp_alloc_local_tag during route lookup).  Drives
 *             the implicit-allocation arm and its lock-acquisition
 *             ordering against the per-net key list.
 *     -> sendmsg() to a synthesised peer sockaddr_mctp.  Routing
 *        almost certainly fails (no MCTP interfaces are wired up on a
 *        random fuzz box), so packets stop in mctp_local_output before
 *        leaving — but the route lookup, key insertion and tag
 *        bookkeeping have already run, which is the surface this
 *        grammar exists for.
 *     -> non-blocking recvmsg() to drain any keyed responses queued
 *        back (the loopback-via-self path that flows when smctp_addr
 *        matches a bound EID).
 *     -> SIOCMCTPDROPTAG (arm A only) to release the preallocated key.
 *     -> close() — exercises mctp_release with both populated and
 *        empty per-socket key lists depending on the arm taken.
 *
 * Hardware reality.  The fuzz box almost certainly has no MCTP
 * interface (no I2C/USB/serial transport bound, no `mctp link set`).
 * Every send falls out at route lookup with -ENETUNREACH after the
 * tag bookkeeping has run.  That's intentional — the parser /
 * tag-key / route lookup paths are the bug surface, not the wire-
 * level transport.  The two ioctls similarly walk the per-socket
 * key tracking and only fail late on routing.
 *
 * needs_listen_accept = false.  AF_MCTP is pure datagram; there is no
 * listen()/accept() path in the kernel.
 *
 * can_run probes socket(AF_MCTP, SOCK_DGRAM, 0) once per process.
 * CONFIG_MCTP=n latches mctp_supported=0 and the grammar gets
 * filtered out at sfg_pick_random_active() time without tainting any
 * per-family unsupported latch shared with other grammars.
 */

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0x4000
#endif

/* Per-process probe cache.  -1 untested, 0 unsupported, 1 supported. */
static int mctp_supported = -1;

static bool mctp_can_run(void)
{
	int fd;

	if (mctp_supported >= 0)
		return mctp_supported == 1;

	fd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (fd < 0) {
		mctp_supported = 0;
		return false;
	}
	close(fd);
	mctp_supported = 1;
	return true;
}

static void mctp_pick_triplet(struct socket_triplet *out)
{
	out->family = PF_MCTP;
	out->type = SOCK_DGRAM;
	out->protocol = 0;
}

/*
 * Pre-bind option churn.  MCTP_OPT_ADDR_EXT arms the per-socket
 * extended-address flag — once set, the kernel reads/writes
 * sockaddr_mctp_ext (with smctp_ifindex + smctp_haddr) instead of
 * the bare sockaddr_mctp on sendmsg/recvmsg, walking a different
 * arm of mctp_sendmsg's address-validation prologue.
 */
static void mctp_configure_pre_bind(int fd, __unused__ struct socket_triplet *triplet)
{
	unsigned int ext = RAND_BOOL();

	(void) setsockopt(fd, SOL_MCTP, MCTP_OPT_ADDR_EXT, &ext, sizeof(ext));
}

static int mctp_bind_or_connect(int fd, __unused__ struct socket_triplet *triplet)
{
	struct sockaddr_mctp sa;

	memset(&sa, 0, sizeof(sa));
	sa.smctp_family = AF_MCTP;
	sa.smctp_network = RAND_BOOL() ? MCTP_NET_ANY :
					 (unsigned int) (rnd_u32() & 0xff);
	/* MCTP_ADDR_NULL is the conventional "bind to all local EIDs"
	 * value; occasionally probe a synthesised mid-range EID too so
	 * the bind-collision arm of mctp_bind() runs as well. */
	sa.smctp_addr.s_addr = RAND_BOOL() ? MCTP_ADDR_NULL :
					     (mctp_eid_t) (8 + (rnd_modulo_u32(120)));
	sa.smctp_type = (__u8) (rnd_u32() & 0xff);
	sa.smctp_tag = 0;

	if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
		return -1;
	return 0;
}

static bool mctp_needs_listen_accept(__unused__ struct socket_triplet *triplet)
{
	/* AF_MCTP is datagram only; no listen()/accept() in the kernel. */
	return false;
}

/*
 * Post-bind option churn.  Cycle MCTP_OPT_ADDR_EXT so the per-socket
 * flag flips between sendmsg attempts in the data leg, plus
 * SO_RCVTIMEO/SO_SNDTIMEO churn to walk the generic sock_setsockopt
 * arm on a freshly bound MCTP socket.
 */
static void mctp_walk_setsockopts(int fd, __unused__ struct socket_triplet *triplet,
				  unsigned int n)
{
	struct timeval tv;
	unsigned int i;
	unsigned int ext;

	for (i = 0; i < n; i++) {
		switch (i % 3) {
		case 0:
			ext = i & 1;
			(void) setsockopt(fd, SOL_MCTP, MCTP_OPT_ADDR_EXT,
					  &ext, sizeof(ext));
			break;
		case 1:
			tv.tv_sec = 0;
			tv.tv_usec = 1000 + (rnd_modulo_u32(5000));
			(void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
					  &tv, sizeof(tv));
			break;
		case 2:
			tv.tv_sec = 0;
			tv.tv_usec = 1000 + (rnd_modulo_u32(5000));
			(void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
					  &tv, sizeof(tv));
			break;
		}
	}
}

static void mctp_data_leg(int parent_fd, __unused__ int child_fd,
			  __unused__ struct socket_triplet *triplet)
{
	struct mctp_ioc_tag_ctl tag_ctl;
	struct sockaddr_mctp peer;
	struct msghdr msg, rmsg;
	struct iovec iov, riov;
	unsigned char payload[64];
	unsigned char rcvbuf[256];
	bool tag_allocated = false;

	/* Tag-allocation arm A: pre-allocate a key against a synthesised
	 * peer EID.  ioctl typically fails late at route lookup but the
	 * key bookkeeping (mctp_alloc_local_tag) ran first — that's the
	 * surface.  When it succeeds, the returned tag carries TO+PREALLOC
	 * and we send/drop with it. */
	memset(&tag_ctl, 0, sizeof(tag_ctl));
	tag_ctl.peer_addr = (mctp_eid_t) (8 + (rnd_modulo_u32(120)));
	tag_ctl.tag = 0;
	tag_ctl.flags = 0;
	if (RAND_BOOL() && ioctl(parent_fd, SIOCMCTPALLOCTAG, &tag_ctl) == 0)
		tag_allocated = true;

	memset(&peer, 0, sizeof(peer));
	peer.smctp_family = AF_MCTP;
	peer.smctp_network = RAND_BOOL() ? MCTP_NET_ANY :
					   (unsigned int) (rnd_u32() & 0xff);
	if (tag_allocated) {
		peer.smctp_addr.s_addr = tag_ctl.peer_addr;
		peer.smctp_tag = tag_ctl.tag;
	} else {
		peer.smctp_addr.s_addr = (mctp_eid_t) (8 + (rnd_modulo_u32(120)));
		/* Arm B: TAG_OWNER set ⇒ kernel auto-allocates outgoing
		 * tag during route lookup.  Bare tag bits set ⇒ responder
		 * pattern (kernel rejects unless a matching key exists). */
		peer.smctp_tag = RAND_BOOL() ? MCTP_TAG_OWNER
					     : (rnd_u32() & MCTP_TAG_MASK);
	}
	peer.smctp_type = (__u8) (rnd_u32() & 0xff);

	generate_rand_bytes(payload, sizeof(payload));
	iov.iov_base = payload;
	iov.iov_len = sizeof(payload);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &peer;
	msg.msg_namelen = sizeof(peer);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	(void) sendmsg(parent_fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);

	memset(&rmsg, 0, sizeof(rmsg));
	riov.iov_base = rcvbuf;
	riov.iov_len = sizeof(rcvbuf);
	rmsg.msg_iov = &riov;
	rmsg.msg_iovlen = 1;
	(void) recvmsg(parent_fd, &rmsg, MSG_DONTWAIT);

	if (tag_allocated)
		(void) ioctl(parent_fd, SIOCMCTPDROPTAG, &tag_ctl);
}

const struct socket_family_grammar grammar_mctp = {
	.family			= PF_MCTP,
	.name			= "mctp",
	.can_run		= mctp_can_run,
	.pick_triplet		= mctp_pick_triplet,
	.configure_pre_bind	= mctp_configure_pre_bind,
	.bind_or_connect	= mctp_bind_or_connect,
	.needs_listen_accept	= mctp_needs_listen_accept,
	.walk_setsockopts	= mctp_walk_setsockopts,
	.data_leg		= mctp_data_leg,
};
#endif /* USE_MCTP */
