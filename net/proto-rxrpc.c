#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <linux/rxrpc.h>
#include "net.h"
#include "random.h"
#include "socket-family-grammar.h"
#include "utils.h"
#include "compat.h"
#include "rnd.h"

#define SOL_RXRPC 272

#ifndef RXRPC_MANAGE_RESPONSE
#define RXRPC_MANAGE_RESPONSE 7
#endif

static const unsigned int rxrpc_opts[] = {
	RXRPC_MIN_SECURITY_LEVEL,
	RXRPC_UPGRADEABLE_SERVICE,
	RXRPC_SUPPORTED_CMSG,
	RXRPC_MANAGE_RESPONSE,
};

static void rxrpc_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_rxrpc *rxrpc;

	rxrpc = zmalloc_tracked(sizeof(struct sockaddr_rxrpc));
	rxrpc->srx_family = AF_RXRPC;
	rxrpc->srx_service = rnd_u32();
	rxrpc->transport_type = SOCK_DGRAM;

	if (RAND_BOOL()) {
		rxrpc->transport_len = sizeof(struct sockaddr_in);
		rxrpc->transport.sin.sin_family = AF_INET;
		rxrpc->transport.sin.sin_addr.s_addr = random_ipv4_address();
		rxrpc->transport.sin.sin_port = htons(rnd_modulo_u32(65536));
	} else {
		rxrpc->transport_len = sizeof(struct sockaddr_in6);
		rxrpc->transport.sin6.sin6_family = AF_INET6;
		rxrpc->transport.sin6.sin6_addr.s6_addr32[3] = htonl(1); /* ::1 */
		rxrpc->transport.sin6.sin6_port = htons(rnd_modulo_u32(65536));
	}

	*addr = (struct sockaddr *) rxrpc;
	*addrlen = sizeof(struct sockaddr_rxrpc);
}

static void rxrpc_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	unsigned short *optval_us;
	unsigned int *optval32;

	so->level = SOL_RXRPC;
	so->optname = RAND_ARRAY(rxrpc_opts);

	switch (so->optname) {
	case RXRPC_MIN_SECURITY_LEVEL:
		/* 0=plain, 1=auth, 2=encrypt */
		optval32 = (unsigned int *) so->optval;
		*optval32 = rnd_modulo_u32(3);
		so->optlen = sizeof(unsigned int);
		break;
	case RXRPC_UPGRADEABLE_SERVICE:
		/* two unsigned short values: service[0] -> service[1] */
		optval_us = (unsigned short *) so->optval;
		optval_us[0] = rnd_u32();
		optval_us[1] = rnd_u32();
		so->optlen = 2 * sizeof(unsigned short);
		break;
	default:
		optval32 = (unsigned int *) so->optval;
		*optval32 = rnd_u32();
		so->optlen = sizeof(unsigned int);
		break;
	}
}

static struct socket_triplet rxrpc_triplet[] = {
	{ .family = PF_RXRPC, .protocol = PF_INET, .type = SOCK_DGRAM },
	{ .family = PF_RXRPC, .protocol = PF_INET6, .type = SOCK_DGRAM },
};

const struct netproto proto_rxrpc = {
	.name = "rxrpc",
	.gen_sockaddr = rxrpc_gen_sockaddr,
	.setsockopt = rxrpc_setsockopt,
	.valid_triplets = rxrpc_triplet,
	.nr_triplets = ARRAY_SIZE(rxrpc_triplet),
};

/*
 * grammar_rxrpc — coherent walk for AF_RXRPC (Rx remote procedure call,
 * the AFS/Kerberos-era RPC the kernel still ships an in-tree
 * implementation of).
 *
 * Random per-syscall fuzzing essentially never assembles a coherent
 * AF_RXRPC sequence:  the family carries cmsg-driven call state
 * machinery on top of an AF_INET/AF_INET6 UDP underlay, with most
 * setsockopts gated on rx_local being non-NULL (i.e. pre-bind only)
 * and the actual call lifecycle driven by an RXRPC_USER_CALL_ID cmsg
 * tag the kernel uses to multiplex outstanding calls on a single fd.
 *
 *   socket(AF_RXRPC, SOCK_DGRAM, PF_INET[6])
 *     -> RXRPC_MIN_SECURITY_LEVEL / RXRPC_EXCLUSIVE_CONNECTION /
 *        RXRPC_UPGRADEABLE_SERVICE pre-bind churn (these all reject
 *        post-bind so we have to hit them before bind() lands)
 *     -> bind() to sockaddr_rxrpc with srx_service=0 (client side) and
 *        a loopback transport_addr — kernel allocates the underlay UDP
 *        port for us
 *     -> getsockopt(RXRPC_SUPPORTED_CMSG) churn post-bind to exercise
 *        the option dispatcher's bound-state arm
 *     -> sendmsg() with a START-OF-CALL cmsg burst:
 *          RXRPC_USER_CALL_ID  (mandatory; opaque-to-kernel call tag)
 *          RXRPC_TX_LENGTH     (optional; advertises Tx call length)
 *          RXRPC_EXCLUSIVE_CALL or RXRPC_UPGRADE_SERVICE flag (optional)
 *          RXRPC_SET_CALL_TIMEOUT (optional; arms timeouts)
 *        targeted at a synthesised peer sockaddr_rxrpc with a non-zero
 *        service id over the same transport family.  Delivery to the
 *        peer port likely fails; that's fine — the cmsg parser dispatch
 *        in rxrpc_sendmsg_cmsg() runs before the packet leaves and is
 *        the surface we want to land on.
 *     -> non-blocking recvmsg() to drain any cmsg metadata the kernel
 *        plumbed back (RXRPC_LOCAL_ERROR / RXRPC_NET_ERROR / etc.)
 *     -> close()
 *
 * Security path is intentionally NOT exercised.  RXRPC_SECURITY_KEY
 * needs a kernel keyring key referenced by name, which would require
 * us to install one via add_key() (and CONFIG_RXKAD/RXGK on the kernel
 * side).  That's out of scope for a userspace grammar — the plaintext
 * (RXRPC_SECURITY_PLAIN) path is reachable without any of that and is
 * what this grammar drives.
 *
 * Per-call user_call_id allocation.  The kernel treats this as opaque;
 * userspace just needs to pick something it won't collide with on the
 * same fd before close().  We use a per-process monotonically
 * increasing counter, which trivially avoids collision because every
 * walk closes the fd at the end.
 *
 * can_run probes both PF_INET and PF_INET6 transports once per process
 * (each opens an AF_RXRPC socket() with the corresponding protocol
 * argument and caches the verdict).  CONFIG_AF_RXRPC=n latches both
 * states to 0; can_run returns false; sfg_pick_random_active() filters
 * the grammar out without tainting any per-family unsupported latch
 * shared with other grammars.
 */

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0x4000
#endif

/* Per-process probe cache.  -1 untested, 0 unsupported, 1 supported. */
static int rxrpc_v4_state = -1;
static int rxrpc_v6_state = -1;
static unsigned long rxrpc_next_call_id;

static void rxrpc_probe_one(int proto, int *state)
{
	int fd;

	if (*state >= 0)
		return;

	fd = socket(AF_RXRPC, SOCK_DGRAM, proto);
	if (fd < 0) {
		*state = 0;
		return;
	}
	close(fd);
	*state = 1;
}

static bool rxrpc_can_run(void)
{
	rxrpc_probe_one(PF_INET, &rxrpc_v4_state);
	rxrpc_probe_one(PF_INET6, &rxrpc_v6_state);
	return rxrpc_v4_state == 1 || rxrpc_v6_state == 1;
}

static void rxrpc_pick_triplet(struct socket_triplet *out)
{
	out->family = PF_RXRPC;
	out->type = SOCK_DGRAM;

	if (rxrpc_v4_state == 1 && rxrpc_v6_state == 1)
		out->protocol = RAND_BOOL() ? PF_INET : PF_INET6;
	else if (rxrpc_v4_state == 1)
		out->protocol = PF_INET;
	else
		out->protocol = PF_INET6;
}

/*
 * Fill *srx with a loopback rxrpc-over-UDP address.  service is the
 * service id (0 for the client-side bind, non-zero for sendmsg peers);
 * port is the transport-layer UDP port (0 lets the kernel assign on
 * bind, non-zero targets a specific peer on sendmsg).  Caller picks
 * the underlay family based on the triplet protocol field.
 */
static void rxrpc_fill_addr(struct sockaddr_rxrpc *srx, int proto,
			    unsigned short service, unsigned short port)
{
	memset(srx, 0, sizeof(*srx));
	srx->srx_family = AF_RXRPC;
	srx->srx_service = service;
	srx->transport_type = SOCK_DGRAM;

	if (proto == PF_INET6) {
		srx->transport_len = sizeof(struct sockaddr_in6);
		srx->transport.sin6.sin6_family = AF_INET6;
		/* in6addr_loopback (::1) — open-coded so we don't need
		 * the extern at link time. */
		srx->transport.sin6.sin6_addr.s6_addr[15] = 1;
		srx->transport.sin6.sin6_port = htons(port);
	} else {
		srx->transport_len = sizeof(struct sockaddr_in);
		srx->transport.sin.sin_family = AF_INET;
		srx->transport.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		srx->transport.sin.sin_port = htons(port);
	}
}

/*
 * Pre-bind option churn.  All three of these reject with -EINVAL once
 * rx_local is wired up by bind(), so they have to land here.  The
 * grammar driver calls walk_setsockopts AFTER configure_pre_bind, so
 * we keep these atomic in this hook to guarantee ordering.
 */
static void rxrpc_configure_pre_bind(int fd, __unused__ struct socket_triplet *triplet)
{
	unsigned int level;
	int excl;
	unsigned short upgrade[2];

	level = rnd_modulo_u32(3);	/* PLAIN / AUTH / ENCRYPT */
	(void) setsockopt(fd, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL,
			  &level, sizeof(level));

	excl = RAND_BOOL();
	(void) setsockopt(fd, SOL_RXRPC, RXRPC_EXCLUSIVE_CONNECTION,
			  &excl, sizeof(excl));

	/* RXRPC_UPGRADEABLE_SERVICE wants {from, to} as two unsigned
	 * shorts and only makes sense if the bind below carried a
	 * non-zero srx_service.  We bind as a client (service=0), so
	 * this call is expected to fail validation — it still walks
	 * the option dispatcher's bound/unbound check, which is the
	 * coverage we want. */
	upgrade[0] = (unsigned short) (rnd_u32() & 0xffff);
	upgrade[1] = (unsigned short) (rnd_u32() & 0xffff);
	(void) setsockopt(fd, SOL_RXRPC, RXRPC_UPGRADEABLE_SERVICE,
			  upgrade, sizeof(upgrade));
}

static int rxrpc_bind_or_connect(int fd, struct socket_triplet *triplet)
{
	struct sockaddr_rxrpc srx;

	rxrpc_fill_addr(&srx, triplet->protocol, /*service=*/0, /*port=*/0);
	if (bind(fd, (struct sockaddr *) &srx, sizeof(srx)) < 0)
		return -1;
	return 0;
}

static bool rxrpc_needs_listen_accept(__unused__ struct socket_triplet *triplet)
{
	/* AF_RXRPC has no listen()/accept() — server-mode is via the
	 * RXRPC_CHARGE_ACCEPT cmsg path, not the BSD listen path. */
	return false;
}

/*
 * Post-bind option churn.  Most SOL_RXRPC setsockopts reject with
 * -EINVAL once rx_local is bound; we still emit a handful so the
 * dispatcher's bound-state reject arm is exercised.  The one option
 * that's reliably reachable post-bind via getsockopt is
 * RXRPC_SUPPORTED_CMSG — exercise that on every iteration too.
 */
static void rxrpc_walk_setsockopts(int fd, __unused__ struct socket_triplet *triplet,
				   unsigned int n)
{
	unsigned int i;
	unsigned int level;
	int excl;
	int supported;
	socklen_t slen;

	for (i = 0; i < n; i++) {
		switch (i & 0x3) {
		case 0:
			level = rnd_modulo_u32(3);
			(void) setsockopt(fd, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL,
					  &level, sizeof(level));
			break;
		case 1:
			excl = RAND_BOOL();
			(void) setsockopt(fd, SOL_RXRPC, RXRPC_EXCLUSIVE_CONNECTION,
					  &excl, sizeof(excl));
			break;
		case 2:
			supported = 0;
			slen = sizeof(supported);
			(void) getsockopt(fd, SOL_RXRPC, RXRPC_SUPPORTED_CMSG,
					  &supported, &slen);
			break;
		case 3:
			/* Undersized buffer to exercise the early
			 * size-validation reject in the getsockopt path. */
			slen = (socklen_t) (rnd_modulo_u32(sizeof(int)));
			(void) getsockopt(fd, SOL_RXRPC, RXRPC_SUPPORTED_CMSG,
					  &supported, &slen);
			break;
		}
	}
}

/*
 * Build a START-OF-CALL cmsg burst.  RXRPC_USER_CALL_ID is mandatory
 * (rxrpc_sendmsg_cmsg returns -EINVAL without it); the rest are
 * randomised in/out per walk to fan over the cmsg parser branches.
 *
 * Returns the total cmsghdr-payload byte length written to buf.
 */
static size_t rxrpc_build_cmsg_burst(unsigned char *buf, size_t buflen,
				     unsigned long call_id)
{
	struct cmsghdr *cmsg;
	struct msghdr fake;
	size_t used = 0;
	size_t need;

	memset(&fake, 0, sizeof(fake));
	fake.msg_control = buf;
	fake.msg_controllen = buflen;

	/* Mandatory: RXRPC_USER_CALL_ID */
	need = CMSG_SPACE(sizeof(call_id));
	if (used + need > buflen)
		return used;
	cmsg = (struct cmsghdr *) (buf + used);
	cmsg->cmsg_level = SOL_RXRPC;
	cmsg->cmsg_type  = RXRPC_USER_CALL_ID;
	cmsg->cmsg_len   = CMSG_LEN(sizeof(call_id));
	memcpy(CMSG_DATA(cmsg), &call_id, sizeof(call_id));
	used += need;

	/* Optional: RXRPC_TX_LENGTH (s64 — kernel reads __s64) */
	if (RAND_BOOL()) {
		long long tx_len = (long long) (rnd_modulo_u32(4096));

		need = CMSG_SPACE(sizeof(tx_len));
		if (used + need > buflen)
			return used;
		cmsg = (struct cmsghdr *) (buf + used);
		cmsg->cmsg_level = SOL_RXRPC;
		cmsg->cmsg_type  = RXRPC_TX_LENGTH;
		cmsg->cmsg_len   = CMSG_LEN(sizeof(tx_len));
		memcpy(CMSG_DATA(cmsg), &tx_len, sizeof(tx_len));
		used += need;
	}

	/* Optional: one of RXRPC_EXCLUSIVE_CALL or RXRPC_UPGRADE_SERVICE
	 * — both are zero-payload flag cmsgs that the kernel records in
	 * the call's per-call exclusive/upgrade flags during start. */
	if (RAND_BOOL()) {
		int type = RAND_BOOL() ? RXRPC_EXCLUSIVE_CALL
				       : RXRPC_UPGRADE_SERVICE;

		need = CMSG_SPACE(0);
		if (used + need > buflen)
			return used;
		cmsg = (struct cmsghdr *) (buf + used);
		cmsg->cmsg_level = SOL_RXRPC;
		cmsg->cmsg_type  = type;
		cmsg->cmsg_len   = CMSG_LEN(0);
		used += need;
	}

	/* Optional: RXRPC_SET_CALL_TIMEOUT (1..3 unsigned ints — kernel
	 * accepts variable-length payloads to arm hard / idle / normal
	 * timeouts in order). */
	if (RAND_BOOL()) {
		unsigned int timeouts[3];
		unsigned int nr = 1 + (rnd_modulo_u32(3));
		size_t payload = nr * sizeof(unsigned int);
		unsigned int j;

		for (j = 0; j < nr; j++)
			timeouts[j] = (unsigned int) (rnd_modulo_u32(5000));

		need = CMSG_SPACE(payload);
		if (used + need > buflen)
			return used;
		cmsg = (struct cmsghdr *) (buf + used);
		cmsg->cmsg_level = SOL_RXRPC;
		cmsg->cmsg_type  = RXRPC_SET_CALL_TIMEOUT;
		cmsg->cmsg_len   = CMSG_LEN(payload);
		memcpy(CMSG_DATA(cmsg), timeouts, payload);
		used += need;
	}

	return used;
}

static void rxrpc_data_leg(int parent_fd, __unused__ int child_fd,
			   struct socket_triplet *triplet)
{
	struct sockaddr_rxrpc peer;
	struct msghdr msg;
	struct iovec iov;
	unsigned char cmsgbuf[CMSG_SPACE(sizeof(unsigned long))
			      + CMSG_SPACE(sizeof(long long))
			      + CMSG_SPACE(0)
			      + CMSG_SPACE(3 * sizeof(unsigned int))];
	unsigned char payload[64];
	unsigned char rcvbuf[256];
	unsigned char rcvcmsg[CMSG_SPACE(256)];
	struct msghdr rmsg;
	struct iovec riov;
	unsigned long call_id;
	size_t cmsg_used;
	unsigned short service;
	unsigned short port;

	/* Per-walk monotonically-increasing call id (opaque to kernel). */
	call_id = ++rxrpc_next_call_id;

	memset(cmsgbuf, 0, sizeof(cmsgbuf));
	cmsg_used = rxrpc_build_cmsg_burst(cmsgbuf, sizeof(cmsgbuf), call_id);
	if (cmsg_used == 0)
		return;

	/* Synthesised peer: loopback transport, small non-zero service id,
	 * randomised UDP port.  Delivery is not the point — the cmsg
	 * parser runs before the packet leaves rxrpc_sendmsg_cmsg(). */
	service = (unsigned short) (1 + (rnd_modulo_u32(1024)));
	port = (unsigned short) (1024 + (rnd_modulo_u32(60000)));
	rxrpc_fill_addr(&peer, triplet->protocol, service, port);

	generate_rand_bytes(payload, sizeof(payload));
	iov.iov_base = payload;
	iov.iov_len  = sizeof(payload);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name       = &peer;
	msg.msg_namelen    = sizeof(peer);
	msg.msg_iov        = &iov;
	msg.msg_iovlen     = 1;
	msg.msg_control    = cmsgbuf;
	msg.msg_controllen = cmsg_used;

	(void) sendmsg(parent_fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);

	/* Drain any cmsg metadata the kernel queued back (LOCAL_ERROR
	 * for unreachable peer, ABORT, etc.).  Non-blocking — if nothing
	 * is queued we just return -EAGAIN. */
	memset(&rmsg, 0, sizeof(rmsg));
	riov.iov_base = rcvbuf;
	riov.iov_len  = sizeof(rcvbuf);
	rmsg.msg_iov        = &riov;
	rmsg.msg_iovlen     = 1;
	rmsg.msg_control    = rcvcmsg;
	rmsg.msg_controllen = sizeof(rcvcmsg);
	(void) recvmsg(parent_fd, &rmsg, MSG_DONTWAIT);
}

const struct socket_family_grammar grammar_rxrpc = {
	.family			= PF_RXRPC,
	.name			= "rxrpc",
	.can_run		= rxrpc_can_run,
	.pick_triplet		= rxrpc_pick_triplet,
	.configure_pre_bind	= rxrpc_configure_pre_bind,
	.bind_or_connect	= rxrpc_bind_or_connect,
	.needs_listen_accept	= rxrpc_needs_listen_accept,
	.walk_setsockopts	= rxrpc_walk_setsockopts,
	.data_leg		= rxrpc_data_leg,
};
