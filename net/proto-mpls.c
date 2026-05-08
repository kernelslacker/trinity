/* MPLS socket (AF_MPLS=28) handler */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <linux/if_ether.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "net.h"
#include "random.h"
#include "socket-family-grammar.h"
#include "trinity.h"
#include "compat.h"

#ifndef ETH_P_MPLS_UC
#define ETH_P_MPLS_UC 0x8847
#endif
#ifndef ETH_P_MPLS_MC
#define ETH_P_MPLS_MC 0x8848
#endif

/* MPLS label stack entry: 20-bit label, 3-bit TC, 1-bit BoS, 8-bit TTL */
struct sockaddr_mpls {
	unsigned short smpls_family;
	uint32_t       smpls_addr; /* label stack entry in network byte order */
};

static void mpls_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_mpls *sa;

	sa = zmalloc(sizeof(struct sockaddr_mpls));
	sa->smpls_family = AF_MPLS;
	/* keep label in valid range 0..0xFFFFF, set BoS bit, TTL=64 */
	sa->smpls_addr = htonl(((rand() & 0xFFFFF) << 12) | 0x100 | 64);

	*addr = (struct sockaddr *)sa;
	*addrlen = sizeof(struct sockaddr_mpls);
}

static struct socket_triplet mpls_triplets[] = {
	{ .family = PF_MPLS, .protocol = ETH_P_MPLS_UC, .type = SOCK_RAW },
	{ .family = PF_MPLS, .protocol = ETH_P_MPLS_MC, .type = SOCK_RAW },
};

const struct netproto proto_mpls = {
	.name = "mpls",
	.gen_sockaddr = mpls_gen_sockaddr,
	.valid_triplets = mpls_triplets,
	.nr_triplets = ARRAY_SIZE(mpls_triplets),
};

/*
 * grammar_mpls — coherent walk for AF_MPLS (Multi-Protocol Label
 * Switching, RFC 3032 / RFC 5462 label-stack).
 *
 * Reality check.  Upstream net/mpls/af_mpls.c does NOT call
 * sock_register() — PF_MPLS only registers RTNL handlers
 * (RTM_NEWROUTE / RTM_DELROUTE / RTM_GETROUTE / RTM_GETNETCONF) under
 * rtm_family=AF_MPLS, gated on CONFIG_MPLS_ROUTING.  socket(AF_MPLS,
 * ...) returns -EAFNOSUPPORT for every type/protocol combination on
 * stock Linux because no net_proto_family is installed at the
 * net_families[PF_MPLS] slot.  The interesting MPLS surface lives
 * behind NETLINK_ROUTE messages with rtm_family=AF_MPLS (route /
 * label / NEWNEIGH management) plus the MPLS_IPTUNNEL encap path
 * reached through ip_tunnel; neither is a socket-family axis.
 *
 * Why register a grammar here.  Two reasons:
 *   1. Symmetry with the rest of the per-family grammar registry —
 *      the design spec lists every live socket family in the in-tree
 *      fuzz config, with AF_MPLS in the "smaller live families" group.
 *      Filling the slot keeps the registry dense and self-documenting.
 *   2. If a future kernel patch (or a non-upstream fork) ever does
 *      register an AF_MPLS socket family — there has been periodic
 *      list discussion about exposing the label-stack write/read path
 *      through SOCK_RAW for tools that emit raw MPLS frames — the
 *      grammar becomes live without any registry edit.  Until then
 *      can_run latches off after the first probe and the grammar
 *      contributes nothing to runtime cost.
 *
 *   socket(AF_MPLS, SOCK_RAW, ETH_P_MPLS_UC | ETH_P_MPLS_MC)
 *     -> can_run probes once and latches mpls_supported=0 the first
 *        time socket() returns -EAFNOSUPPORT.  Subsequent walks are
 *        filtered out at sfg_pick_random_active() time without
 *        re-probing so the per-walk cost is a single load on the
 *        fast path.
 *     -> defence-in-depth on the off chance the family becomes live:
 *          * configure_pre_bind churns generic SOL_SOCKET options
 *            (SO_RCVBUF / SO_SNDBUF / SO_PRIORITY / SO_REUSEADDR) —
 *            these would land on the common sock layer regardless of
 *            family-specific ops
 *          * walk_setsockopts cycles the same SOL_SOCKET set in a
 *            deterministic order so each walk hits a different subset
 *            of sock_setsockopt's switch arms
 *          * bind_or_connect uses the existing sockaddr_mpls
 *            constructor (valid 20-bit label, BoS bit set, TTL=64)
 *          * data_leg builds a 1-3 entry MPLS label stack as the
 *            sendmsg payload (20-bit label / 3-bit TC / 1-bit BoS /
 *            8-bit TTL packed into a 32-bit network-order word per
 *            RFC 3032) so that if the path ever runs end-to-end the
 *            kernel sees a wire-shaped frame instead of random bytes
 *
 * needs_listen_accept = false.  PF_MPLS valid_triplets are SOCK_RAW
 * only; raw sockets have no listen()/accept() phase even when the
 * family is registered.
 *
 * cmsg = none.  No SOL_MPLS cmsg parser exists upstream and none of
 * the generic ip-layer cmsgs apply to a hypothetical AF_MPLS raw
 * socket; leaving gen_cmsg NULL keeps the data leg minimal.
 */

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0x4000
#endif

/* Per-process probe cache.  -1 untested, 0 unsupported, 1 supported.
 * On stock upstream kernels this stays at 0 after the first probe
 * because no sock_register() exists for PF_MPLS. */
static int mpls_supported = -1;

static bool mpls_can_run(void)
{
	int fd;

	if (mpls_supported >= 0)
		return mpls_supported == 1;

	fd = socket(AF_MPLS, SOCK_RAW, ETH_P_MPLS_UC);
	if (fd < 0) {
		mpls_supported = 0;
		return false;
	}
	close(fd);
	mpls_supported = 1;
	return true;
}

static void mpls_pick_triplet(struct socket_triplet *out)
{
	out->family = PF_MPLS;
	out->type = SOCK_RAW;
	out->protocol = RAND_BOOL() ? ETH_P_MPLS_UC : ETH_P_MPLS_MC;
}

/*
 * Pre-bind option churn.  All SOL_SOCKET — there is no SOL_MPLS
 * sockopt set in upstream UAPI (linux/mpls.h has zero options).  The
 * common sock layer's locked-resize / priority / reuseaddr arms are
 * the only writeable surface a hypothetical AF_MPLS raw socket
 * exposes.
 */
static void mpls_configure_pre_bind(int fd, __unused__ struct socket_triplet *triplet)
{
	int rcvbuf = 1024 + (rand() & 0xffff);
	int sndbuf = 1024 + (rand() & 0xffff);
	int reuse = RAND_BOOL();
	int priority = rand() & 0x7;

	(void) setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	(void) setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
	(void) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	(void) setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
}

/*
 * Coherent SOL_SOCKET walk.  Cycle through a deterministic option set
 * so each walk lands on a fresh subset of sock_setsockopt's switch
 * arms.  Values are bounded so the range-check arms accept them and
 * the writes settle on sk fields.
 */
static void mpls_walk_setsockopts(int fd, __unused__ struct socket_triplet *triplet,
				  unsigned int n)
{
	static const int opts_seq[] = {
		SO_RCVBUF, SO_SNDBUF, SO_REUSEADDR, SO_PRIORITY,
		SO_RCVLOWAT, SO_TIMESTAMP,
	};
	unsigned int i;
	int v;

	for (i = 0; i < n; i++) {
		int opt = opts_seq[i % ARRAY_SIZE(opts_seq)];

		switch (opt) {
		case SO_RCVBUF:
		case SO_SNDBUF:
			v = 1024 + (rand() & 0xffff);
			break;
		case SO_REUSEADDR:
		case SO_TIMESTAMP:
			v = i & 1;
			break;
		case SO_PRIORITY:
			v = rand() & 0x7;
			break;
		case SO_RCVLOWAT:
			v = 1 + (rand() & 0xff);
			break;
		default:
			v = 1;
			break;
		}
		(void) setsockopt(fd, SOL_SOCKET, opt, &v, sizeof(v));
	}
}

static int mpls_bind_or_connect(int fd, __unused__ struct socket_triplet *triplet)
{
	struct sockaddr_mpls sa;

	memset(&sa, 0, sizeof(sa));
	sa.smpls_family = AF_MPLS;
	/* Valid 20-bit label, BoS bit set, TTL=64 — same shape as
	 * mpls_gen_sockaddr above so the kernel-side address parser (if
	 * one ever exists) sees a well-formed label stack entry. */
	sa.smpls_addr = htonl(((rand() & 0xFFFFF) << 12) | 0x100 | 64);

	if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
		return -1;
	return 0;
}

static bool mpls_needs_listen_accept(__unused__ struct socket_triplet *triplet)
{
	/* SOCK_RAW only; no listen()/accept(). */
	return false;
}

/*
 * Build a small MPLS label stack as the sendmsg payload.  Each entry
 * is a 32-bit network-order word: 20-bit label, 3-bit TC, 1-bit BoS,
 * 8-bit TTL (RFC 3032).  BoS bit set on the last entry only so a
 * label-stack walker terminates correctly.
 */
static size_t mpls_build_label_stack(uint32_t *stack, size_t max_entries)
{
	size_t n = 1 + (rand() % max_entries);
	size_t i;

	for (i = 0; i < n; i++) {
		uint32_t label = rand() & 0xFFFFF;
		uint32_t tc = rand() & 0x7;
		uint32_t bos = (i == n - 1) ? 1 : 0;
		uint32_t ttl = 1 + (rand() & 0xff);

		stack[i] = htonl((label << 12) | (tc << 9) | (bos << 8) | ttl);
	}
	return n * sizeof(uint32_t);
}

static void mpls_data_leg(int parent_fd, __unused__ int child_fd,
			  __unused__ struct socket_triplet *triplet)
{
	struct sockaddr_mpls peer;
	struct msghdr msg, rmsg;
	struct iovec iov, riov;
	uint32_t label_stack[3];
	unsigned char rcvbuf[256];
	size_t payload_len;

	memset(&peer, 0, sizeof(peer));
	peer.smpls_family = AF_MPLS;
	peer.smpls_addr = htonl(((rand() & 0xFFFFF) << 12) | 0x100 | 64);

	payload_len = mpls_build_label_stack(label_stack, ARRAY_SIZE(label_stack));
	iov.iov_base = label_stack;
	iov.iov_len = payload_len;

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
}

const struct socket_family_grammar grammar_mpls = {
	.family			= PF_MPLS,
	.name			= "mpls",
	.can_run		= mpls_can_run,
	.pick_triplet		= mpls_pick_triplet,
	.configure_pre_bind	= mpls_configure_pre_bind,
	.bind_or_connect	= mpls_bind_or_connect,
	.needs_listen_accept	= mpls_needs_listen_accept,
	.walk_setsockopts	= mpls_walk_setsockopts,
	.data_leg		= mpls_data_leg,
};
