#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_ether.h> /* for ETH_ALEN in if_pppox.h */
#include <linux/if_pppox.h>
#include <linux/if_pppol2tp.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"
#include "compat.h"

#pragma GCC diagnostic ignored "-Waddress-of-packed-member"

static void pppox_PX_PROTO_OE(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_pppox *pppox;
	unsigned int i;

	pppox = zmalloc(sizeof(struct sockaddr_pppox));

	pppox->sa_family = PF_PPPOX;
	pppox->sa_protocol = rnd() % 3;

	pppox->sa_addr.pppoe.sid = rnd();
	for (i = 0; i < ETH_ALEN; i++)
		pppox->sa_addr.pppoe.remote[i] = rnd();
	for (i = 0; i < IFNAMSIZ; i++)
		pppox->sa_addr.pppoe.dev[i] = rnd();

#ifdef USE_PPPOX_PPTP
	pppox->sa_addr.pptp.call_id = rnd();
	pppox->sa_addr.pptp.sin_addr.s_addr = random_ipv4_address();
#endif

	*addr = (struct sockaddr *) pppox;
	*addrlen = sizeof(struct sockaddr_pppox);
}

static void pppox_PX_PROTO_OL2TP_PPPoL2TP(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_pppol2tp *pppol2tp;

	pppol2tp = zmalloc(sizeof(struct sockaddr_pppol2tp));

	pppol2tp->sa_family = PF_PPPOX;
	pppol2tp->sa_protocol = rnd() % 3;
	pppol2tp->pppol2tp.pid = get_pid();
	pppol2tp->pppol2tp.fd = get_random_fd();
	pppol2tp->pppol2tp.addr.sin_addr.s_addr = random_ipv4_address();
	pppol2tp->pppol2tp.s_tunnel = rnd();
	pppol2tp->pppol2tp.s_session = rnd();
	pppol2tp->pppol2tp.d_tunnel = rnd();
	pppol2tp->pppol2tp.d_session = rnd();
	*addr = (struct sockaddr *) pppol2tp;
	*addrlen = sizeof(struct sockaddr_pppol2tp);
}

static void pppox_PX_PROTO_OL2TP_PPPoL2TPin6(__unused__ struct sockaddr **addr,
						__unused__ socklen_t *addrlen)
{
#ifdef USE_PPPOL2TPIN6
	struct sockaddr_pppol2tpin6 *pppol2tpin6;

	pppol2tpin6 = zmalloc(sizeof(struct sockaddr_pppol2tpin6));

	pppol2tpin6->sa_family = PF_PPPOX;
	pppol2tpin6->sa_protocol = rnd() % 3;
	pppol2tpin6->pppol2tp.pid = get_pid();
	pppol2tpin6->pppol2tp.fd = get_random_fd();
	pppol2tpin6->pppol2tp.s_tunnel = rnd();
	pppol2tpin6->pppol2tp.s_session = rnd();
	pppol2tpin6->pppol2tp.d_tunnel = rnd();
	pppol2tpin6->pppol2tp.d_session = rnd();
	pppol2tpin6->pppol2tp.addr.sin6_family = AF_INET6;
	pppol2tpin6->pppol2tp.addr.sin6_port = rnd();
	pppol2tpin6->pppol2tp.addr.sin6_flowinfo = rnd();
	pppol2tpin6->pppol2tp.addr.sin6_addr.s6_addr32[0] = 0;
	pppol2tpin6->pppol2tp.addr.sin6_addr.s6_addr32[1] = 0;
	pppol2tpin6->pppol2tp.addr.sin6_addr.s6_addr32[2] = 0;
	pppol2tpin6->pppol2tp.addr.sin6_addr.s6_addr32[3] = htonl(1);
	pppol2tpin6->pppol2tp.addr.sin6_scope_id = rnd();
	*addr = (struct sockaddr *) pppol2tpin6;
	*addrlen = sizeof(struct sockaddr_pppol2tpin6);
#endif
}

static void pppox_PX_PROTO_OL2TP_PPPoL2TPv3(__unused__ struct sockaddr **addr,
						__unused__ socklen_t *addrlen)
{
#ifdef USE_PPPOL2TPV3
	struct sockaddr_pppol2tpv3 *pppol2tpv3;

	pppol2tpv3 = zmalloc(sizeof(struct sockaddr_pppol2tpv3));

	pppol2tpv3->sa_family = PF_PPPOX;
	pppol2tpv3->sa_protocol = rnd() % 3;
	pppol2tpv3->pppol2tp.pid = get_pid();
	pppol2tpv3->pppol2tp.fd = get_random_fd();
	pppol2tpv3->pppol2tp.addr.sin_addr.s_addr = random_ipv4_address();
	pppol2tpv3->pppol2tp.s_tunnel = rnd();
	pppol2tpv3->pppol2tp.s_session = rnd();
	pppol2tpv3->pppol2tp.d_tunnel = rnd();
	pppol2tpv3->pppol2tp.d_session = rnd();
	*addr = (struct sockaddr *) pppol2tpv3;
	*addrlen = sizeof(struct sockaddr_pppol2tpv3);
#endif
}

static void pppox_PX_PROTO_OL2TP_PPPoL2TPv3in6(__unused__ struct sockaddr **addr,
						__unused__ socklen_t *addrlen)
{
#ifdef USE_PPPOL2TPIN6
	struct sockaddr_pppol2tpv3in6 *pppol2tpv3in6;

	pppol2tpv3in6 = zmalloc(sizeof(struct sockaddr_pppol2tpv3in6));

	pppol2tpv3in6->sa_family = PF_PPPOX;
	pppol2tpv3in6->sa_protocol = rnd() % 3;
	pppol2tpv3in6->pppol2tp.pid = get_pid();
	pppol2tpv3in6->pppol2tp.fd = get_random_fd();
	pppol2tpv3in6->pppol2tp.s_tunnel = rnd();
	pppol2tpv3in6->pppol2tp.s_session = rnd();
	pppol2tpv3in6->pppol2tp.d_tunnel = rnd();
	pppol2tpv3in6->pppol2tp.d_session = rnd();
	pppol2tpv3in6->pppol2tp.addr.sin6_family = AF_INET6;
	pppol2tpv3in6->pppol2tp.addr.sin6_port = rnd();
	pppol2tpv3in6->pppol2tp.addr.sin6_flowinfo = rnd();
	pppol2tpv3in6->pppol2tp.addr.sin6_addr.s6_addr32[0] = 0;
	pppol2tpv3in6->pppol2tp.addr.sin6_addr.s6_addr32[1] = 0;
	pppol2tpv3in6->pppol2tp.addr.sin6_addr.s6_addr32[2] = 0;
	pppol2tpv3in6->pppol2tp.addr.sin6_addr.s6_addr32[3] = random_ipv4_address();
	pppol2tpv3in6->pppol2tp.addr.sin6_scope_id = rnd();
	*addr = (struct sockaddr *) pppol2tpv3in6;
	*addrlen = sizeof(struct sockaddr_pppol2tpv3in6);
#endif
}

struct ppp_funcptr {
	void (*func)(struct sockaddr **addr, socklen_t *addrlen);
};

static void pppox_PX_PROTO_OL2TP(struct sockaddr **addr, socklen_t *addrlen)
{
	const struct ppp_funcptr pppox_px_protos[] = {
		{ .func = pppox_PX_PROTO_OL2TP_PPPoL2TP },
		{ .func = pppox_PX_PROTO_OL2TP_PPPoL2TPin6 },
		{ .func = pppox_PX_PROTO_OL2TP_PPPoL2TPv3 },
		{ .func = pppox_PX_PROTO_OL2TP_PPPoL2TPv3in6 },
	};

	pppox_px_protos[rnd() % ARRAY_SIZE(pppox_px_protos)].func(addr, addrlen);
}

static void pppox_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	const struct ppp_funcptr pppox_protos[] = {
		{ .func = pppox_PX_PROTO_OE },
		{ .func = pppox_PX_PROTO_OL2TP },
#ifdef USE_PPPOX_PPTP
//		{ .func = pppox_PX_PROTO_PPTP },	// TBD
#endif
	};

	pppox_protos[rnd() % ARRAY_SIZE(pppox_protos)].func(addr, addrlen);
}

static const unsigned int pppol2tp_opts[] = {
	PPPOL2TP_SO_DEBUG, PPPOL2TP_SO_RECVSEQ, PPPOL2TP_SO_SENDSEQ, PPPOL2TP_SO_LNSMODE,
	PPPOL2TP_SO_REORDERTO };

#define SOL_PPPOL2TP 273

static void pppol2tp_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_PPPOL2TP;
	so->optname = RAND_ARRAY(pppol2tp_opts);

	so->optlen = sizeof(int);
}

static struct socket_triplet pppox_triplets[] = {
	{ .family = PF_PPPOX, .protocol = PX_PROTO_OE, .type = SOCK_DGRAM },
	{ .family = PF_PPPOX, .protocol = PX_PROTO_OE, .type = SOCK_RAW },
	{ .family = PF_PPPOX, .protocol = PX_PROTO_OE, .type = SOCK_SEQPACKET },
	{ .family = PF_PPPOX, .protocol = PX_PROTO_OE, .type = SOCK_STREAM },

	{ .family = PF_PPPOX, .protocol = PX_PROTO_OL2TP, .type = SOCK_DGRAM },
	{ .family = PF_PPPOX, .protocol = PX_PROTO_OL2TP, .type = SOCK_RAW },
	{ .family = PF_PPPOX, .protocol = PX_PROTO_OL2TP, .type = SOCK_SEQPACKET },
	{ .family = PF_PPPOX, .protocol = PX_PROTO_OL2TP, .type = SOCK_STREAM },

	{ .family = PF_PPPOX, .protocol = PX_PROTO_PPTP, .type = SOCK_DGRAM },
	{ .family = PF_PPPOX, .protocol = PX_PROTO_PPTP, .type = SOCK_RAW },
	{ .family = PF_PPPOX, .protocol = PX_PROTO_PPTP, .type = SOCK_SEQPACKET },
	{ .family = PF_PPPOX, .protocol = PX_PROTO_PPTP, .type = SOCK_STREAM },

	// TODO: Figure out wtf '9' means.
	{ .family = PF_PPPOX, .protocol = PX_PROTO_OL2TP, .type = 9 },
	{ .family = PF_PPPOX, .protocol = PX_PROTO_PPTP, .type = 9 },
};

const struct netproto proto_pppol2tp = {
	.name = "pppol2tp",
//	.socket = pppol2tp_rand_socket,
	.setsockopt = pppol2tp_setsockopt,
	.gen_sockaddr = pppox_gen_sockaddr,
	.valid_triplets = pppox_triplets,
	.nr_triplets = ARRAY_SIZE(pppox_triplets),
};
