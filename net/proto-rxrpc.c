#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <linux/rxrpc.h>
#include "net.h"
#include "random.h"
#include "compat.h"

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

	rxrpc = zmalloc(sizeof(struct sockaddr_rxrpc));
	rxrpc->srx_family = AF_RXRPC;
	rxrpc->srx_service = rand();
	rxrpc->transport_type = SOCK_DGRAM;

	rxrpc->transport_len = sizeof(struct sockaddr_in);
	rxrpc->transport.sin.sin_family = AF_INET;
	rxrpc->transport.sin.sin_addr.s_addr = random_ipv4_address();
	rxrpc->transport.sin.sin_port = htons(rand() % 65536);

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
		*optval32 = rand() % 3;
		so->optlen = sizeof(unsigned int);
		break;
	case RXRPC_UPGRADEABLE_SERVICE:
		/* two unsigned short values: service[0] -> service[1] */
		optval_us = (unsigned short *) so->optval;
		optval_us[0] = rand();
		optval_us[1] = rand();
		so->optlen = 2 * sizeof(unsigned short);
		break;
	default:
		optval32 = (unsigned int *) so->optval;
		*optval32 = rand();
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
