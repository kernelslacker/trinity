#include <stdlib.h>
#include "net.h"
#include "compat.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY

static const unsigned int rxrpc_opts[] = {
	RXRPC_USER_CALL_ID, RXRPC_ABORT, RXRPC_ACK, RXRPC_NET_ERROR,
	RXRPC_BUSY, RXRPC_LOCAL_ERROR, RXRPC_NEW_CALL, RXRPC_ACCEPT,
};

#define SOL_RXRPC 272

static void rxrpc_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_RXRPC;

	so->optname = RAND_ARRAY(rxrpc_opts);
}

static struct socket_triplet rxrpc_triplet[] = {
	{ .family = PF_RXRPC, .protocol = PF_INET, .type = SOCK_DGRAM },
};

const struct netproto proto_rxrpc = {
	.name = "rxrpc",
//	.socket = rxrpc_rand_socket,
	.setsockopt = rxrpc_setsockopt,
	.valid_triplets = rxrpc_triplet,
	.nr_triplets = ARRAY_SIZE(rxrpc_triplet),
};
