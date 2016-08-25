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

static void generate_rxrpc(void)
{
	generate_socket(PF_RXRPC, PF_INET, SOCK_DGRAM);
}

const struct netproto proto_rxrpc = {
	.name = "rxrpc",
//	.socket = rxrpc_rand_socket,
	.generate = generate_rxrpc,
	.setsockopt = rxrpc_setsockopt,
};
