#include <stdlib.h>
#include "net.h"
#include "compat.h"
#include "utils.h"	// ARRAY_SIZE

#define NR_SOL_RXRPC_OPTS ARRAY_SIZE(rxrpc_opts)
static const unsigned int rxrpc_opts[] = {
	RXRPC_USER_CALL_ID, RXRPC_ABORT, RXRPC_ACK, RXRPC_NET_ERROR,
	RXRPC_BUSY, RXRPC_LOCAL_ERROR, RXRPC_NEW_CALL, RXRPC_ACCEPT };

void rxrpc_setsockopt(struct sockopt *so)
{
	unsigned char val;

	val = rand() % NR_SOL_RXRPC_OPTS;
	so->optname = rxrpc_opts[val];
}
