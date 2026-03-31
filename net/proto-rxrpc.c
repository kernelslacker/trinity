#include <stdlib.h>
#include "net.h"
#include "compat.h"

/* Real setsockopt options, not cmsg types. */
#define RXRPC_MIN_SECURITY_LEVEL	4
#define RXRPC_UPGRADEABLE_SERVICE	0x200
#define RXRPC_SUPPORTED_CMSG		0x400

static const unsigned int rxrpc_opts[] = {
	RXRPC_MIN_SECURITY_LEVEL, RXRPC_UPGRADEABLE_SERVICE,
	RXRPC_SUPPORTED_CMSG,
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
	.setsockopt = rxrpc_setsockopt,
	.valid_triplets = rxrpc_triplet,
	.nr_triplets = ARRAY_SIZE(rxrpc_triplet),
};
