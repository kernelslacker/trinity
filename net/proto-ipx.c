#ifdef USE_IPX
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <netipx/ipx.h>
#include "net.h"
#include "random.h"
#include "utils.h"

static void ipx_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_ipx *ipx;
	unsigned int i;

	ipx = zmalloc(sizeof(struct sockaddr_ipx));

	ipx->sipx_family = PF_IPX;
	ipx->sipx_port = rnd();
	ipx->sipx_network = rnd();
	for (i = 0; i < 6; i++)
		ipx->sipx_node[i] = rnd();
	ipx->sipx_type = rnd();
	ipx->sipx_zero = RAND_BOOL();
	*addr = (struct sockaddr *) ipx;
	*addrlen = sizeof(struct sockaddr_ipx);
}

static void ipx_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_IPX;
	so->optname = IPX_TYPE;
}

static struct socket_triplet ipx_triplet[] = {
	{ .family = PF_IPX, .protocol = 0, .type = SOCK_DGRAM },
};

const struct netproto proto_ipx = {
	.name = "ipx",
	.setsockopt = ipx_setsockopt,
	.gen_sockaddr = ipx_gen_sockaddr,
	.valid_triplets = ipx_triplet,
	.nr_triplets = ARRAY_SIZE(ipx_triplet),
};

#endif
