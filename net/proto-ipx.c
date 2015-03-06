#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <netipx/ipx.h>
#include "net.h"
#include "random.h"
#include "utils.h"

void ipx_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_ipx *ipx;
	unsigned int i;

	ipx = zmalloc(sizeof(struct sockaddr_ipx));

	ipx->sipx_family = PF_IPX;
	ipx->sipx_port = rand();
	ipx->sipx_network = rand();
	for (i = 0; i < 6; i++)
		ipx->sipx_node[i] = rand();
	ipx->sipx_type = rand();
	ipx->sipx_zero = RAND_BOOL();
	*addr = (struct sockaddr *) ipx;
	*addrlen = sizeof(struct sockaddr_ipx);
}

void ipx_rand_socket(struct socket_triplet *st)
{
	st->protocol = rand() % PROTO_MAX;
	st->type = SOCK_DGRAM;
}

void ipx_setsockopt(struct sockopt *so)
{
	so->level = SOL_IPX;
	so->optname = IPX_TYPE;
}
