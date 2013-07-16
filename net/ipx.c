#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/ipx.h>
#include <stdlib.h>
#include "net.h"

void gen_ipx(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_ipx *ipx;
	unsigned int i;

	ipx = malloc(sizeof(struct sockaddr_ipx));
	if (ipx == NULL)
		return;

	ipx->sipx_family = PF_IPX;
	ipx->sipx_port = rand();
	ipx->sipx_network = rand();
	for (i = 0; i < 6; i++)
		ipx->sipx_node[i] = rand();
	ipx->sipx_type = rand();
	ipx->sipx_zero = rand() % 2;
	*addr = (unsigned long) ipx;
	*addrlen = sizeof(struct sockaddr_ipx);
}

void ipx_rand_socket(struct proto_type *pt)
{
	pt->protocol = rand() % PROTO_MAX;
	pt->type = SOCK_DGRAM;
}
