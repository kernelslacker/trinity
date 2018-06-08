
#ifdef USE_ROSE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <bits/sockaddr.h>
#include <netax25/ax25.h> /* for ax25_address in rose.h */
#include <netrose/rose.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY
#include "compat.h"

static void rose_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_rose *rose;

	rose = zmalloc(sizeof(struct sockaddr_rose));

	rose->srose_family = PF_ROSE;
	rose->srose_addr.rose_addr[0] = rnd();
	rose->srose_addr.rose_addr[1] = rnd();
	rose->srose_addr.rose_addr[2] = rnd();
	rose->srose_addr.rose_addr[3] = rnd();
	rose->srose_addr.rose_addr[4] = rnd();

	generate_rand_bytes((unsigned char *) rose->srose_call.ax25_call, sizeof(ax25_address));

	rose->srose_ndigis = rnd();

	*addr = (struct sockaddr *) rose;
	*addrlen = sizeof(struct sockaddr_rose);
}

static const unsigned int rose_opts[] = {
	ROSE_DEFER, ROSE_T1, ROSE_T2, ROSE_T3,
	ROSE_IDLE, ROSE_QBITINCL, ROSE_HOLDBACK,
};

static void rose_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_ROSE;
	so->optname = RAND_ARRAY(rose_opts);
}
const struct netproto proto_rose = {
	.name = "rose",
	//     .socket = rose_rand_socket,
	.setsockopt = rose_setsockopt,
	.gen_sockaddr = rose_gen_sockaddr,
};
#endif
