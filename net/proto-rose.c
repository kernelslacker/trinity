#include "config.h"

#ifdef USE_ROSE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <bits/sockaddr.h>
#include <linux/ax25.h> /* for ax25_address in rose.h */
#include <netrose/rose.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY
#include "compat.h"

void rose_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_rose *rose;

	rose = zmalloc(sizeof(struct sockaddr_rose));

	rose->srose_family = PF_ROSE;
	rose->srose_addr.rose_addr[0] = rand();
	rose->srose_addr.rose_addr[1] = rand();
	rose->srose_addr.rose_addr[2] = rand();
	rose->srose_addr.rose_addr[3] = rand();
	rose->srose_addr.rose_addr[4] = rand();

	generate_rand_bytes((unsigned char *) rose->srose_call.ax25_call, sizeof(ax25_address));

	rose->srose_ndigis = rand();

	*addr = (struct sockaddr *) rose;
	*addrlen = sizeof(struct sockaddr_rose);
}

static const unsigned int rose_opts[] = {
	ROSE_DEFER, ROSE_T1, ROSE_T2, ROSE_T3,
	ROSE_IDLE, ROSE_QBITINCL, ROSE_HOLDBACK,
};

void rose_setsockopt(struct sockopt *so)
{
	unsigned char val;

	val = RAND_ARRAY(rose_opts);
	so->optname = rose_opts[val];
}
#endif
