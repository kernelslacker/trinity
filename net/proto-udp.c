#include <stdlib.h>
#include <netinet/udp.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// ARRAY_SIZE
#include "compat.h"

#define NR_SOL_UDP_OPTS ARRAY_SIZE(udp_opts)
static const unsigned int udp_opts[] = { UDP_CORK, UDP_ENCAP };

void udp_setsockopt(struct sockopt *so)
{
	unsigned char val;
	char *optval;

	val = rand() % NR_SOL_UDP_OPTS;
	so->optname = udp_opts[val];

	switch (so->optname) {
	case UDP_CORK:
		break;
	case UDP_ENCAP:
		optval = (char *) so->optval;
		optval[0] = RAND_RANGE(1, 3);        // Encapsulation types.
		break;
	default:
		break;
	}
}
