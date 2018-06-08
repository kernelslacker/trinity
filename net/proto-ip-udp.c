#include <stdlib.h>
#include <netinet/udp.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY
#include "compat.h"

static const unsigned int udp_opts[] = {
	UDP_CORK, UDP_ENCAP
};

void udp_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	char *optval;

	so->optname = RAND_ARRAY(udp_opts);

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
