#include <stdlib.h>
#include <linux/udp.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY
#include "compat.h"

static const unsigned int udplite_opts[] = {
	UDP_CORK, UDP_ENCAP, UDPLITE_SEND_CSCOV, UDPLITE_RECV_CSCOV,
};

void udplite_setsockopt(struct sockopt *so)
{
	char *optval;
	unsigned char val;

	val = RAND_ARRAY(udplite_opts);
	so->optname = udplite_opts[val];

	switch (so->optname) {
	case UDP_CORK:
		break;
	case UDP_ENCAP:
		optval = (char *) so->optval;
		optval[0] = RAND_RANGE(1, 3);        // Encapsulation types.
		break;
	case UDPLITE_SEND_CSCOV:
		break;
	case UDPLITE_RECV_CSCOV:
		break;
	default:
		break;
	}
}
