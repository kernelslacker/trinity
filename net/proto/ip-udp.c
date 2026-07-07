#include <netinet/udp.h>
#include "net.h"
#include "random.h"
#include "kernel/udp.h"
#include "rnd.h"

static const unsigned int udp_opts[] = {
	UDP_CORK, UDP_ENCAP,
	UDP_NO_CHECK6_TX, UDP_NO_CHECK6_RX,
	UDP_SEGMENT, UDP_GRO,
};

void udp_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	unsigned short *optval16;

	so->optname = RAND_ARRAY(udp_opts);

	switch (so->optname) {
	case UDP_CORK:
	case UDP_NO_CHECK6_TX:
	case UDP_NO_CHECK6_RX:
	case UDP_GRO:
		so->optlen = sizeof(unsigned int);
		break;

	case UDP_ENCAP: {
		unsigned int *optval32 = (unsigned int *) so->optval;
		*optval32 = RAND_RANGE(1, UDP_ENCAP_RXRPC);
		so->optlen = sizeof(unsigned int);
		break;
	}

	case UDP_SEGMENT:
		/* GSO segment size — typical MTU-derived values are most interesting. */
		optval16 = (unsigned short *) so->optval;
		switch (rnd_modulo_u32(5)) {
		case 0: *optval16 = 0; break;
		case 1: *optval16 = 1; break;
		case 2: *optval16 = 1400; break;		/* ~MTU minus headers */
		case 3: *optval16 = 65535; break;		/* max */
		case 4: *optval16 = rnd_modulo_u32(65536); break;
		}
		so->optlen = sizeof(unsigned short);
		break;

	default:
		break;
	}
}
