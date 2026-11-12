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
	unsigned int *optval32 = (unsigned int *) so->optval;

	so->optname = RAND_ARRAY(udp_opts);

	switch (so->optname) {
	case UDP_CORK:
	case UDP_NO_CHECK6_TX:
	case UDP_NO_CHECK6_RX:
	case UDP_GRO:
		/* A flag, on for any value but 0. */
		*optval32 = RAND_BOOL();
		so->optlen = sizeof(unsigned int);
		break;

	case UDP_ENCAP: {
		/* udp_lib_setsockopt() takes ESP-in-UDP, L2TP or 0 for none,
		 * and refuses the other types: one draw in eight takes any,
		 * for the refusal. */
		static const unsigned int encaps[] = {
			0, UDP_ENCAP_ESPINUDP, UDP_ENCAP_L2TPINUDP,
		};

		if (ONE_IN(8))
			*optval32 = RAND_RANGE(1, UDP_ENCAP_RXRPC);
		else
			*optval32 = RAND_ARRAY(encaps);
		so->optlen = sizeof(unsigned int);
		break;
	}

	case UDP_SEGMENT:
		/* GSO segment size — typical MTU-derived values are most interesting.
		 * udp_lib_setsockopt() reads an int, refusing a shorter one. */
		switch (rnd_modulo_u32(5)) {
		case 0: *optval32 = 0; break;
		case 1: *optval32 = 1; break;
		case 2: *optval32 = 1400; break;		/* ~MTU minus headers */
		case 3: *optval32 = 65535; break;		/* max */
		case 4: *optval32 = rnd_modulo_u32(65536); break;
		}
		so->optlen = sizeof(unsigned int);
		break;

	default:
		break;
	}
}
