#include <stdlib.h>
#include <netinet/udp.h>
#include "net.h"
#include "random.h"
#include "compat.h"

#ifndef UDP_NO_CHECK6_TX
#define UDP_NO_CHECK6_TX	101
#endif
#ifndef UDP_NO_CHECK6_RX
#define UDP_NO_CHECK6_RX	102
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT		103
#endif
#ifndef UDP_GRO
#define UDP_GRO			104
#endif

#ifndef UDP_ENCAP_GTP0
#define UDP_ENCAP_GTP0		4
#endif
#ifndef UDP_ENCAP_GTP1U
#define UDP_ENCAP_GTP1U		5
#endif
#ifndef UDP_ENCAP_RXRPC
#define UDP_ENCAP_RXRPC		6
#endif

static const unsigned int udp_opts[] = {
	UDP_CORK, UDP_ENCAP,
	UDP_NO_CHECK6_TX, UDP_NO_CHECK6_RX,
	UDP_SEGMENT, UDP_GRO,
};

void udp_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	unsigned short *optval16;
	char *optval;

	so->optname = RAND_ARRAY(udp_opts);

	switch (so->optname) {
	case UDP_CORK:
	case UDP_NO_CHECK6_TX:
	case UDP_NO_CHECK6_RX:
	case UDP_GRO:
		break;

	case UDP_ENCAP:
		optval = (char *) so->optval;
		optval[0] = RAND_RANGE(1, UDP_ENCAP_RXRPC);
		break;

	case UDP_SEGMENT:
		/* GSO segment size — typical MTU-derived values are most interesting. */
		optval16 = (unsigned short *) so->optval;
		switch (rand() % 5) {
		case 0: *optval16 = 0; break;
		case 1: *optval16 = 1; break;
		case 2: *optval16 = 1400; break;		/* ~MTU minus headers */
		case 3: *optval16 = 65535; break;		/* max */
		case 4: *optval16 = rand() % 65536; break;
		}
		so->optlen = sizeof(unsigned short);
		break;

	default:
		break;
	}
}
