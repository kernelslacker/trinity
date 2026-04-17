#include <stdlib.h>
#include <linux/udp.h>
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

static const unsigned int udplite_opts[] = {
	UDP_CORK, UDP_ENCAP, UDPLITE_SEND_CSCOV, UDPLITE_RECV_CSCOV,
	UDP_NO_CHECK6_TX, UDP_NO_CHECK6_RX, UDP_SEGMENT, UDP_GRO,
};

/* Interesting checksum coverage values for UDPLite. */
static const unsigned int cscov_values[] = {
	0,	/* covers entire datagram */
	8,	/* UDP header only */
	20,	/* header + some payload */
	65535,	/* max */
};

void udplite_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	unsigned int *optval32;
	unsigned short *optval16;

	so->optname = RAND_ARRAY(udplite_opts);

	switch (so->optname) {
	case UDP_CORK:
	case UDP_NO_CHECK6_TX:
	case UDP_NO_CHECK6_RX:
	case UDP_GRO:
		break;

	case UDP_ENCAP: {
		unsigned int *encap = (unsigned int *) so->optval;
		*encap = RAND_RANGE(1, UDP_ENCAP_RXRPC);
		so->optlen = sizeof(unsigned int);
		break;
	}

	case UDP_SEGMENT:
		optval16 = (unsigned short *) so->optval;
		switch (rand() % 5) {
		case 0: *optval16 = 0; break;
		case 1: *optval16 = 1; break;
		case 2: *optval16 = 1400; break;
		case 3: *optval16 = 65535; break;
		case 4: *optval16 = rand() % 65536; break;
		}
		so->optlen = sizeof(unsigned short);
		break;

	case UDPLITE_SEND_CSCOV:
	case UDPLITE_RECV_CSCOV:
		optval32 = (unsigned int *) so->optval;
		if (RAND_BOOL())
			*optval32 = RAND_ARRAY(cscov_values);
		else
			*optval32 = rand() % 65536;
		so->optlen = sizeof(unsigned int);
		break;

	default:
		break;
	}
}
