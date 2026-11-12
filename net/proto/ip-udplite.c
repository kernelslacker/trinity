#include "net.h"
#include "random.h"
#include "rnd.h"

#include "kernel/udplite.h"
/* Interesting checksum coverage values for UDPLite. */
static const unsigned int cscov_values[] = {
	0,	/* covers entire datagram */
	8,	/* UDP header only */
	20,	/* header + some payload */
	65535,	/* max */
};

void udplite_setsockopt(struct sockopt *so, struct socket_triplet *triplet)
{
	unsigned int *optval32 = (unsigned int *) so->optval;

	/* udp_lib_setsockopt() takes UDP's options on a UDP-Lite socket
	 * too: the checksum coverage pair keeps its quarter of the draws. */
	if (!ONE_IN(4)) {
		udp_setsockopt(so, triplet);
		return;
	}

	so->optname = RAND_BOOL() ? UDPLITE_SEND_CSCOV : UDPLITE_RECV_CSCOV;
	if (RAND_BOOL())
		*optval32 = RAND_ARRAY(cscov_values);
	else
		*optval32 = rnd_modulo_u32(65536);
	so->optlen = sizeof(unsigned int);
}
