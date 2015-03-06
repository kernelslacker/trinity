#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// ARRAY_SIZE
#include "compat.h"

void packet_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_pkt *pkt;
	unsigned int i;

	//TODO: See also sockaddr_ll
	pkt = zmalloc(sizeof(struct sockaddr_pkt));

	pkt->spkt_family = PF_PACKET;
	for (i = 0; i < 14; i++)
		pkt->spkt_device[i] = rand();
	*addr = (struct sockaddr *) pkt;
	*addrlen = sizeof(struct sockaddr_pkt);
}

void packet_rand_socket(struct socket_triplet *st)
{
	st->protocol = htons(ETH_P_ALL);

	if (ONE_IN(8))		// FIXME: 8 ? Why?
		st->protocol = get_random_ether_type();

	switch (rand() % 3) {
	case 0: st->type = SOCK_DGRAM;
		break;
	case 1: st->type = SOCK_RAW;
		break;
	case 2: st->type = SOCK_PACKET;
		break;
	default: break;
	}
}

#define NR_SOL_PACKET_OPTS ARRAY_SIZE(packet_opts)
static const unsigned int packet_opts[] = {
	PACKET_ADD_MEMBERSHIP, PACKET_DROP_MEMBERSHIP, PACKET_RECV_OUTPUT, 4,   /* Value 4 is still used by obsolete turbo-packet. */
	PACKET_RX_RING, PACKET_STATISTICS, PACKET_COPY_THRESH, PACKET_AUXDATA,
	PACKET_ORIGDEV, PACKET_VERSION, PACKET_HDRLEN, PACKET_RESERVE,
	PACKET_TX_RING, PACKET_LOSS, PACKET_VNET_HDR, PACKET_TX_TIMESTAMP,
	PACKET_TIMESTAMP, PACKET_FANOUT };

void packet_setsockopt(struct sockopt *so)
{
	unsigned char val;
	char *optval;

	so->level = SOL_PACKET;

	optval = (char *) so->optval;

	val = rand() % NR_SOL_PACKET_OPTS;
	so->optname = packet_opts[val];

	/* Adjust length according to operation set. */
	switch (so->optname) {
	case PACKET_VERSION:
		optval[0] = rand() % 3; /* tpacket versions 1/2/3 */
		break;

	case PACKET_TX_RING:
	case PACKET_RX_RING:
#ifdef TPACKET3_HDRLEN
		if (ONE_IN(3))
			so->optlen = sizeof(struct tpacket_req3);
		else
#endif
			so->optlen = sizeof(struct tpacket_req);
		break;
	default:
		break;
	}
}
