#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY
#include "compat.h"

static void packet_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_pkt *pkt;
	unsigned int i;

	//TODO: See also sockaddr_ll
	pkt = zmalloc(sizeof(struct sockaddr_pkt));

	pkt->spkt_family = PF_PACKET;
	for (i = 0; i < 14; i++)
		pkt->spkt_device[i] = rnd();
	*addr = (struct sockaddr *) pkt;
	*addrlen = sizeof(struct sockaddr_pkt);
}


static const unsigned int packet_opts[] = {
	PACKET_ADD_MEMBERSHIP, PACKET_DROP_MEMBERSHIP, PACKET_RECV_OUTPUT, 4,   /* Value 4 is still used by obsolete turbo-packet. */
	PACKET_RX_RING, PACKET_STATISTICS, PACKET_COPY_THRESH, PACKET_AUXDATA,
	PACKET_ORIGDEV, PACKET_VERSION, PACKET_HDRLEN, PACKET_RESERVE,
	PACKET_TX_RING, PACKET_LOSS, PACKET_VNET_HDR, PACKET_TX_TIMESTAMP,
	PACKET_TIMESTAMP, PACKET_FANOUT,
};


static void setup_tpacket_req3(struct tpacket_req3 *req)
{
	unsigned int blocksiz = 1 << 21, framesiz = 1 << 11;
	unsigned int blocknum = 1;

	memset(req, 0, sizeof(struct tpacket_req3));
	req->tp_block_size = blocksiz;
	req->tp_frame_size = framesiz;
	req->tp_block_nr = blocknum;
	req->tp_frame_nr = (blocksiz * blocknum) / framesiz;
	req->tp_retire_blk_tov = 60;
	req->tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
}

static void packet_socket_setup(int fd)
{
	int v3 = TPACKET_V3;

	// for now, we only speak v3
	// trying to mix it up goes horribly wrong, with oom kills etc.
	(void) setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v3, sizeof(v3));
}


static void set_tpacket_version3(struct sockopt *so)
{
	char *optval = (char *) so->optval;

	optval[0] = TPACKET_V3;
	so->optlen = sizeof(int);
}

static void packet_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	struct tpacket_req3 *req = (struct tpacket_req3 *) so->optval;

	so->level = SOL_PACKET;

	so->optname = RAND_ARRAY(packet_opts);

	/* Adjust length according to operation set. */
	switch (so->optname) {
	case PACKET_VERSION:
		set_tpacket_version3(so);
		break;

	case PACKET_RX_RING:
		setup_tpacket_req3(req);
		so->optlen = sizeof(struct tpacket_req3);
		break;

	default:
		break;
	}
}

static struct socket_triplet packet_triplets[] = {
	{ .family = PF_PACKET, .protocol = 768, .type = SOCK_PACKET },
	{ .family = PF_PACKET, .protocol = 768, .type = SOCK_RAW },
/*
   revisit all this:

	st->protocol = htons(ETH_P_ALL);

	if (ONE_IN(8))		// FIXME: 8 ? Why?
		st->protocol = get_random_ether_type();

*/

};

const struct netproto proto_packet = {
	.name = "packet",
	.socket_setup = packet_socket_setup,
	.setsockopt = packet_setsockopt,
	.gen_sockaddr = packet_gen_sockaddr,
	.valid_triplets = packet_triplets,
	.nr_triplets = ARRAY_SIZE(packet_triplets),
};
