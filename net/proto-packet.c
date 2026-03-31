#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <stdlib.h>
#include <string.h>
#include "net.h"
#include "random.h"
#include "compat.h"

static void packet_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_ll *ll;

	ll = zmalloc(sizeof(struct sockaddr_ll));

	ll->sll_family = PF_PACKET;

	switch (rand() % 5) {
	case 0:
		ll->sll_protocol = htons(ETH_P_ALL);
		break;
	case 1:
		ll->sll_protocol = htons(ETH_P_IP);
		break;
	case 2:
		ll->sll_protocol = htons(ETH_P_ARP);
		break;
	case 3:
		ll->sll_protocol = htons(ETH_P_8021Q);
		break;
	case 4:
		ll->sll_protocol = htons(rand());
		break;
	}

	ll->sll_ifindex = rand() % 2;	/* 0=any, 1=lo */
	ll->sll_hatype = rand() % 2 ? 1 : rand();	/* 1=ARPHRD_ETHER */
	ll->sll_pkttype = rand() % 5;	/* HOST..OTHERHOST */
	ll->sll_halen = 6;
	generate_rand_bytes(ll->sll_addr, 8);

	*addr = (struct sockaddr *) ll;
	*addrlen = sizeof(struct sockaddr_ll);
}


static const unsigned int packet_opts[] = {
	PACKET_ADD_MEMBERSHIP, PACKET_DROP_MEMBERSHIP, PACKET_RECV_OUTPUT, 4,   /* Value 4 is still used by obsolete turbo-packet. */
	PACKET_RX_RING, PACKET_STATISTICS, PACKET_COPY_THRESH, PACKET_AUXDATA,
	PACKET_ORIGDEV, PACKET_VERSION, PACKET_HDRLEN, PACKET_RESERVE,
	PACKET_TX_RING, PACKET_LOSS, PACKET_VNET_HDR, PACKET_TX_TIMESTAMP,
	PACKET_TIMESTAMP, PACKET_FANOUT,
	PACKET_TX_HAS_OFF, PACKET_QDISC_BYPASS, PACKET_ROLLOVER_STATS,
	PACKET_FANOUT_DATA, PACKET_IGNORE_OUTGOING, PACKET_VNET_HDR_SZ,
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

	case PACKET_FANOUT: {
		/* type in low 16 bits, flags in high 16 bits */
		unsigned int *optval32 = (unsigned int *) so->optval;
		unsigned int type = rand() % 7;	/* HASH..CBPF */
		unsigned int flags = 0;

		if (RAND_BOOL())
			flags |= 0x1000;	/* PACKET_FANOUT_FLAG_ROLLOVER */
		if (RAND_BOOL())
			flags |= 0x2000;	/* PACKET_FANOUT_FLAG_UNIQUEID */
		if (RAND_BOOL())
			flags |= 0x4000;	/* PACKET_FANOUT_FLAG_DEFRAG */
		*optval32 = type | (flags << 16) | ((rand() % 256) << 8);
		so->optlen = sizeof(unsigned int);
		break;
	}

	case PACKET_ADD_MEMBERSHIP:
	case PACKET_DROP_MEMBERSHIP: {
		struct packet_mreq *mreq = (struct packet_mreq *) so->optval;

		memset(mreq, 0, sizeof(struct packet_mreq));
		mreq->mr_ifindex = rand() % 4;
		mreq->mr_type = rand() % 4 + 1;	/* MULTICAST..ALLMULTI */
		mreq->mr_alen = rand() % 9;
		generate_rand_bytes((unsigned char *) mreq->mr_address, 8);
		so->optlen = sizeof(struct packet_mreq);
		break;
	}

	default:
		break;
	}
}

static struct socket_triplet packet_triplets[] = {
	{ .family = PF_PACKET, .protocol = ETH_P_ALL, .type = SOCK_PACKET },
	{ .family = PF_PACKET, .protocol = ETH_P_ALL, .type = SOCK_RAW },
	{ .family = PF_PACKET, .protocol = ETH_P_ALL, .type = SOCK_DGRAM },
};

const struct netproto proto_packet = {
	.name = "packet",
	.socket_setup = packet_socket_setup,
	.setsockopt = packet_setsockopt,
	.gen_sockaddr = packet_gen_sockaddr,
	.valid_triplets = packet_triplets,
	.nr_triplets = ARRAY_SIZE(packet_triplets),
};
