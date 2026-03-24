#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "compat.h"

#ifndef SOL_CAN_RAW
#define SOL_CAN_RAW	(SOL_CAN_BASE + CAN_RAW)
#endif
#ifndef CAN_ISOTP
#define CAN_ISOTP	6
#endif
#ifndef CAN_J1939
#define CAN_J1939	7
#endif

static void can_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_can *can;

	can = zmalloc(sizeof(struct sockaddr_can));

	can->can_family = AF_CAN;
	can->can_ifindex = rand();
	can->can_addr.tp.rx_id = rand();
	can->can_addr.tp.tx_id = rand();
	*addr = (struct sockaddr *) can;
	*addrlen = sizeof(struct sockaddr_can);
}

static struct socket_triplet can_triplets[] = {
	{ .family = PF_CAN, .protocol = CAN_RAW,  .type = SOCK_RAW },
	{ .family = PF_CAN, .protocol = CAN_BCM,  .type = SOCK_DGRAM },
	{ .family = PF_CAN, .protocol = CAN_ISOTP, .type = SOCK_DGRAM },
	{ .family = PF_CAN, .protocol = CAN_J1939, .type = SOCK_DGRAM },
};

static const unsigned int can_raw_opts[] = {
	CAN_RAW_FILTER, CAN_RAW_ERR_FILTER,
	CAN_RAW_LOOPBACK, CAN_RAW_RECV_OWN_MSGS,
	CAN_RAW_FD_FRAMES, CAN_RAW_JOIN_FILTERS,
	CAN_RAW_XL_FRAMES,
};

static void can_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	struct can_filter *filter;
	unsigned int *optval32;

	so->level = SOL_CAN_RAW;
	so->optname = RAND_ARRAY(can_raw_opts);

	switch (so->optname) {
	case CAN_RAW_FILTER:
		/* 1-3 filters with random CAN IDs and masks */
		filter = (struct can_filter *) so->optval;
		filter[0].can_id = rand();
		filter[0].can_mask = rand();
		so->optlen = sizeof(struct can_filter);
		break;

	case CAN_RAW_ERR_FILTER:
		optval32 = (unsigned int *) so->optval;
		*optval32 = rand() & CAN_ERR_MASK;
		so->optlen = sizeof(unsigned int);
		break;

	case CAN_RAW_LOOPBACK:
	case CAN_RAW_RECV_OWN_MSGS:
	case CAN_RAW_FD_FRAMES:
	case CAN_RAW_JOIN_FILTERS:
	case CAN_RAW_XL_FRAMES:
		optval32 = (unsigned int *) so->optval;
		*optval32 = RAND_BOOL();
		so->optlen = sizeof(unsigned int);
		break;

	default:
		break;
	}
}

const struct netproto proto_can = {
	.name = "can",
	.gen_sockaddr = can_gen_sockaddr,
	.valid_triplets = can_triplets,
	.nr_triplets = ARRAY_SIZE(can_triplets),
	.setsockopt = can_setsockopt,
};
