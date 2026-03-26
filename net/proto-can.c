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
#ifndef CANFD_MAX_DLEN
#define CANFD_MAX_DLEN	64
#endif
#ifndef CANXL_MIN_DLEN
#define CANXL_MIN_DLEN	1
#endif
#ifndef CANXL_MAX_DLEN
#define CANXL_MAX_DLEN	2048
#endif
#ifndef CANXL_XLF
#define CANXL_XLF	0x80
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

static void can_gen_msg(__unused__ struct socket_triplet *triplet, void **buf, size_t *len)
{
	struct can_frame *cf;
	struct canfd_frame *cfd;
	struct canxl_frame *cxl;

	switch (rand() % 3) {
	case 0:
		cf = zmalloc(sizeof(struct can_frame));
		cf->can_id = rand() & (CAN_EFF_FLAG | CAN_RTR_FLAG | CAN_ERR_FLAG | CAN_EFF_MASK);
		cf->len = rand() % (CAN_MAX_DLEN + 1);
		generate_rand_bytes(cf->data, CAN_MAX_DLEN);
		*buf = cf;
		*len = sizeof(struct can_frame);
		break;

	case 1:
		cfd = zmalloc(sizeof(struct canfd_frame));
		cfd->can_id = rand() & (CAN_EFF_FLAG | CAN_RTR_FLAG | CAN_ERR_FLAG | CAN_EFF_MASK);
		cfd->len = rand() % (CANFD_MAX_DLEN + 1);
		cfd->flags = rand() & 0x07;
		generate_rand_bytes(cfd->data, CANFD_MAX_DLEN);
		*buf = cfd;
		*len = sizeof(struct canfd_frame);
		break;

	default:
		cxl = zmalloc(sizeof(struct canxl_frame));
		cxl->prio = rand() & CAN_SFF_MASK;
		cxl->flags = CANXL_XLF | (rand() & 0x03);
		cxl->sdt = rand();
		cxl->len = CANXL_MIN_DLEN + rand() % CANXL_MAX_DLEN;
		cxl->af = rand();
		generate_rand_bytes(cxl->data, CANXL_MAX_DLEN);
		*buf = cxl;
		*len = sizeof(struct canxl_frame);
		break;
	}
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
	.gen_msg = can_gen_msg,
	.valid_triplets = can_triplets,
	.nr_triplets = ARRAY_SIZE(can_triplets),
	.setsockopt = can_setsockopt,
};
