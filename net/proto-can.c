#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <linux/can/isotp.h>
#include <linux/can/j1939.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "compat.h"

static void can_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_can *can;

	can = zmalloc(sizeof(struct sockaddr_can));

	can->can_family = AF_CAN;
	can->can_ifindex = rand();

	switch (rand() % 3) {
	case 0:
		/* ISOTP: fill .tp union member */
		can->can_addr.tp.rx_id = rand();
		can->can_addr.tp.tx_id = rand();
		break;
	case 1:
		/* J1939: fill .j1939 union member */
		can->can_addr.j1939.name = rand64();
		can->can_addr.j1939.pgn = rand() & 0x3ffff;
		can->can_addr.j1939.addr = RAND_BOOL() ? rand() % 0xfe : 0xff;
		break;
	default:
		/* CAN_RAW: no address needed, zero is fine */
		break;
	}

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

static void can_isotp_setsockopt(struct sockopt *so)
{
	static const unsigned int isotp_opts[] = {
		CAN_ISOTP_OPTS, CAN_ISOTP_RECV_FC,
		CAN_ISOTP_TX_STMIN, CAN_ISOTP_RX_STMIN,
		CAN_ISOTP_LL_OPTS,
	};
	struct can_isotp_options *opts;
	struct can_isotp_fc_options *fc;
	struct can_isotp_ll_options *ll;

	so->level = SOL_CAN_ISOTP;
	so->optname = RAND_ARRAY(isotp_opts);

	switch (so->optname) {
	case CAN_ISOTP_OPTS:
		opts = (struct can_isotp_options *) so->optval;
		opts->flags = rand() & 0x3fff;
		opts->frame_txtime = rand();
		opts->ext_address = rand();
		opts->txpad_content = rand();
		opts->rxpad_content = rand();
		opts->rx_ext_address = rand();
		so->optlen = sizeof(struct can_isotp_options);
		break;
	case CAN_ISOTP_RECV_FC:
		fc = (struct can_isotp_fc_options *) so->optval;
		fc->bs = rand();
		fc->stmin = rand();
		fc->wftmax = rand();
		so->optlen = sizeof(struct can_isotp_fc_options);
		break;
	case CAN_ISOTP_TX_STMIN:
	case CAN_ISOTP_RX_STMIN:
		*(unsigned int *) so->optval = rand();
		so->optlen = sizeof(unsigned int);
		break;
	case CAN_ISOTP_LL_OPTS:
		ll = (struct can_isotp_ll_options *) so->optval;
		ll->mtu = RAND_BOOL() ? 16 : 72;
		ll->tx_dl = 8;
		ll->tx_flags = rand() & 0x07;
		so->optlen = sizeof(struct can_isotp_ll_options);
		break;
	}
}

static void can_j1939_setsockopt(struct sockopt *so)
{
	static const unsigned int j1939_opts[] = {
		SO_J1939_FILTER, SO_J1939_PROMISC,
		SO_J1939_SEND_PRIO, SO_J1939_ERRQUEUE,
	};
	struct j1939_filter *filter;

	so->level = SOL_CAN_J1939;
	so->optname = RAND_ARRAY(j1939_opts);

	switch (so->optname) {
	case SO_J1939_FILTER:
		filter = (struct j1939_filter *) so->optval;
		filter->name = rand64();
		filter->name_mask = rand64();
		filter->pgn = rand() & 0x3ffff;
		filter->pgn_mask = rand() & 0x3ffff;
		filter->addr = rand();
		filter->addr_mask = rand();
		so->optlen = sizeof(struct j1939_filter);
		break;
	case SO_J1939_PROMISC:
	case SO_J1939_ERRQUEUE:
		*(unsigned int *) so->optval = RAND_BOOL();
		so->optlen = sizeof(unsigned int);
		break;
	case SO_J1939_SEND_PRIO:
		*(unsigned int *) so->optval = rand() % 8;
		so->optlen = sizeof(unsigned int);
		break;
	}
}

static void can_setsockopt(struct sockopt *so, struct socket_triplet *triplet)
{
	struct can_filter *filter;
	unsigned int *optval32;

	switch (triplet->protocol) {
	case CAN_ISOTP:
		can_isotp_setsockopt(so);
		return;
	case CAN_J1939:
		can_j1939_setsockopt(so);
		return;
	default:
		break;
	}

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
