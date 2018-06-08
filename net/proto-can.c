#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/can.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"
#include "compat.h"

static void can_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_can *can;

	can = zmalloc(sizeof(struct sockaddr_can));

	can->can_family = AF_CAN;
	can->can_ifindex = rnd();
	can->can_addr.tp.rx_id = rnd();
	can->can_addr.tp.tx_id = rnd();
	*addr = (struct sockaddr *) can;
	*addrlen = sizeof(struct sockaddr_can);
}

static struct socket_triplet can_triplets[] = {
	{ .family = PF_CAN, .protocol = CAN_RAW, .type = SOCK_RAW },
	{ .family = PF_CAN, .protocol = CAN_BCM, .type = SOCK_DGRAM },
	// protos 3-7 seem unimplemented.
};

const struct netproto proto_can = {
	.name = "can",
	.gen_sockaddr = can_gen_sockaddr,
	.valid_triplets = can_triplets,
	.nr_triplets = ARRAY_SIZE(can_triplets),
};
