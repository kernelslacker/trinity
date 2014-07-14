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

void can_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
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

void can_rand_socket(struct socket_triplet *st)
{
	st->protocol = rand() % 7;  // CAN_NPROTO
	st->type = rand() % TYPE_MAX;
}
