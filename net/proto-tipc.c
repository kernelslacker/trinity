#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/tipc.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY
#include "compat.h"

void tipc_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_tipc *tipc;

	tipc = zmalloc(sizeof(struct sockaddr_tipc));

	tipc->family = AF_TIPC;
	tipc->addrtype = rand();
	tipc->scope = rand();
	tipc->addr.id.ref = rand();
	tipc->addr.id.node = rand();
	tipc->addr.nameseq.type = rand();
	tipc->addr.nameseq.lower = rand();
	tipc->addr.nameseq.upper = rand();
	tipc->addr.name.name.type = rand();
	tipc->addr.name.name.instance = rand();
	tipc->addr.name.domain = rand();
	*addr = (struct sockaddr *) tipc;
	*addrlen = sizeof(struct sockaddr_tipc);
}

void tipc_rand_socket(struct socket_triplet *st)
{
	st->protocol = 0;

	switch (rand() % 3) {
	case 0: st->type = SOCK_STREAM;
		break;
	case 1: st->type = SOCK_SEQPACKET;
		break;
	case 2: st->type = SOCK_DGRAM;
		break;
	default: break;
	}
}

static const unsigned int tipc_opts[] = {
	TIPC_IMPORTANCE, TIPC_SRC_DROPPABLE, TIPC_DEST_DROPPABLE, TIPC_CONN_TIMEOUT,
	TIPC_NODE_RECVQ_DEPTH, TIPC_SOCK_RECVQ_DEPTH,
};

void tipc_setsockopt(struct sockopt *so)
{
	unsigned char val;

	val = RAND_ARRAY(tipc_opts);
	so->optname = tipc_opts[val];

	so->optlen = sizeof(__u32);
}
