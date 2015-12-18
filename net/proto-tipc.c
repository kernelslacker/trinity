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
	tipc->addrtype = rnd();
	tipc->scope = rnd();
	tipc->addr.id.ref = rnd();
	tipc->addr.id.node = rnd();
	tipc->addr.nameseq.type = rnd();
	tipc->addr.nameseq.lower = rnd();
	tipc->addr.nameseq.upper = rnd();
	tipc->addr.name.name.type = rnd();
	tipc->addr.name.name.instance = rnd();
	tipc->addr.name.domain = rnd();
	*addr = (struct sockaddr *) tipc;
	*addrlen = sizeof(struct sockaddr_tipc);
}

void tipc_rand_socket(struct socket_triplet *st)
{
	st->protocol = 0;

	switch (rnd() % 3) {
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
	so->optname = RAND_ARRAY(tipc_opts);

	so->optlen = sizeof(__u32);
}
