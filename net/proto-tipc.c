#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/tipc.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "compat.h"

#ifndef TIPC_SERVICE_RANGE
#define TIPC_SERVICE_RANGE	1
#endif
#ifndef TIPC_MCAST_BROADCAST
#define TIPC_MCAST_BROADCAST	133
#endif
#ifndef TIPC_GROUP_JOIN
#define TIPC_GROUP_JOIN		135
#endif
#ifndef TIPC_GROUP_LEAVE
#define TIPC_GROUP_LEAVE	136
#endif
#ifndef TIPC_NODELAY
#define TIPC_NODELAY		138
#endif
#ifndef TIPC_GROUP_LOOPBACK
#define TIPC_GROUP_LOOPBACK	0x1
#endif
#ifndef TIPC_GROUP_MEMBER_EVTS
#define TIPC_GROUP_MEMBER_EVTS	0x2
#endif

static const unsigned int tipc_addrtype[] = {
	TIPC_ADDR_NAMESEQ, TIPC_ADDR_NAME, TIPC_ADDR_ID, TIPC_SERVICE_RANGE,
};

static void tipc_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_tipc *tipc;

	tipc = zmalloc(sizeof(struct sockaddr_tipc));

	tipc->family = AF_TIPC;
	tipc->addrtype = RAND_ARRAY(tipc_addrtype);
	tipc->scope = rand();

	switch (tipc->addrtype) {
	case TIPC_ADDR_ID:
		tipc->addr.id.ref = rand();
		tipc->addr.id.node = rand();
		break;
	case TIPC_ADDR_NAMESEQ:	/* also TIPC_SERVICE_RANGE */
		tipc->addr.nameseq.type = rand();
		tipc->addr.nameseq.lower = rand();
		tipc->addr.nameseq.upper = rand();
		break;
	case TIPC_ADDR_NAME:
	default:
		tipc->addr.name.name.type = rand();
		tipc->addr.name.name.instance = rand();
		tipc->addr.name.domain = rand();
		break;
	}
	*addr = (struct sockaddr *) tipc;
	*addrlen = sizeof(struct sockaddr_tipc);
}

static const unsigned int tipc_opts[] = {
	TIPC_IMPORTANCE, TIPC_SRC_DROPPABLE, TIPC_DEST_DROPPABLE, TIPC_CONN_TIMEOUT,
	TIPC_NODE_RECVQ_DEPTH, TIPC_SOCK_RECVQ_DEPTH,
	TIPC_MCAST_BROADCAST, TIPC_GROUP_JOIN, TIPC_GROUP_LEAVE, TIPC_NODELAY,
};

static void tipc_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	struct tipc_group_req *greq;
	__u32 *optval32;

	so->level = SOL_TIPC;
	so->optname = RAND_ARRAY(tipc_opts);

	switch (so->optname) {
	case TIPC_GROUP_JOIN:
		greq = (struct tipc_group_req *) so->optval;
		greq->type = rand();
		greq->instance = rand();
		greq->scope = rand() % 3 + 1;
		greq->flags = rand() & (TIPC_GROUP_LOOPBACK | TIPC_GROUP_MEMBER_EVTS);
		so->optlen = sizeof(struct tipc_group_req);
		break;

	case TIPC_MCAST_BROADCAST:
	case TIPC_GROUP_LEAVE:
		so->optlen = 0;
		break;

	case TIPC_NODELAY:
	case TIPC_SRC_DROPPABLE:
	case TIPC_DEST_DROPPABLE:
		optval32 = (__u32 *) so->optval;
		*optval32 = RAND_BOOL();
		so->optlen = sizeof(__u32);
		break;

	default:
		so->optlen = sizeof(__u32);
		break;
	}
}

static struct socket_triplet tipc_triplets[] = {
	{ .family = PF_TIPC, .protocol = 0, .type = SOCK_DGRAM },
	{ .family = PF_TIPC, .protocol = 0, .type = SOCK_SEQPACKET },
	{ .family = PF_TIPC, .protocol = 0, .type = SOCK_STREAM },
};

const struct netproto proto_tipc = {
	.name = "tipc",
	.setsockopt = tipc_setsockopt,
	.gen_sockaddr = tipc_gen_sockaddr,
	.valid_triplets = tipc_triplets,
	.nr_triplets = ARRAY_SIZE(tipc_triplets),
};
