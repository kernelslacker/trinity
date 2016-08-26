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

static void tipc_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
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

static const unsigned int tipc_opts[] = {
	TIPC_IMPORTANCE, TIPC_SRC_DROPPABLE, TIPC_DEST_DROPPABLE, TIPC_CONN_TIMEOUT,
	TIPC_NODE_RECVQ_DEPTH, TIPC_SOCK_RECVQ_DEPTH,
};

static void tipc_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_TIPC;

	so->optname = RAND_ARRAY(tipc_opts);

	so->optlen = sizeof(__u32);
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
