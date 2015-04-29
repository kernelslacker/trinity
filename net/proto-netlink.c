#include <sys/types.h>
#include <sys/socket.h> /* old netlink.h is broken */
#include <sys/un.h>
/* For sa_family_t needed by <linux/netlink.h> */
#include <netinet/in.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include "compat.h"
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"	// ARRAY_SIZE
#include "compat.h"


/* Current highest netlink socket. Supports some older kernels. */
#ifdef NETLINK_CRYPTO
#define _NETLINK_MAX NETLINK_CRYPTO
#else
	#ifdef NETLINK_RDMA
	#define _NETLINK_MAX NETLINK_RDMA
	#else
		#define _NETLINK_MAX NETLINK_ECRYPTFS
	#endif /* NETLINK_RDMA */
#endif /* NETLINK_CRYPTO */

void netlink_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_nl *nl;

	nl = zmalloc(sizeof(struct sockaddr_nl));

	nl->nl_family = PF_NETLINK;
	nl->nl_pid = rand32();
	nl->nl_groups = rand32();
	*addr = (struct sockaddr *) nl;
	*addrlen = sizeof(struct sockaddr_nl);
}

void netlink_rand_socket(struct socket_triplet *st)
{
	if (RAND_BOOL())
		st->type = SOCK_RAW;
	else
		st->type = SOCK_DGRAM;

	st->protocol = rand() % (_NETLINK_MAX + 1);
}

#define NR_SOL_NETLINK_OPTS ARRAY_SIZE(netlink_opts)
static const unsigned int netlink_opts[] = {
	NETLINK_ADD_MEMBERSHIP, NETLINK_DROP_MEMBERSHIP, NETLINK_PKTINFO, NETLINK_BROADCAST_ERROR,
	NETLINK_NO_ENOBUFS, NETLINK_RX_RING, NETLINK_TX_RING };

void netlink_setsockopt(struct sockopt *so)
{
	unsigned char val;

	val = rand() % NR_SOL_NETLINK_OPTS;
	so->optname = netlink_opts[val];
}
