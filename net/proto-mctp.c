#ifdef USE_MCTP
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/mctp.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "compat.h"

#ifndef MCTP_NET_ANY
#define MCTP_NET_ANY		0x0
#endif
#ifndef MCTP_ADDR_ANY
#define MCTP_ADDR_ANY		0xff
#endif
#ifndef MCTP_TAG_MASK
#define MCTP_TAG_MASK		0x07
#endif
#ifndef MCTP_TAG_OWNER
#define MCTP_TAG_OWNER		0x08
#endif
#ifndef MCTP_OPT_ADDR_EXT
#define MCTP_OPT_ADDR_EXT	1
#endif

static void mctp_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_mctp *mctp;

	mctp = zmalloc(sizeof(struct sockaddr_mctp));
	mctp->smctp_family = AF_MCTP;
	mctp->smctp_network = RAND_BOOL() ? MCTP_NET_ANY : rand();
	mctp->smctp_addr.s_addr = RAND_BOOL() ? MCTP_ADDR_ANY : rand();
	mctp->smctp_type = rand();
	mctp->smctp_tag = rand() & (MCTP_TAG_MASK | MCTP_TAG_OWNER);

	*addr = (struct sockaddr *) mctp;
	*addrlen = sizeof(struct sockaddr_mctp);
}

static const unsigned int mctp_opts[] = { MCTP_OPT_ADDR_EXT };

static void mctp_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_MCTP;
	so->optname = RAND_ARRAY(mctp_opts);
	*(unsigned int *) so->optval = RAND_BOOL();
	so->optlen = sizeof(unsigned int);
}

static struct socket_triplet mctp_triplets[] = {
	{ .family = PF_MCTP, .protocol = 0, .type = SOCK_DGRAM },
};

const struct netproto proto_mctp = {
	.name = "mctp",
	.gen_sockaddr = mctp_gen_sockaddr,
	.setsockopt = mctp_setsockopt,
	.valid_triplets = mctp_triplets,
	.nr_triplets = ARRAY_SIZE(mctp_triplets),
};
#endif /* USE_MCTP */
