#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "compat.h"

#ifndef AF_MCTP
#define AF_MCTP		45
#endif
#ifndef PF_MCTP
#define PF_MCTP		AF_MCTP
#endif

#define MCTP_NET_ANY	0x0
#define MCTP_ADDR_ANY	0xff
#define MCTP_TAG_MASK	0x07
#define MCTP_TAG_OWNER	0x08

struct mctp_addr {
	__u8 s_addr;
};

struct sockaddr_mctp {
	sa_family_t      smctp_family;
	__u16            __smctp_pad0;
	unsigned int     smctp_network;
	struct mctp_addr smctp_addr;
	__u8             smctp_type;
	__u8             smctp_tag;
	__u8             __smctp_pad1;
};

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

#ifndef SOL_MCTP
#define SOL_MCTP		285
#endif
#define MCTP_OPT_ADDR_EXT	1

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
