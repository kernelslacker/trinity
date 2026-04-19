/* InfiniBand socket (AF_IB=27) handler */

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "net.h"
#include "random.h"
#include "compat.h"

#ifndef AF_IB
#define AF_IB 27
#endif

/* struct sockaddr_ib from <rdma/ib_user_sa.h> */
struct sockaddr_ib {
	unsigned short	sib_family;
	uint16_t	sib_pkey;
	uint32_t	sib_flowinfo;
	uint8_t		sib_addr[16];
	uint64_t	sib_sid;
	uint64_t	sib_sid_mask;
	uint64_t	sib_scope_id;
};

static void ib_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_ib *sa;
	unsigned int i;

	sa = zmalloc(sizeof(struct sockaddr_ib));
	sa->sib_family = AF_IB;
	sa->sib_pkey = rand();
	sa->sib_flowinfo = rand();
	for (i = 0; i < 16; i++)
		sa->sib_addr[i] = rand();
	sa->sib_sid = (uint64_t)rand() << 32 | rand();
	sa->sib_sid_mask = ~0ULL;
	sa->sib_scope_id = 0;

	*addr = (struct sockaddr *)sa;
	*addrlen = sizeof(struct sockaddr_ib);
}

static struct socket_triplet ib_triplets[] = {
	{ .family = PF_IB, .protocol = 0, .type = SOCK_DGRAM },
	{ .family = PF_IB, .protocol = 0, .type = SOCK_STREAM },
};

const struct netproto proto_ib = {
	.name = "ib",
	.gen_sockaddr = ib_gen_sockaddr,
	.valid_triplets = ib_triplets,
	.nr_triplets = ARRAY_SIZE(ib_triplets),
};
