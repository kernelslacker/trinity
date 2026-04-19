/* MPLS socket (AF_MPLS=28) handler */

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <stdint.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "compat.h"

#ifndef AF_MPLS
#define AF_MPLS 28
#endif
#ifndef ETH_P_MPLS_UC
#define ETH_P_MPLS_UC 0x8847
#endif
#ifndef ETH_P_MPLS_MC
#define ETH_P_MPLS_MC 0x8848
#endif

/* MPLS label stack entry: 20-bit label, 3-bit TC, 1-bit BoS, 8-bit TTL */
struct sockaddr_mpls {
	unsigned short smpls_family;
	uint32_t       smpls_addr; /* label stack entry in network byte order */
};

static void mpls_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_mpls *sa;

	sa = zmalloc(sizeof(struct sockaddr_mpls));
	sa->smpls_family = AF_MPLS;
	/* keep label in valid range 0..0xFFFFF, set BoS bit, TTL=64 */
	sa->smpls_addr = htonl(((rand() & 0xFFFFF) << 12) | 0x100 | 64);

	*addr = (struct sockaddr *)sa;
	*addrlen = sizeof(struct sockaddr_mpls);
}

static struct socket_triplet mpls_triplets[] = {
	{ .family = PF_MPLS, .protocol = ETH_P_MPLS_UC, .type = SOCK_RAW },
	{ .family = PF_MPLS, .protocol = ETH_P_MPLS_MC, .type = SOCK_RAW },
};

const struct netproto proto_mpls = {
	.name = "mpls",
	.gen_sockaddr = mpls_gen_sockaddr,
	.valid_triplets = mpls_triplets,
	.nr_triplets = ARRAY_SIZE(mpls_triplets),
};
