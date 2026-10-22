/* MPLS socket (AF_MPLS=28) handler */

#include <sys/socket.h>
#include <stdint.h>
#include "net.h"
#include "trinity.h"
#include "kernel/if_ether.h"
#include "rnd.h"

#include "kernel/socket.h"
/* MPLS label stack entry: 20-bit label, 3-bit TC, 1-bit BoS, 8-bit TTL */
struct sockaddr_mpls {
	unsigned short smpls_family;
	uint32_t       smpls_addr; /* label stack entry in network byte order */
};

static void mpls_gen_sockaddr(__unused__ struct socket_triplet *triplet, struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_mpls *sa;

	sa = zmalloc_tracked(sizeof(struct sockaddr_mpls));
	sa->smpls_family = AF_MPLS;
	/* keep label in valid range 0..0xFFFFF, set BoS bit, TTL=64 */
	sa->smpls_addr = htonl(((rnd_u32() & 0xFFFFF) << 12) | 0x100 | 64);

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
