#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/phonet.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "compat.h"

#pragma GCC diagnostic ignored "-Waddress-of-packed-member"

static void phonet_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_pn *pn;

	pn = zmalloc(sizeof(struct sockaddr_pn));

	pn->spn_family = PF_PHONET;
	pn->spn_obj = rand();
	pn->spn_dev = rand();
	pn->spn_resource = rand();
	*addr = (struct sockaddr *) pn;
	*addrlen = sizeof(struct sockaddr_pn);
}

#define SOL_PNPIPE 275

static void phonet_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	static const unsigned int pnpipe_opts[] = {
		PNPIPE_ENCAP, PNPIPE_IFINDEX, PNPIPE_HANDLE, PNPIPE_INITSTATE,
	};

	so->level = SOL_PNPIPE;
	so->optname = RAND_ARRAY(pnpipe_opts);
	so->optlen = sizeof(unsigned int);
}

static struct socket_triplet phonet_triplets[] = {
	{ .family = PF_PHONET, .protocol = 0, .type = SOCK_DGRAM },
	{ .family = PF_PHONET, .protocol = 0, .type = SOCK_SEQPACKET },
	{ .family = PF_PHONET, .protocol = 1, .type = SOCK_DGRAM },
	{ .family = PF_PHONET, .protocol = 2, .type = SOCK_SEQPACKET },
};

const struct netproto proto_phonet = {
	.name = "phonet",
	.setsockopt = phonet_setsockopt,
	.gen_sockaddr = phonet_gen_sockaddr,
	.valid_triplets = phonet_triplets,
	.nr_triplets = ARRAY_SIZE(phonet_triplets),
};
