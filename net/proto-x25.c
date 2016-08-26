#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/x25.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"

static void x25_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_x25 *x25;
	unsigned int len;

	x25 = zmalloc(sizeof(struct sockaddr_x25));

	x25->sx25_family = PF_X25;
	len = rnd() % 15;
	generate_rand_bytes((unsigned char *) x25->sx25_addr.x25_addr, len);
	*addr = (struct sockaddr *) x25;
	*addrlen = sizeof(struct sockaddr_x25);
}

static void x25_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	unsigned int *optval;

	so->level = SOL_X25;

	optval = (unsigned int *) so->optval;
	*optval = RAND_BOOL();

	so->optlen = sizeof(int);
}

static struct socket_triplet x25_triplet[] = {
	{ .family = PF_X25, .protocol = 0, .type = SOCK_SEQPACKET },
};

const struct netproto proto_x25 = {
	.name = "x25",
	.setsockopt = x25_setsockopt,
	.gen_sockaddr = x25_gen_sockaddr,
	.valid_triplets = x25_triplet,
	.nr_triplets = ARRAY_SIZE(x25_triplet),
};
