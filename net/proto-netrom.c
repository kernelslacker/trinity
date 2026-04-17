
#ifdef USE_NETROM
#include <netrom/netrom.h>
#include <netax25/ax25.h>
#include "net.h"
#include "random.h"
#include "compat.h"

static void netrom_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_ax25 *ax25;

	ax25 = zmalloc(sizeof(struct sockaddr_ax25));

	ax25->sax25_family = PF_NETROM;
	generate_rand_bytes((unsigned char *) ax25->sax25_call.ax25_call, 7);
	ax25->sax25_ndigis = rand();
	*addr = (struct sockaddr *) ax25;
	*addrlen = sizeof(struct sockaddr_ax25);
}

static void netrom_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	const unsigned int netrom_opts[] = {
		NETROM_T1, NETROM_T2, NETROM_N2, NETROM_T4, NETROM_IDLE
	};

	so->level = SOL_NETROM;
	so->optname = RAND_ARRAY(netrom_opts);
	so->optlen = sizeof(unsigned int);
}

static struct socket_triplet netrom_triplet[] = {
	{ .family = PF_NETROM, .protocol = 0, .type = SOCK_SEQPACKET },
	{ .family = PF_NETROM, .protocol = 0, .type = SOCK_DGRAM },
};

const struct netproto proto_netrom = {
	.name = "netrom",
	.gen_sockaddr = netrom_gen_sockaddr,
	.setsockopt = netrom_setsockopt,
	.valid_triplets = netrom_triplet,
	.nr_triplets = ARRAY_SIZE(netrom_triplet),
};
#endif
