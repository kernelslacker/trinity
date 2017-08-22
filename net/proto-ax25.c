#ifdef USE_NETAX25
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netax25/ax25.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY
#include "compat.h"

static void ax25_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_ax25 *ax25;

	ax25 = zmalloc(sizeof(struct sockaddr_ax25));

	ax25->sax25_family = PF_AX25;
	generate_rand_bytes((unsigned char *) ax25->sax25_call.ax25_call, 7);
	ax25->sax25_ndigis = rnd();
	*addr = (struct sockaddr *) ax25;
	*addrlen = sizeof(struct sockaddr_ax25);
}

static const unsigned int ax25_opts[] = {
	AX25_WINDOW, AX25_T1, AX25_N2, AX25_T3,
	AX25_T2, AX25_BACKOFF, AX25_EXTSEQ, AX25_PIDINCL,
	AX25_IDLE, AX25_PACLEN, AX25_IAMDIGI,
	SO_BINDTODEVICE
};

static void ax25_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_AX25;
	so->optname = RAND_ARRAY(ax25_opts);
}

#define AX25_P_ROSE 1
#define AX25_P_NETROM 0xcf

static struct socket_triplet ax25_triplets[] = {
	{ .family = PF_AX25, .protocol = 0, .type = SOCK_DGRAM },
	{ .family = PF_AX25, .protocol = 0, .type = SOCK_RAW },
	{ .family = PF_AX25, .protocol = 0, .type = SOCK_SEQPACKET },
	{ .family = PF_AX25, .protocol = AX25_P_ROSE, .type = SOCK_SEQPACKET },
	{ .family = PF_AX25, .protocol = AX25_P_NETROM, .type = SOCK_SEQPACKET },
};

const struct netproto proto_ax25 = {
	.name = "ax25",
	.setsockopt = ax25_setsockopt,
	.gen_sockaddr = ax25_gen_sockaddr,
	.valid_triplets = ax25_triplets,
	.nr_triplets = ARRAY_SIZE(ax25_triplets),
};
#endif
