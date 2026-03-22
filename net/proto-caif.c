#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY
#include "compat.h"

#ifdef USE_CAIF
#include <linux/caif/caif_socket.h>

static void caif_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_caif *caif;
	unsigned int i;

	caif = zmalloc(sizeof(struct sockaddr_caif));

	caif->family = PF_CAIF;
	caif->u.at.type = rand();
	for (i = 0; i < 16; i++)
		caif->u.util.service[i] = rand();
	caif->u.dgm.connection_id = rand();
	caif->u.dgm.nsapi = rand();
	caif->u.rfm.connection_id = rand();
	for (i = 0; i < 16; i++)
		caif->u.rfm.volume[i] = rand();
	caif->u.dbg.type = rand();
	caif->u.dbg.service = rand();
	*addr = (struct sockaddr *) caif;
	*addrlen = sizeof(struct sockaddr_caif);
}

static const unsigned int caif_opts[] = {
	CAIFSO_LINK_SELECT, CAIFSO_REQ_PARAM
};

#define SOL_CAIF 278

static void caif_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_CAIF;

	so->optname = RAND_ARRAY(caif_opts);
}

static struct socket_triplet caif_triplet[] = {
	{ .family = PF_CAIF, .protocol = CAIFPROTO_AT, .type = SOCK_SEQPACKET },
	{ .family = PF_CAIF, .protocol = CAIFPROTO_DATAGRAM, .type = SOCK_SEQPACKET },
	{ .family = PF_CAIF, .protocol = CAIFPROTO_DATAGRAM_LOOP, .type = SOCK_SEQPACKET },
	{ .family = PF_CAIF, .protocol = CAIFPROTO_UTIL, .type = SOCK_SEQPACKET },
	{ .family = PF_CAIF, .protocol = CAIFPROTO_RFM, .type = SOCK_SEQPACKET },
	{ .family = PF_CAIF, .protocol = CAIFPROTO_DEBUG, .type = SOCK_SEQPACKET },

	{ .family = PF_CAIF, .protocol = CAIFPROTO_AT, .type = SOCK_STREAM },
	{ .family = PF_CAIF, .protocol = CAIFPROTO_DATAGRAM, .type = SOCK_STREAM },
	{ .family = PF_CAIF, .protocol = CAIFPROTO_DATAGRAM_LOOP, .type = SOCK_STREAM },
	{ .family = PF_CAIF, .protocol = CAIFPROTO_UTIL, .type = SOCK_STREAM },
	{ .family = PF_CAIF, .protocol = CAIFPROTO_RFM, .type = SOCK_STREAM },
	{ .family = PF_CAIF, .protocol = CAIFPROTO_DEBUG, .type = SOCK_STREAM },
};

const struct netproto proto_caif = {
	.name = "caif",
	.setsockopt = caif_setsockopt,
	.gen_sockaddr = caif_gen_sockaddr,
	.valid_triplets = caif_triplet,
	.nr_triplets = ARRAY_SIZE(caif_triplet),
};
#endif
