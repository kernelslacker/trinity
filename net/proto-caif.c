#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "config.h"
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
	caif->u.at.type = rnd();
	for (i = 0; i < 16; i++)
		caif->u.util.service[i] = rnd();
	caif->u.dgm.connection_id = rnd();
	caif->u.dgm.nsapi = rnd();
	caif->u.rfm.connection_id = rnd();
	for (i = 0; i < 16; i++)
		caif->u.rfm.volume[i] = rnd();
	caif->u.dbg.type = rnd();
	caif->u.dbg.service = rnd();
	*addr = (struct sockaddr *) caif;
	*addrlen = sizeof(struct sockaddr_caif);
}

static void caif_rand_socket(struct socket_triplet *st)
{
	st->protocol = rnd() % _CAIFPROTO_MAX;
	if (RAND_BOOL())
		st->type = SOCK_SEQPACKET;
	else
		st->type = SOCK_STREAM;
}

static const unsigned int caif_opts[] = {
	CAIFSO_LINK_SELECT, CAIFSO_REQ_PARAM
};

static void caif_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_CAIF;

	so->optname = RAND_ARRAY(caif_opts);
}
struct netproto proto_caif = {
	.name = "caif",
	.socket = caif_rand_socket,
	.setsockopt = caif_setsockopt,
	.gen_sockaddr = caif_gen_sockaddr,
};
#endif
