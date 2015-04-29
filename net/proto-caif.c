#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "config.h"
#include "net.h"
#include "random.h"
#include "utils.h"	// ARRAY_SIZE
#include "compat.h"

#ifdef USE_CAIF
#include <linux/caif/caif_socket.h>

void caif_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
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

void caif_rand_socket(struct socket_triplet *st)
{
	st->protocol = rand() % _CAIFPROTO_MAX;
	if (RAND_BOOL())
		st->type = SOCK_SEQPACKET;
	else
		st->type = SOCK_STREAM;
}

static const unsigned int caif_opts[] = {
	CAIFSO_LINK_SELECT, CAIFSO_REQ_PARAM
};

void caif_setsockopt(struct sockopt *so)
{
	unsigned char val;

	val = rand() % ARRAY_SIZE(caif_opts);
	so->optname = caif_opts[val];
}
#else
/* stub if we are built on something without CAIF headers */
void caif_setsockopt(struct sockopt *so)
{
}
#endif
