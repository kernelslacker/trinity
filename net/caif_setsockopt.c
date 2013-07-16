#include <stdlib.h>
#include "net.h"
#include "config.h"
#include "compat.h"
#include "trinity.h"	// ARRAY_SIZE

#ifdef USE_CAIF
#include <linux/caif/caif_socket.h>
#endif

#define SOL_CAIF 278

#ifdef USE_CAIF
#define NR_SOL_CAIF_OPTS ARRAY_SIZE(caif_opts)
static const unsigned int caif_opts[] = { CAIFSO_LINK_SELECT, CAIFSO_REQ_PARAM };
#endif

void caif_setsockopt(struct sockopt *so)
{
	unsigned char val;

	so->level = SOL_CAIF;

#ifdef USE_CAIF
	val = rand() % NR_SOL_CAIF_OPTS;
	so->optname = caif_opts[val];
#endif
}
