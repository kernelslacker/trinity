#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "config.h"
#include "net.h"
#include "utils.h"
#include "compat.h"

#define SOL_ALG 279

#ifdef USE_IF_ALG
#include <linux/if_alg.h>

void alg_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_alg *alg;
	unsigned int i;

	alg = zmalloc(sizeof(struct sockaddr_alg));

	alg->salg_family = PF_ALG;
	for (i = 0; i < 14; i++)
		alg->salg_type[i] = rand();
	alg->salg_feat = rand();
	alg->salg_mask = rand();
	for (i = 0; i < 64; i++)
		alg->salg_name[i] = rand();
	*addr = (struct sockaddr *) alg;
	*addrlen = sizeof(struct sockaddr_alg);
}
#endif

void alg_setsockopt(struct sockopt *so)
{
	so->level = SOL_ALG;
}
