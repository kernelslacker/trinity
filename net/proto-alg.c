#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "config.h"
#include "net.h"
#include "utils.h"
#include "compat.h"

#ifdef USE_IF_ALG
#include <linux/if_alg.h>

static const char *hashes[] = {
	"md5", "sha1",
};

void alg_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_alg *alg;
	unsigned int i, type, len;
	const char *types[] = { "aead", "hash", "rng", "skcipher", };

	alg = zmalloc(sizeof(struct sockaddr_alg));

	alg->salg_family = PF_ALG;

	type = rand() % 4;
	len = min(strlen(types[type]), sizeof(alg->salg_type));
	strncpy((char *)alg->salg_type, types[type], len);

	switch (type) {
	case 0:	
		break;
	case 1:	
		i = rand() % ARRAY_SIZE(hashes);
		len = min(strlen(hashes[i]), sizeof(alg->salg_type));
		strncpy((char *)alg->salg_name, hashes[i], len);
		break;
	case 2:	
		break;
	case 3:
		break;
	}

	alg->salg_feat = rand();
	alg->salg_mask = rand();

	*addr = (struct sockaddr *) alg;
	*addrlen = sizeof(struct sockaddr_alg);
}
#endif
