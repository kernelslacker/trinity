/*
 * Self-check for the AF_ALG sockaddr: alg_bind() (crypto/af_alg.c) refuses
 * any salg_feat or salg_mask bit but CRYPTO_ALG_KERN_DRIVER_ONLY with
 * -EINVAL before it looks the algorithm up, so most draws carry no other;
 * a few keep random words, for the refusal.
 */

#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#include "debug.h"		/* BUG */
#include "kernel/crypto.h"	/* CRYPTO_ALG_KERN_DRIVER_ONLY */
#include "net.h"		/* proto_alg */

#define ALG_ROUNDS	4000

void alg_sockaddr_self_check(void);
void alg_sockaddr_self_check(void)
{
	unsigned int i, refused = 0;

	for (i = 0; i < ALG_ROUNDS; i++) {
		struct sockaddr *addr = NULL;
		socklen_t len = 0;
		const struct sockaddr_alg *sa;

		proto_alg.gen_sockaddr(NULL, &addr, &len);
		sa = (const struct sockaddr_alg *) addr;
		if (sa == NULL || len != sizeof(*sa) || sa->salg_family != AF_ALG)
			BUG("alg: a sockaddr that is no sockaddr_alg");
		if ((sa->salg_feat | sa->salg_mask) & ~CRYPTO_ALG_KERN_DRIVER_ONLY)
			refused++;
		free(addr);
	}
	if (refused == 0 || refused > ALG_ROUNDS / 4)
		BUG("alg: salg_feat and salg_mask carry bits alg_bind() refuses too often, or never");
}
