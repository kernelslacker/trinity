#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "compat.h"

#define SMCPROTO_SMC            0       /* SMC protocol, IPv4 */
#define SMCPROTO_SMC6           1       /* SMC protocol, IPv6 */

#define SOL_SMC         286
#define SMC_LIMIT_HS    1

static void smc_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	if (RAND_BOOL()) {
		struct sockaddr_in *sin;

		sin = zmalloc(sizeof(struct sockaddr_in));
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = random_ipv4_address();
		sin->sin_port = htons(rand() % 65536);
		*addr = (struct sockaddr *) sin;
		*addrlen = sizeof(struct sockaddr_in);
	} else {
		struct sockaddr_in6 *sin6;

		sin6 = zmalloc(sizeof(struct sockaddr_in6));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(rand() % 65536);
		*addr = (struct sockaddr *) sin6;
		*addrlen = sizeof(struct sockaddr_in6);
	}
}

static const unsigned int smc_opts[] = { SMC_LIMIT_HS };

static void smc_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	unsigned int *optval32;

	so->level = SOL_SMC;
	so->optname = RAND_ARRAY(smc_opts);

	optval32 = (unsigned int *) so->optval;
	*optval32 = RAND_BOOL();
	so->optlen = sizeof(unsigned int);
}

static struct socket_triplet smc_triplet[] = {
	{ .family = PF_SMC, .protocol = SMCPROTO_SMC, .type = SOCK_STREAM },
	{ .family = PF_SMC, .protocol = SMCPROTO_SMC6, .type = SOCK_STREAM },
};

const struct netproto proto_smc = {
	.name = "smc",
	.gen_sockaddr = smc_gen_sockaddr,
	.setsockopt = smc_setsockopt,
	.valid_triplets = smc_triplet,
	.nr_triplets = ARRAY_SIZE(smc_triplet),
};
