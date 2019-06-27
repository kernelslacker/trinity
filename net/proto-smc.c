#include "net.h"
#include "compat.h"

#define SMCPROTO_SMC            0       /* SMC protocol, IPv4 */
#define SMCPROTO_SMC6           1       /* SMC protocol, IPv6 */

static struct socket_triplet smc_triplet[] = {
	{ .family = SMCPROTO_SMC, .protocol = SMCPROTO_SMC, .type = SOCK_STREAM },
	{ .family = SMCPROTO_SMC6, .protocol = SMCPROTO_SMC6, .type = SOCK_STREAM },
};

const struct netproto proto_smc = {
	.name = "smc",
	.valid_triplets = smc_triplet,
	.nr_triplets = ARRAY_SIZE(smc_triplet),
};
