#include "net.h"
#include "compat.h"

static struct socket_triplet smc_triplet[] = {
	{ .family = PF_QIPCRTR, .protocol = IPPROTO_IP, .type = SOCK_STREAM },
	{ .family = PF_QIPCRTR, .protocol = IPPROTO_TCP, .type = SOCK_STREAM },
};

const struct netproto proto_smc = {
	.name = "smc",
	.valid_triplets = smc_triplet,
	.nr_triplets = ARRAY_SIZE(smc_triplet),
};
