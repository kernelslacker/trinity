#include "net.h"
#include "compat.h"

static struct socket_triplet qipcrtr_triplet[] = {
	{ .family = PF_QIPCRTR, .protocol = 0, .type = SOCK_DGRAM },
};

const struct netproto proto_qipcrtr = {
	.name = "qrtr",
	.valid_triplets = qipcrtr_triplet,
	.nr_triplets = ARRAY_SIZE(qipcrtr_triplet),
};
