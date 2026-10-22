#include <sys/socket.h>
#include <linux/qrtr.h>
#include "net.h"
#include "utils.h"
#include "rnd.h"

#include "kernel/qrtr.h"
#include "kernel/socket.h"
static void qrtr_gen_sockaddr(__unused__ struct socket_triplet *triplet, struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_qrtr *qrtr;

	qrtr = zmalloc_tracked(sizeof(struct sockaddr_qrtr));

	qrtr->sq_family = PF_QIPCRTR;
	qrtr->sq_node = rnd_u32();
	qrtr->sq_port = rnd_u32();
	*addr = (struct sockaddr *) qrtr;
	*addrlen = sizeof(struct sockaddr_qrtr);
}

static struct socket_triplet qipcrtr_triplet[] = {
	{ .family = PF_QIPCRTR, .protocol = 0, .type = SOCK_DGRAM },
};

const struct netproto proto_qipcrtr = {
	.name = "qrtr",
	.gen_sockaddr = qrtr_gen_sockaddr,
	.valid_triplets = qipcrtr_triplet,
	.nr_triplets = ARRAY_SIZE(qipcrtr_triplet),
};
