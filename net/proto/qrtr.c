#include <sys/socket.h>
#include <linux/qrtr.h>
#include "net.h"
#include "utils.h"
#include "rnd.h"

#include "kernel/qrtr.h"
#include "kernel/socket.h"

/* af_qrtr.c's qrtr_local_nid, every socket's own node */
#define QRTR_LOCAL_NODE		1
/* af_qrtr.c's, where the ports a bind to port 0 hands out start */
#define QRTR_MIN_EPH_SOCKET	0x4000

static void qrtr_gen_sockaddr(__unused__ struct socket_triplet *triplet, struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_qrtr *qrtr;

	qrtr = zmalloc_tracked(sizeof(struct sockaddr_qrtr));

	qrtr->sq_family = PF_QIPCRTR;
	/* qrtr_bind() refuses any node but the socket's own, and a send
	 * reaches a socket on this host only there or at QRTR_NODE_BCAST:
	 * any other node is a remote one, which takes a link to exist. */
	switch (rnd_modulo_u32(8)) {
	case 0:
		qrtr->sq_node = QRTR_NODE_BCAST;
		break;
	case 1:
		qrtr->sq_node = rnd_u32();
		break;
	default:
		qrtr->sq_node = QRTR_LOCAL_NODE;
		break;
	}
	/* Port 0 binds the lowest free port from QRTR_MIN_EPH_SOCKET up, as
	 * a send from an unbound socket does, so the first few name siblings'
	 * sockets; QRTR_PORT_CTRL is the name service's, the one port a
	 * broadcast send takes. */
	switch (rnd_modulo_u32(4)) {
	case 0:
		qrtr->sq_port = 0;
		break;
	case 1:
		qrtr->sq_port = QRTR_PORT_CTRL;
		break;
	case 2:
		qrtr->sq_port = QRTR_MIN_EPH_SOCKET + rnd_modulo_u32(64);
		break;
	default:
		qrtr->sq_port = rnd_u32();
		break;
	}
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
