#include <sys/socket.h>
#include <sys/uio.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/qrtr.h>
#include "net.h"
#include "random.h"
#include "socket-family-grammar.h"
#include "utils.h"
#include "compat.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0x4000
#endif

static void qrtr_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_qrtr *qrtr;

	qrtr = zmalloc(sizeof(struct sockaddr_qrtr));

	qrtr->sq_family = PF_QIPCRTR;
	qrtr->sq_node = rand();
	qrtr->sq_port = rand();
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

/*
 * grammar_qrtr — coherent walk for AF_QIPCRTR (Qualcomm IPC Router).
 *
 * QRTR is a datagram family that layers a name-service registration
 * table over an in-kernel routing layer.  The interesting parser
 * surface lives behind the QRTR_PORT_CTRL pseudo-port: clients send
 * struct qrtr_ctrl_pkt payloads there to register a service
 * (QRTR_TYPE_NEW_SERVER), advertise a name lookup
 * (QRTR_TYPE_NEW_LOOKUP), and tear those down again
 * (QRTR_TYPE_DEL_SERVER / QRTR_TYPE_DEL_LOOKUP).  Random per-syscall
 * fuzzing essentially never assembles the full sequence required to
 * land on the registration-table lifecycle paths — historic protocol
 * bugs cluster around the new-server / del-server window and the
 * lookup notifier dispatch.
 *
 *   socket(AF_QIPCRTR, SOCK_DGRAM, 0)
 *     -> bind() to sockaddr_qrtr with sq_node=0 sq_port=0; the kernel
 *        auto-allocates a port off the local node
 *     -> sendmsg() to QRTR_PORT_CTRL carrying a qrtr_ctrl_pkt with
 *        cmd=QRTR_TYPE_NEW_SERVER and synthesised service/instance —
 *        drives the routing-layer dispatch into qrtr_local_enqueue
 *        and (with a nameserver loaded) the registration-table insert
 *     -> sendmsg() to QRTR_PORT_CTRL with cmd=QRTR_TYPE_NEW_LOOKUP
 *        targeting the same service/instance — exercises the lookup
 *        notifier registration path
 *     -> sendmsg() of a small data payload to a synthesised peer
 *        sockaddr_qrtr (loopback node, random port).  Delivery very
 *        likely fails (no peer listening) but the qrtr_sendmsg parser
 *        and routing decision have already run, which is the surface
 *        this walk is for
 *     -> non-blocking recvmsg() to drain any control-channel
 *        notifications the routing layer plumbed back
 *     -> sendmsg() to QRTR_PORT_CTRL with cmd=QRTR_TYPE_DEL_LOOKUP
 *        and cmd=QRTR_TYPE_DEL_SERVER — the registration-table
 *        teardown ordering window matched against the parent close()
 *     -> close()
 *
 * Module presence.  AF_QIPCRTR is a loadable module on most distros
 * and the protocol family registers as soon as the qrtr module is
 * loaded.  socket(AF_QIPCRTR, SOCK_DGRAM, 0) returns -EAFNOSUPPORT
 * when the module is absent; can_run latches that as a permanent
 * skip and the grammar is filtered out at sfg_pick_random_active()
 * without tainting the per-family unsupported latch shared with
 * other grammars.  The registration-table inserts go through the
 * routing layer regardless of whether a nameserver is consuming
 * QRTR_PORT_CTRL packets — the parser dispatch we want is on the
 * sender side.
 *
 * needs_listen_accept = false.  QRTR is datagram-only; there is no
 * listen() / accept() phase.
 */

/* Per-process probe cache.  -1 untested, 0 unsupported, 1 supported. */
static int qrtr_supported = -1;

/* Per-walk: the service / instance pair we registered.  Set in the
 * data leg's NEW_SERVER step, read by the matching DEL_SERVER /
 * NEW_LOOKUP / DEL_LOOKUP steps so the teardown targets the same
 * entry the registration created.  Each child runs grammar walks
 * serially so a file-static is collision-free here. */
static uint32_t qrtr_walk_service;
static uint32_t qrtr_walk_instance;

static bool qrtr_can_run(void)
{
	int fd;

	if (qrtr_supported >= 0)
		return qrtr_supported == 1;

	fd = socket(PF_QIPCRTR, SOCK_DGRAM, 0);
	if (fd < 0) {
		qrtr_supported = 0;
		return false;
	}
	close(fd);
	qrtr_supported = 1;
	return true;
}

static void qrtr_pick_triplet(struct socket_triplet *out)
{
	out->family = PF_QIPCRTR;
	out->type = SOCK_DGRAM;
	out->protocol = 0;
}

static int qrtr_bind_or_connect(int fd, __unused__ struct socket_triplet *triplet)
{
	struct sockaddr_qrtr sq;

	memset(&sq, 0, sizeof(sq));
	sq.sq_family = AF_QIPCRTR;
	sq.sq_node = 0;
	sq.sq_port = 0;	/* kernel auto-allocates */
	if (bind(fd, (struct sockaddr *) &sq, sizeof(sq)) < 0)
		return -1;
	return 0;
}

static bool qrtr_needs_listen_accept(__unused__ struct socket_triplet *triplet)
{
	return false;
}

static void qrtr_send_ctrl(int fd, uint32_t cmd, uint32_t service,
			   uint32_t instance)
{
	struct sockaddr_qrtr peer;
	struct qrtr_ctrl_pkt pkt;
	struct iovec iov;
	struct msghdr msg;

	memset(&peer, 0, sizeof(peer));
	peer.sq_family = AF_QIPCRTR;
	peer.sq_node = 0;
	peer.sq_port = QRTR_PORT_CTRL;

	/* The .server view of the union covers NEW_SERVER / DEL_SERVER and
	 * the {service,instance,node-mask} prefix the kernel reads off
	 * NEW_LOOKUP / DEL_LOOKUP packets — same wire layout, different
	 * dispatcher arm. */
	memset(&pkt, 0, sizeof(pkt));
	pkt.cmd = htole32(cmd);
	pkt.server.service = htole32(service);
	pkt.server.instance = htole32(instance);
	pkt.server.node = htole32(0);
	pkt.server.port = htole32(0);

	iov.iov_base = &pkt;
	iov.iov_len = sizeof(pkt);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &peer;
	msg.msg_namelen = sizeof(peer);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	(void) sendmsg(fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
}

static void qrtr_data_leg(int parent_fd, __unused__ int child_fd,
			  __unused__ struct socket_triplet *triplet)
{
	struct sockaddr_qrtr peer;
	struct msghdr msg, rmsg;
	struct iovec iov, riov;
	unsigned char payload[64];
	unsigned char rcvbuf[256];

	qrtr_walk_service = 0x5000 + (rand() % 0x100);
	qrtr_walk_instance = rand();

	qrtr_send_ctrl(parent_fd, QRTR_TYPE_NEW_SERVER,
		       qrtr_walk_service, qrtr_walk_instance);
	qrtr_send_ctrl(parent_fd, QRTR_TYPE_NEW_LOOKUP,
		       qrtr_walk_service, qrtr_walk_instance);

	memset(&peer, 0, sizeof(peer));
	peer.sq_family = AF_QIPCRTR;
	peer.sq_node = 0;
	peer.sq_port = 1024 + (rand() % 60000);

	generate_rand_bytes(payload, sizeof(payload));
	iov.iov_base = payload;
	iov.iov_len = sizeof(payload);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &peer;
	msg.msg_namelen = sizeof(peer);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	(void) sendmsg(parent_fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);

	memset(&rmsg, 0, sizeof(rmsg));
	riov.iov_base = rcvbuf;
	riov.iov_len = sizeof(rcvbuf);
	rmsg.msg_iov = &riov;
	rmsg.msg_iovlen = 1;
	(void) recvmsg(parent_fd, &rmsg, MSG_DONTWAIT);

	qrtr_send_ctrl(parent_fd, QRTR_TYPE_DEL_LOOKUP,
		       qrtr_walk_service, qrtr_walk_instance);
	qrtr_send_ctrl(parent_fd, QRTR_TYPE_DEL_SERVER,
		       qrtr_walk_service, qrtr_walk_instance);
}

const struct socket_family_grammar grammar_qrtr = {
	.family			= PF_QIPCRTR,
	.name			= "qrtr",
	.can_run		= qrtr_can_run,
	.pick_triplet		= qrtr_pick_triplet,
	.bind_or_connect	= qrtr_bind_or_connect,
	.needs_listen_accept	= qrtr_needs_listen_accept,
	.data_leg		= qrtr_data_leg,
};
