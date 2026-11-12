/*
 * Self-check for the AF_QIPCRTR sockaddr: qrtr_bind() (net/qrtr/af_qrtr.c)
 * refuses any node but the socket's own, which is 1, and a send reaches a
 * socket on this host only there or at the broadcast node, so most draws
 * name node 1; some name the name service's control port.
 */

#include <stdlib.h>
#include <sys/socket.h>

#include "debug.h"		/* BUG */
#include "kernel/qrtr.h"	/* struct sockaddr_qrtr, QRTR_PORT_CTRL */
#include "net.h"		/* proto_qipcrtr */

#define QRTR_ROUNDS	4000

void qrtr_sockaddr_self_check(void);
void qrtr_sockaddr_self_check(void)
{
	unsigned int i, local = 0, remote = 0, ctrl = 0;

	for (i = 0; i < QRTR_ROUNDS; i++) {
		struct sockaddr *addr = NULL;
		socklen_t len = 0;
		const struct sockaddr_qrtr *sq;

		proto_qipcrtr.gen_sockaddr(NULL, &addr, &len);
		sq = (const struct sockaddr_qrtr *) addr;
		if (sq == NULL || len != sizeof(*sq) || sq->sq_family != AF_QIPCRTR)
			BUG("qrtr: a sockaddr that is no sockaddr_qrtr");
		if (sq->sq_node == 1)
			local++;
		else
			remote++;
		if (sq->sq_port == QRTR_PORT_CTRL)
			ctrl++;
		free(addr);
	}
	if (local < QRTR_ROUNDS / 2 || remote == 0)
		BUG("qrtr: the node qrtr_bind() takes is rare, or the only one");
	if (ctrl == 0)
		BUG("qrtr: no sockaddr names the name service's port");
}
