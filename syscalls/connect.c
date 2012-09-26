/*
 * SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr, int, addrlen
 *
 * If the connection or binding succeeds, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/x25.h>
#include <linux/ax25.h>
#include <linux/ipx.h>
#include <linux/atalk.h>
#include <linux/netlink.h>
#include <linux/nfc.h>
#include <stdlib.h>
#include "trinity.h"
#include "sanitise.h"
#include "shm.h"

static void sanitise_connect(int childno)
{
	struct sockaddr_un *unixsock;
	struct sockaddr_in *ipv4;
	struct sockaddr_x25 *x25;
	struct sockaddr_in6 *ipv6;
	struct sockaddr_ax25 *ax25;
	struct sockaddr_ipx *ipx;
	struct sockaddr_at *atalk;
	struct sockaddr_nl *nl;
	struct sockaddr_nfc *nfc;
	unsigned int len;
	unsigned int pf;
	unsigned int i;

	pf = rand() % PF_MAX;

	switch (pf) {

	case PF_UNSPEC:
		//TODO
		break;

	case PF_UNIX:
		unixsock = malloc(sizeof(struct sockaddr_un));
		if (unixsock == NULL)
			return;

		unixsock->sun_family = PF_UNIX;
		len = rand() % 20;
		memset(&page_rand[len], 0, 1);
		strncpy(unixsock->sun_path, page_rand, len);
		shm->a2[childno] = (unsigned long) unixsock;
		shm->a3[childno] = sizeof(struct sockaddr_un);
		break;

	case PF_INET:
		ipv4 = malloc(sizeof(struct sockaddr_in));
		if (ipv4 == NULL)
			return;

		ipv4->sin_family = PF_INET;
		ipv4->sin_addr.s_addr = htonl(0x7f000001);
		ipv4->sin_port = rand() % 65535;
		shm->a2[childno] = (unsigned long) ipv4;
		shm->a3[childno] = sizeof(struct sockaddr_in);
		break;

	case PF_AX25:
		ax25 = malloc(sizeof(struct sockaddr_ax25));
		if (ax25 == NULL)
			return;

		ax25->sax25_family = PF_AX25;
		len = rand() % 7;
		memset(&page_rand[len], 0, 1);
		strncpy(ax25->sax25_call.ax25_call, page_rand, len);
		ax25->sax25_ndigis = rand();
		shm->a2[childno] = (unsigned long) ax25;
		shm->a3[childno] = sizeof(struct sockaddr_ax25);
		break;

	case PF_IPX:
		ipx = malloc(sizeof(struct sockaddr_ipx));
		if (ipx == NULL)
			return;

		ipx->sipx_family = PF_AX25;
		ipx->sipx_port = rand();
		ipx->sipx_network = rand();
		for (i = 0; i < 6; i++)
			ipx->sipx_node[i] = rand();
		ipx->sipx_type = rand();
		ipx->sipx_zero = rand() % 2;
		shm->a2[childno] = (unsigned long) ipx;
		shm->a3[childno] = sizeof(struct sockaddr_ipx);
		break;

	case PF_APPLETALK:
		atalk = malloc(sizeof(struct sockaddr_at));
		if (atalk == NULL)
			return;

		atalk->sat_family = PF_APPLETALK;
		atalk->sat_port = rand();
		atalk->sat_addr.s_net = rand();
		atalk->sat_addr.s_node = rand();
		shm->a2[childno] = (unsigned long) atalk;
		shm->a3[childno] = sizeof(struct sockaddr_at);
		break;

	case PF_NETROM:
		//TODO
		break;

	case PF_BRIDGE:
		//TODO
		break;

	case PF_ATMPVC:
		//TODO
		break;

	case PF_X25:
		x25 = malloc(sizeof(struct sockaddr_x25));
		if (x25 == NULL)
			return;

		x25->sx25_family = PF_X25;
		len = rand() % 15;
		memset(&page_rand[len], 0, 1);
		strncpy(x25->sx25_addr.x25_addr, page_rand, len);
		shm->a2[childno] = (unsigned long) x25;
		shm->a3[childno] = sizeof(struct sockaddr_x25);
		break;

	case PF_INET6:
		ipv6 = malloc(sizeof(struct sockaddr_in6));
		if (ipv6 == NULL)
			return;

		ipv6->sin6_family = PF_INET6;
		ipv6->sin6_addr.s6_addr32[0] = 0;
		ipv6->sin6_addr.s6_addr32[1] = 0;
		ipv6->sin6_addr.s6_addr32[2] = 0;
		ipv6->sin6_addr.s6_addr32[3] = htonl(1);
		ipv6->sin6_port = rand() % 65535;
		shm->a2[childno] = (unsigned long) ipv6;
		shm->a3[childno] = sizeof(struct sockaddr_in6);
		break;

	case PF_ROSE:
		//TODO
		break;

	case PF_DECnet:
		//TODO
		break;

	case PF_NETBEUI:
		//TODO
		break;

	case PF_SECURITY:
		//TODO
		break;

	case PF_KEY:
		break;

	case PF_NETLINK:
		nl = malloc(sizeof(struct sockaddr_nl));
		if (nl == NULL)
			return;

		nl->nl_family = PF_NETLINK;
		nl->nl_pid = rand();
		nl->nl_groups = rand();
		shm->a2[childno] = (unsigned long) nl;
		shm->a3[childno] = sizeof(struct sockaddr_nl);
		break;

	case PF_PACKET:
		//TODO
		break;

	case PF_ASH:
		//TODO
		break;

	case PF_ECONET:
		//TODO
		break;

	case PF_ATMSVC:
		//TODO
		break;

	case PF_RDS:
		//TODO
		break;

	case PF_SNA:
		//TODO
		break;

	case PF_IRDA:
		//TODO
		break;

	case PF_PPPOX:
		//TODO
		break;

	case PF_WANPIPE:
		//TODO
		break;

	case PF_LLC:
		//TODO
		break;

	case PF_CAN:
		//TODO
		break;

	case PF_TIPC:
		//TODO
		break;

	case PF_BLUETOOTH:
		//TODO
		break;

	case PF_IUCV:
		//TODO
		break;

	case PF_RXRPC:
		//TODO
		break;

	case PF_ISDN:
		//TODO
		break;

	case PF_PHONET:
		//TODO
		break;

	case PF_IEEE802154:
		//TODO
		break;

	case PF_CAIF:
		//TODO
		break;

	case PF_ALG:
		//TODO
		break;

	case PF_NFC:
		// TODO: See also sockaddr_nfc_llcp
		nfc = malloc(sizeof(struct sockaddr_nfc));
		if (nfc == NULL)
			return;

		nfc->sa_family = PF_NFC;
		nfc->dev_idx = rand();
		nfc->target_idx = rand();
		nfc->nfc_protocol = rand() % 5;
		shm->a2[childno] = (unsigned long) nfc;
		shm->a3[childno] = sizeof(struct sockaddr_nfc);
		break;

	default:
		break;
	}
}

struct syscall syscall_connect = {
	.name = "connect",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "uservaddr",
	.arg2type = ARG_ADDRESS,
	.arg3name = "addrlen",
	.arg3type = ARG_LEN,
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_connect,
};
