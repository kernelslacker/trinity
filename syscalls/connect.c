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
#include <stdlib.h>
#include "trinity.h"
#include "sanitise.h"
#include "shm.h"

static void sanitise_connect(int childno)
{
	struct sockaddr_in *ipv4;
	struct sockaddr_in6 *ipv6;
	struct sockaddr_un *unixsock;
	struct sockaddr_x25 *x25;
	unsigned int len;
	unsigned int pf;

	pf = rand() % PF_MAX;

	switch (pf) {

	case AF_INET:
		ipv4 = malloc(sizeof(struct sockaddr_in));
		if (ipv4 == NULL)
			return;

		ipv4->sin_family = AF_INET;
		ipv4->sin_addr.s_addr = htonl(0x7f000001);
		ipv4->sin_port = rand() % 65535;
		shm->a2[childno] = (unsigned long) ipv4;
		shm->a3[childno] = sizeof(struct sockaddr_in);
		break;

	case AF_INET6:
		ipv6 = malloc(sizeof(struct sockaddr_in6));
		if (ipv6 == NULL)
			return;

		ipv6->sin6_family = AF_INET6;
		ipv6->sin6_addr.s6_addr32[0] = 0;
		ipv6->sin6_addr.s6_addr32[1] = 0;
		ipv6->sin6_addr.s6_addr32[2] = 0;
		ipv6->sin6_addr.s6_addr32[3] = htonl(1);
		ipv6->sin6_port = rand() % 65535;
		shm->a2[childno] = (unsigned long) ipv6;
		shm->a3[childno] = sizeof(struct sockaddr_in6);
		break;

	case AF_UNIX:
		unixsock = malloc(sizeof(struct sockaddr_un));
		if (unixsock == NULL)
			return;

		unixsock->sun_family = AF_UNIX;
		len = rand() % 20;
		memset(&page_rand[len], 0, 1);
		strncpy(unixsock->sun_path, page_rand, len);
		shm->a2[childno] = (unsigned long) unixsock;
		shm->a3[childno] = sizeof(struct sockaddr_un);
		break;

	case AF_X25:
		x25 = malloc(sizeof(struct sockaddr_x25));
		if (x25 == NULL)
			return;

		x25->sx25_family = AF_X25;
		len = rand() % 15;
		memset(&page_rand[len], 0, 1);
		strncpy(x25->sx25_addr.x25_addr, page_rand, len);
		break;

	case AF_NETLINK:
		break;
	case AF_APPLETALK:
		break;
	case AF_NFC:
		break;

	//TODO: Support more families

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
