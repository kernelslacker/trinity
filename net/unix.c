#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/dn.h>
#include <stdlib.h>
#include "maps.h"
#include "net.h"

void gen_unixsock(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_un *unixsock;
	unsigned int len;

	unixsock = malloc(sizeof(struct sockaddr_un));
	if (unixsock == NULL)
		return;

	unixsock->sun_family = PF_UNIX;
	len = rand() % 20;
	memset(&page_rand[len], 0, 1);
	strncpy(unixsock->sun_path, page_rand, len);
	*addr = (unsigned long) unixsock;
	*addrlen = sizeof(struct sockaddr_un);
}

void unix_rand_socket(struct proto_type *pt)
{
	pt->protocol = PF_UNIX;

	switch (rand() % 3) {
	case 0: pt->type = SOCK_STREAM;
		break;
	case 1: pt->type = SOCK_DGRAM;
		break;
	case 2: pt->type = SOCK_SEQPACKET;
		break;
	default:break;
	}
}
