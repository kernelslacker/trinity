#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/dn.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"

void unix_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_un *unixsock;
	unsigned int len;

	unixsock = zmalloc(sizeof(struct sockaddr_un));

	unixsock->sun_family = PF_UNIX;
	len = rand() % 20;
	generate_rand_bytes((unsigned char *)unixsock->sun_path, len);
	*addr = (struct sockaddr *) unixsock;
	*addrlen = sizeof(struct sockaddr_un);
}

void unix_rand_socket(struct socket_triplet *st)
{
	st->protocol = PF_UNIX;

	switch (rand() % 3) {
	case 0: st->type = SOCK_STREAM;
		break;
	case 1: st->type = SOCK_DGRAM;
		break;
	case 2: st->type = SOCK_SEQPACKET;
		break;
	default:break;
	}
}
