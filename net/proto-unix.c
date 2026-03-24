#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include "net.h"
#include "random.h"
#include "compat.h"

#ifndef SO_PEEK_OFF
#define SO_PEEK_OFF	42
#endif

static void unix_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_un *unixsock;
	unsigned int len;

	unixsock = zmalloc(sizeof(struct sockaddr_un));

	unixsock->sun_family = PF_UNIX;

	switch (rand() % 4) {
	case 0:
		/* Pathname socket — random path */
		len = RAND_RANGE(1, 20);
		generate_rand_bytes((unsigned char *)unixsock->sun_path, len);
		*addrlen = sizeof(sa_family_t) + len;
		break;

	case 1:
		/* Abstract namespace — NUL byte prefix */
		unixsock->sun_path[0] = '\0';
		len = RAND_RANGE(1, 20);
		generate_rand_bytes((unsigned char *)unixsock->sun_path + 1, len);
		*addrlen = sizeof(sa_family_t) + 1 + len;
		break;

	case 2:
		/* Unnamed socket — zero-length path */
		*addrlen = sizeof(sa_family_t);
		break;

	case 3:
		/* Varying addrlen to exercise edge cases */
		len = rand() % 20;
		generate_rand_bytes((unsigned char *)unixsock->sun_path, len);
		*addrlen = sizeof(sa_family_t) + rand() % (sizeof(unixsock->sun_path) + 1);
		break;
	}

	*addr = (struct sockaddr *) unixsock;
}

static const unsigned int unix_opts[] = {
	SO_PASSCRED, SO_PEEK_OFF,
};

static void unix_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	int *optval32;

	so->level = SOL_SOCKET;
	so->optname = RAND_ARRAY(unix_opts);

	switch (so->optname) {
	case SO_PASSCRED:
		optval32 = (int *) so->optval;
		*optval32 = RAND_BOOL();
		so->optlen = sizeof(int);
		break;

	case SO_PEEK_OFF:
		optval32 = (int *) so->optval;
		switch (rand() % 4) {
		case 0: *optval32 = -1; break;		/* disable */
		case 1: *optval32 = 0; break;		/* start of queue */
		case 2: *optval32 = rand() % 4096; break;
		case 3: *optval32 = rand(); break;
		}
		so->optlen = sizeof(int);
		break;

	default:
		break;
	}
}

static struct socket_triplet unix_triplet[] = {
	{ .family = PF_LOCAL, .protocol = 0, .type = SOCK_DGRAM },
	{ .family = PF_LOCAL, .protocol = 0, .type = SOCK_SEQPACKET },
	{ .family = PF_LOCAL, .protocol = 0, .type = SOCK_STREAM },
};

const struct netproto proto_unix = {
	.name = "unix",
	.gen_sockaddr = unix_gen_sockaddr,
	.setsockopt = unix_setsockopt,
	.valid_triplets = unix_triplet,
	.nr_triplets = ARRAY_SIZE(unix_triplet),
};
