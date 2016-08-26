#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/dn.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"

static void unix_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_un *unixsock;
	unsigned int len;

	unixsock = zmalloc(sizeof(struct sockaddr_un));

	unixsock->sun_family = PF_UNIX;
	len = rnd() % 20;
	generate_rand_bytes((unsigned char *)unixsock->sun_path, len);
	*addr = (struct sockaddr *) unixsock;
	*addrlen = sizeof(struct sockaddr_un);
}

static void unix_rand_socket(struct socket_triplet *st)
{
	st->protocol = 0;

	switch (rnd() % 3) {
	case 0: st->type = SOCK_STREAM;
		break;
	case 1: st->type = SOCK_DGRAM;
		break;
	case 2: st->type = SOCK_SEQPACKET;
		break;
	default:break;
	}
}

static struct socket_triplet unix_triplet[] = {
	{ .family = PF_LOCAL, .protocol = 0, .type = SOCK_DGRAM },
	{ .family = PF_LOCAL, .protocol = 0, .type = SOCK_SEQPACKET },
	{ .family = PF_LOCAL, .protocol = 0, .type = SOCK_STREAM },
};

const struct netproto proto_unix = {
	.name = "unix",
	.socket = unix_rand_socket,
	.gen_sockaddr = unix_gen_sockaddr,
	.valid_triplets = unix_triplet,
	.nr_triplets = ARRAY_SIZE(unix_triplet),
};
