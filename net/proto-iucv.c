#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <netiucv/iucv.h>
#include "net.h"
#include "compat.h"

/*
 * IUCV is an s390-only transport.  Probe the machine type once and cache
 * the result so we skip iucv socket work on any other architecture.
 */
static bool iucv_available(void)
{
	static int cached = -1;
	struct utsname buf;

	if (cached != -1)
		return cached;

	if (uname(&buf) != 0) {
		cached = 0;
		return false;
	}
	cached = (strncmp(buf.machine, "s390", 4) == 0);
	return cached;
}

static const unsigned int iucv_opts[] = {
	SO_IPRMDATA_MSG, SO_MSGLIMIT, SO_MSGSIZE
};

static void iucv_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	if (!iucv_available())
		return;

	so->level = SOL_IUCV;

	so->optname = RAND_ARRAY(iucv_opts);

	so->optlen = sizeof(int);
}

static void iucv_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_iucv *sa;
	unsigned int i;

	if (!iucv_available()) {
		*addr = zmalloc(sizeof(struct sockaddr));
		*addrlen = sizeof(struct sockaddr);
		return;
	}

	sa = zmalloc(sizeof(struct sockaddr_iucv));
	sa->siucv_family = AF_IUCV;

	for (i = 0; i < sizeof(sa->siucv_user_id); i++)
		sa->siucv_user_id[i] = rand();
	for (i = 0; i < sizeof(sa->siucv_name); i++)
		sa->siucv_name[i] = rand();

	*addr = (struct sockaddr *) sa;
	*addrlen = sizeof(struct sockaddr_iucv);
}

static struct socket_triplet iucv_triplets[] = {
	{ .family = AF_IUCV, .protocol = 0, .type = SOCK_STREAM },
	{ .family = AF_IUCV, .protocol = 0, .type = SOCK_SEQPACKET },
};

const struct netproto proto_iucv = {
	.name = "iucv",
//	.socket = iucv_rand_socket,
	.setsockopt = iucv_setsockopt,
	.gen_sockaddr = iucv_gen_sockaddr,
	.valid_triplets = iucv_triplets,
	.nr_triplets = ARRAY_SIZE(iucv_triplets),
};
