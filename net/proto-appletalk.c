
#ifdef USE_APPLETALK
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netatalk/at.h>
#include <linux/atalk.h>
#include "random.h"
#include "net.h"
#include "utils.h"

static void atalk_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_at *atalk;

	atalk = zmalloc(sizeof(struct sockaddr_at));

	atalk->sat_family = PF_APPLETALK;
	atalk->sat_port = rnd();
	atalk->sat_addr.s_net = rnd();
	atalk->sat_addr.s_node = rnd();
	*addr = (struct sockaddr *) atalk;
	*addrlen = sizeof(struct sockaddr_at);
}

static void atalk_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_ATALK;
}

static struct socket_triplet atalk_triplets[] = {
	{ .family = PF_APPLETALK, .protocol = 0, .type = SOCK_DGRAM },
	// Atalk will let us create 256 RAW sockets, but we only need one.
	{ .family = PF_APPLETALK, .protocol = 0, .type = SOCK_RAW },
};

const struct netproto proto_appletalk = {
	.name = "appletalk",
	.setsockopt = atalk_setsockopt,
	.gen_sockaddr = atalk_gen_sockaddr,
	.valid_triplets = atalk_triplets,
	.nr_triplets = ARRAY_SIZE(atalk_triplets),
};
#endif
