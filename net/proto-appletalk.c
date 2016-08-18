#include "config.h"

#ifdef USE_APPLETALK
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netatalk/at.h>
#include <linux/atalk.h>
#include "log.h"
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

static void atalk_rand_socket(struct socket_triplet *st)
{
	if (RAND_BOOL()) {
		st->type = SOCK_DGRAM;
	        st->protocol = 0;
	        return;
	}

	st->protocol = rnd() % PROTO_MAX;
	st->type = SOCK_RAW;
}

static void atalk_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_ATALK;
}

static void generate_atalk(unsigned int protocol, unsigned int type)
{
	struct socket_triplet st;
	int fd;

	st.family = PF_APPLETALK;
	st.type = type;
	st.protocol = protocol;

	fd = open_socket(st.family, st.type, st.protocol);
	if (fd > -1) {
		write_socket_to_cache(&st);
		return;
	}
	output(0, "Couldn't open socket PF_INET:%d:%d. %s\n", type, protocol, strerror(errno));
}

static void gen_atalk(void)
{
	generate_atalk(0, SOCK_DGRAM);

	// Atalk will let us create 256 RAW sockets, but we only need one.
	generate_atalk(0, SOCK_RAW);
}

const struct netproto proto_appletalk = {
	.name = "appletalk",
	.socket = atalk_rand_socket,
	.setsockopt = atalk_setsockopt,
	.gen_sockaddr = atalk_gen_sockaddr,
	.generate = gen_atalk,
};
#endif
