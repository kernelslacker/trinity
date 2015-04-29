#include "config.h"

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

void atalk_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_at *atalk;

	atalk = zmalloc(sizeof(struct sockaddr_at));

	atalk->sat_family = PF_APPLETALK;
	atalk->sat_port = rand();
	atalk->sat_addr.s_net = rand();
	atalk->sat_addr.s_node = rand();
	*addr = (struct sockaddr *) atalk;
	*addrlen = sizeof(struct sockaddr_at);
}

void atalk_rand_socket(struct socket_triplet *st)
{
	if (RAND_BOOL()) {
		st->type = SOCK_DGRAM;
	        st->protocol = 0;
	        return;
	}

	st->protocol = rand() % PROTO_MAX;
	st->type = SOCK_RAW;
}
#endif
