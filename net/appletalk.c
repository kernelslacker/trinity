#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/atalk.h>
#include "random.h"
#include "net.h"

void gen_appletalk(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_at *atalk;

	atalk = malloc(sizeof(struct sockaddr_at));
	if (atalk == NULL)
		return;

	atalk->sat_family = PF_APPLETALK;
	atalk->sat_port = rand();
	atalk->sat_addr.s_net = rand();
	atalk->sat_addr.s_node = rand();
	*addr = (unsigned long) atalk;
	*addrlen = sizeof(struct sockaddr_at);
}

void appletalk_rand_socket(struct proto_type *pt)
{
	if (rand_bool()) {
		pt->type = SOCK_DGRAM;
	        pt->protocol = 0;
	        return;
	}

	pt->protocol = rand() % PROTO_MAX;
	pt->type = SOCK_RAW;
}
