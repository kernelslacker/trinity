#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <neteconet/ec.h>
#include <stdlib.h>
#include "net.h"

void econet_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_ec *ec;

	ec = malloc(sizeof(struct sockaddr_ec));
	if (ec == NULL)
		return;

	ec->sec_family = PF_ECONET;
	ec->port = rand();
	ec->cb = rand();
	ec->type = rand();
	ec->addr.station = rand();
	ec->addr.net = rand();
	ec->cookie = rand();
	*addr = (struct sockaddr *) ec;
	*addrlen = sizeof(struct sockaddr_ec);
}
