#include <sys/socket.h>
#include <sys/un.h>
#include "arch.h"	// page_size
#include "net.h"
#include "params.h"	// do_specific_domain
#include "random.h"
#include "rnd.h"

void generate_sockaddr(struct sockaddr **addr, socklen_t *addrlen, int pf)
{
	const struct netproto *proto;

	if (RAND_BOOL()) {
		struct sockaddr_un *un;

		un = (struct sockaddr_un *) *addr;
		if (un == NULL)
			un = zmalloc_tracked(sizeof(struct sockaddr_un));
		un->sun_family = PF_UNSPEC;
		*addr = (struct sockaddr *) un;
		*addrlen = sizeof(sa_family_t);
		return;
	}

	/* If we want sockets of a specific type, we'll want sockaddrs that match. */
	if (do_specific_domain == true)
		pf = specific_domain;

	/* If we got no hint passed down, pick a random proto. */
	if (pf == -1)
		pf = rnd_modulo_u32(TRINITY_PF_MAX);

	proto = net_protocols[pf].proto;
	if (proto != NULL) {
		if (proto->gen_sockaddr != NULL) {
			struct socket_triplet stub = { .family = pf };
			proto->gen_sockaddr(&stub, addr, addrlen);
			return;
		}
	}

	/* Make something up for unknown protocols. */
	*addr = (struct sockaddr *) zmalloc_tracked(page_size);
	*addrlen = rnd_modulo_u32(page_size - 1) + 1;
}
