#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/x25.h>
#include <stdlib.h>
#include "net.h"
#include "maps.h"	// page_rand
#include "random.h"
#include "utils.h"

void x25_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_x25 *x25;
	unsigned int len;

	x25 = zmalloc(sizeof(struct sockaddr_x25));

	x25->sx25_family = PF_X25;
	len = rand() % 15;
	strncpy(x25->sx25_addr.x25_addr, page_rand, len);	// TODO: generate_rand_bytes()
	*addr = (struct sockaddr *) x25;
	*addrlen = sizeof(struct sockaddr_x25);
}

void x25_rand_socket(struct socket_triplet *st)
{
	st->type = SOCK_SEQPACKET;
	st->protocol = 0;
}

void x25_setsockopt(struct sockopt *so)
{
	so->level = SOL_X25;

	page_rand[0] = rand_bool();
	so->optval = sizeof(int);
}
