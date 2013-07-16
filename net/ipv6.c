#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"

void gen_ipv6(unsigned long *addr, unsigned long *addrlen)
{
	struct sockaddr_in6 *ipv6;

	ipv6 = malloc(sizeof(struct sockaddr_in6));
	if (ipv6 == NULL)
		return;

	ipv6->sin6_family = PF_INET6;
	ipv6->sin6_addr.s6_addr32[0] = 0;
	ipv6->sin6_addr.s6_addr32[1] = 0;
	ipv6->sin6_addr.s6_addr32[2] = 0;
	ipv6->sin6_addr.s6_addr32[3] = htonl(1);
	ipv6->sin6_port = rand() % 65535;
	*addr = (unsigned long) ipv6;
	*addrlen = sizeof(struct sockaddr_in6);
}

void inet6_rand_socket(struct proto_type *pt)
{
	switch (rand() % 3) {
	case 0: pt->type = SOCK_STREAM;     // TCP
		pt->protocol = 0;
		break;

	case 1: pt->type = SOCK_DGRAM;      // UDP
		if (rand_bool())
			pt->protocol = 0;
		else
			pt->protocol = IPPROTO_UDP;
		break;

	case 2: pt->type = SOCK_RAW;
		pt->protocol = rand() % PROTO_MAX;
		break;

	default:break;
	}
}
