#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <stdlib.h>

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
