#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <stdlib.h>
#include "maps.h"	// page_rand
#include "net.h"
#include "random.h"
#include "utils.h"	// ARRAY_SIZE
#include "compat.h"

void ipv6_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_in6 *ipv6;

	ipv6 = zmalloc(sizeof(struct sockaddr_in6));

	ipv6->sin6_family = PF_INET6;
	ipv6->sin6_addr.s6_addr32[0] = 0;
	ipv6->sin6_addr.s6_addr32[1] = 0;
	ipv6->sin6_addr.s6_addr32[2] = 0;
	ipv6->sin6_addr.s6_addr32[3] = htonl(1);
	ipv6->sin6_port = htons(rand() % 65535);
	*addr = (struct sockaddr *) ipv6;
	*addrlen = sizeof(struct sockaddr_in6);
}

void inet6_rand_socket(struct socket_triplet *st)
{
	switch (rand() % 3) {
	case 0: st->type = SOCK_STREAM;     // TCP
		st->protocol = 0;
		break;

	case 1: st->type = SOCK_DGRAM;      // UDP
		if (rand_bool())
			st->protocol = 0;
		else
			st->protocol = IPPROTO_UDP;
		break;

	case 2: st->type = SOCK_RAW;
		st->protocol = rand() % PROTO_MAX;
		break;

	default:break;
	}
}

#define NR_SOL_INET6_OPTS ARRAY_SIZE(inet6_opts)
static const unsigned int inet6_opts[] = {
	IPV6_ADDRFORM, IPV6_2292PKTINFO, IPV6_2292HOPOPTS, IPV6_2292DSTOPTS,
	IPV6_2292RTHDR, IPV6_2292PKTOPTIONS, IPV6_CHECKSUM, IPV6_2292HOPLIMIT,
	IPV6_NEXTHOP, IPV6_AUTHHDR, IPV6_FLOWINFO, IPV6_UNICAST_HOPS,
	IPV6_MULTICAST_IF, IPV6_MULTICAST_HOPS, IPV6_MULTICAST_LOOP, IPV6_ADD_MEMBERSHIP,
	IPV6_DROP_MEMBERSHIP, IPV6_ROUTER_ALERT, IPV6_MTU_DISCOVER, IPV6_MTU,
	IPV6_RECVERR, IPV6_V6ONLY, IPV6_JOIN_ANYCAST, IPV6_LEAVE_ANYCAST };

void inet6_setsockopt(struct sockopt *so)
{
	unsigned char val;

	so->level = SOL_IPV6;

	val = rand() % NR_SOL_INET6_OPTS;
	so->optname = inet6_opts[val];
}
