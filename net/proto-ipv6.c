#include "config.h"

#ifdef USE_IPV6
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// ARRAY_SIZE
#include "compat.h"

static void gen_random_ipv6_address(struct in6_addr *v6)
{
	in_addr_t v4 = random_ipv4_address();

	switch (rand() % 9) {
	case 0:
		/* deprecated ipv4 style ::v4 */
		v6->s6_addr32[0] = 0;
		v6->s6_addr32[1] = 0;
		v6->s6_addr32[2] = 0;
		v6->s6_addr32[3] = htonl(v4);
		break;
	case 1:
		/* v4 in v6 ::ffff:0:0/96 */
		v6->s6_addr32[0] = 0;
		v6->s6_addr32[1] = 0;
		v6->s6_addr32[2] = 0xffffffff;
		v6->s6_addr32[3] = htonl(v4);
		break;
	case 2:
		/* ::1/128 loopback */
		v6->s6_addr32[0] = 0;
		v6->s6_addr32[1] = 0;
		v6->s6_addr32[2] = 0;
		v6->s6_addr32[3] = htonl(1);
		break;
	case 3:
		/* ::/128 unspecified */
		v6->s6_addr32[0] = 0;
		v6->s6_addr32[1] = 0;
		v6->s6_addr32[2] = 0;
		v6->s6_addr32[3] = 0;
		break;
	case 4:
		/* 2002::/16 "6to4" */
		inet_pton(AF_INET6, "2002::", v6);
		v6->s6_addr32[3] = htonl(v4);
		break;
	case 5:
		/* fe80::/10 link-local */
		inet_pton(AF_INET6, "fe80::", v6);
		break;
	case 6:
		/* fc00::/7  unique local address (ULA) */
		inet_pton(AF_INET6, "fc00::", v6);
		break;
	case 7:
		/* 64:ff9b::/96 "Well known" prefix */
		inet_pton(AF_INET6, "64:ff9b::", v6);
		break;
	case 8:
		/* 0100::/64 remotely triggered blackhole */
		inet_pton(AF_INET6, "0100::", v6);
		break;
	}
}

void ipv6_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_in6 *ipv6;
	struct in6_addr serv_addr;

	ipv6 = zmalloc(sizeof(struct sockaddr_in6));

	ipv6->sin6_family = PF_INET6;

	gen_random_ipv6_address(&ipv6->sin6_addr);
	ipv6->sin6_port = htons(rand() % 65535);

	/* Client side if we supplied server_addr */
	if (inet_pton(PF_INET6, server_addr, &serv_addr) == 1)
		ipv6->sin6_addr = serv_addr;
	/* Server side if we supplied port without addr, so listen on in6addr_any */
	else if (server_port != 0)
		ipv6->sin6_addr = in6addr_any;

	/* Fuzz from port to (port + 100) if supplied */
	if (server_port != 0)
		ipv6->sin6_port = htons(server_port + rand() % 100);

	*addr = (struct sockaddr *) ipv6;
	*addrlen = sizeof(struct sockaddr_in6);
}

void inet6_rand_socket(struct socket_triplet *st)
{
	switch (rand() % 4) {
	case 0: st->type = SOCK_STREAM;     // TCP/SCTP
		switch (rand() % 3) {
		case 0:
			st->protocol = 0;
			break;
		case 1:
			st->protocol = IPPROTO_TCP;
			break;
		case 2:
			st->protocol = IPPROTO_SCTP;
			break;
		default:
			break;
		}
		break;

	case 1: st->type = SOCK_DGRAM;      // UDP
		if (RAND_BOOL())
			st->protocol = 0;
		else
			st->protocol = IPPROTO_UDP;
		break;

	case 2: st->type = SOCK_SEQPACKET;      // SCTP
		if (RAND_BOOL())
			st->protocol = 0;
		else
			st->protocol = IPPROTO_SCTP;
		break;

	case 3: st->type = SOCK_RAW;
		st->protocol = rand() % PROTO_MAX;
		break;

	default:
		break;
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
#endif
