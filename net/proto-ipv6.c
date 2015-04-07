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

struct addrtext {
	const char *name;
};

static void gen_random_ipv6_address(struct in6_addr *v6)
{
	const char *p;

	if (RAND_BOOL()) {
		/* v4 in v6 somehow. */

		in_addr_t v4;
		const struct addrtext v4_in_v6_addresses[] = {
			{ "::" },		/* deprecated ipv4 style ::v4 */
			{ "::ffff:0:0" },	/* v4 in v6 ::ffff:0:0/96 */
			{ "::ffff:0:0:0" },	/* stateless IP/ICMP translation (SIIT) ::ffff:0:0:0/96 */
			{ "2002::" },		/* 2002::/16 "6to4" */
		};

		p = v4_in_v6_addresses[rand() % ARRAY_SIZE(v4_in_v6_addresses)].name;
		inet_pton(AF_INET6, p, v6);

		v4 = random_ipv4_address();
		v6->s6_addr32[3] = htonl(v4);

	} else {
		/* actual v6 addresses. */

		const struct addrtext v6_addresses[] = {
			{ "::1" },		/* ::1/128 loopback */
			{ "::" },		/* ::/128 unspecified */
			{ "fe80::" },		/* fe80::/10 link-local */
			{ "fc00::" },		/* fc00::/7  unique local address (ULA) */
			{ "64:ff9b::" },	/* 64:ff9b::/96 "Well known" prefix */
			{ "0100::" },		/* 0100::/64 remotely triggered blackhole */
		};

		p = v6_addresses[rand() % ARRAY_SIZE(v6_addresses)].name;
		inet_pton(AF_INET6, p, v6);
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

static const unsigned int inet6_opts[] = {
	IPV6_ADDRFORM, IPV6_2292PKTINFO, IPV6_2292HOPOPTS, IPV6_2292DSTOPTS,
	IPV6_2292RTHDR, IPV6_2292PKTOPTIONS, IPV6_CHECKSUM, IPV6_2292HOPLIMIT,
	IPV6_NEXTHOP, IPV6_AUTHHDR, IPV6_FLOWINFO, IPV6_UNICAST_HOPS,
	IPV6_MULTICAST_IF, IPV6_MULTICAST_HOPS, IPV6_MULTICAST_LOOP, IPV6_ADD_MEMBERSHIP,
	IPV6_DROP_MEMBERSHIP, IPV6_ROUTER_ALERT, IPV6_MTU_DISCOVER, IPV6_MTU,
	IPV6_RECVERR, IPV6_V6ONLY, IPV6_JOIN_ANYCAST, IPV6_LEAVE_ANYCAST,
	IPV6_FLOWLABEL_MGR, IPV6_FLOWINFO_SEND, IPV6_IPSEC_POLICY, IPV6_XFRM_POLICY,
	MCAST_JOIN_GROUP, MCAST_BLOCK_SOURCE, MCAST_UNBLOCK_SOURCE, MCAST_LEAVE_GROUP,
	MCAST_JOIN_SOURCE_GROUP, MCAST_LEAVE_SOURCE_GROUP, MCAST_MSFILTER,
	IPV6_RECVPKTINFO, IPV6_PKTINFO, IPV6_RECVHOPLIMIT, IPV6_HOPLIMIT,
	IPV6_RECVHOPOPTS, IPV6_HOPOPTS, IPV6_RTHDRDSTOPTS, IPV6_RECVRTHDR,
	IPV6_RTHDR, IPV6_RECVDSTOPTS, IPV6_DSTOPTS, IPV6_RECVPATHMTU,
	IPV6_PATHMTU, IPV6_DONTFRAG,
	IPV6_RECVTCLASS, IPV6_TCLASS,
	IP6T_SO_GET_REVISION_MATCH, IP6T_SO_GET_REVISION_TARGET, IP6T_SO_ORIGINAL_DST,
	IPV6_AUTOFLOWLABEL, IPV6_ADDR_PREFERENCES,
	IPV6_MINHOPCOUNT, IPV6_ORIGDSTADDR, IPV6_TRANSPARENT, IPV6_UNICAST_IF
};

void inet6_setsockopt(struct sockopt *so)
{
	unsigned char val;

	so->level = SOL_IPV6;

	val = rand() % ARRAY_SIZE(inet6_opts);
	so->optname = inet6_opts[val];
}
#endif
