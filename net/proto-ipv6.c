#include "config.h"

#ifdef USE_IPV6
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <linux/in6.h>	// needed for in6_flowlabel_req
#include <linux/if.h>
#include <linux/ipv6.h>	// needed for ipv6_opt_hdr
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "arch.h"
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
	// Use the same socket generator as ipv4
	inet_rand_socket(st);
}

static const struct sock_option inet6_opts[] = {
	{ .name = IPV6_ADDRFORM, },
	{ .name = IPV6_2292PKTINFO, },
	{ .name = IPV6_2292HOPOPTS, },
	{ .name = IPV6_2292DSTOPTS, },
	{ .name = IPV6_2292RTHDR, },
	{ .name = IPV6_2292PKTOPTIONS, },
	{ .name = IPV6_CHECKSUM, },
	{ .name = IPV6_2292HOPLIMIT, },
	{ .name = IPV6_NEXTHOP, },
	{ .name = IPV6_AUTHHDR, },
	{ .name = IPV6_FLOWINFO, },
	{ .name = IPV6_UNICAST_HOPS, },
	{ .name = IPV6_MULTICAST_IF, },
	{ .name = IPV6_MULTICAST_HOPS, },
	{ .name = IPV6_MULTICAST_LOOP, },
	{ .name = IPV6_ADD_MEMBERSHIP, .len = sizeof(struct ipv6_mreq) },
	{ .name = IPV6_DROP_MEMBERSHIP, .len = sizeof(struct ipv6_mreq) },
	{ .name = IPV6_ROUTER_ALERT, },
	{ .name = IPV6_MTU_DISCOVER, },
	{ .name = IPV6_MTU, },
	{ .name = IPV6_RECVERR, },
	{ .name = IPV6_V6ONLY, },
	{ .name = IPV6_JOIN_ANYCAST, .len = sizeof(struct ipv6_mreq) },
	{ .name = IPV6_LEAVE_ANYCAST, .len = sizeof(struct ipv6_mreq) },
	{ .name = IPV6_FLOWLABEL_MGR, .len = sizeof(struct in6_flowlabel_req) },
	{ .name = IPV6_FLOWINFO_SEND, },
	{ .name = IPV6_IPSEC_POLICY, },
	{ .name = IPV6_XFRM_POLICY, },
	{ .name = MCAST_JOIN_GROUP, .len = sizeof(struct group_req) },
	{ .name = MCAST_BLOCK_SOURCE, .len = sizeof(struct group_source_req) },
	{ .name = MCAST_UNBLOCK_SOURCE, .len = sizeof(struct group_source_req) },
	{ .name = MCAST_LEAVE_GROUP, sizeof(struct group_req) },
	{ .name = MCAST_JOIN_SOURCE_GROUP, .len = sizeof(struct group_source_req) },
	{ .name = MCAST_LEAVE_SOURCE_GROUP, .len = sizeof(struct group_source_req) },
	{ .name = MCAST_MSFILTER, },
	{ .name = IPV6_RECVPKTINFO, },
	{ .name = IPV6_PKTINFO, .len = sizeof(struct in6_pktinfo) },
	{ .name = IPV6_RECVHOPLIMIT, },
	{ .name = IPV6_HOPLIMIT, },
	{ .name = IPV6_RECVHOPOPTS, },
	{ .name = IPV6_HOPOPTS, },
	{ .name = IPV6_RTHDRDSTOPTS, },
	{ .name = IPV6_RECVRTHDR, },
	{ .name = IPV6_RTHDR, },
	{ .name = IPV6_RECVDSTOPTS, },
	{ .name = IPV6_DSTOPTS, },
	{ .name = IPV6_RECVPATHMTU, },
	{ .name = IPV6_PATHMTU, },
	{ .name = IPV6_DONTFRAG, },
	{ .name = IPV6_RECVTCLASS, },
	{ .name = IPV6_TCLASS, },
	{ .name = IP6T_SO_GET_REVISION_MATCH, },
	{ .name = IP6T_SO_GET_REVISION_TARGET, },
	{ .name = IP6T_SO_ORIGINAL_DST, },
	{ .name = IPV6_AUTOFLOWLABEL, },
	{ .name = IPV6_ADDR_PREFERENCES, },
	{ .name = IPV6_MINHOPCOUNT, },
	{ .name = IPV6_ORIGDSTADDR, },
	{ .name = IPV6_TRANSPARENT, },
	{ .name = IPV6_UNICAST_IF, },
};

void inet6_setsockopt(struct sockopt *so)
{
	unsigned char val;

	val = rand() % ARRAY_SIZE(inet6_opts);
	so->optname = inet6_opts[val].name;
	if (inet6_opts[val].len == 0)
		so->optlen = sizeof(int);
	else
		so->optlen = inet6_opts[val].len;

	switch (so->optname) {
	case IPV6_HOPOPTS:
	case IPV6_RTHDRDSTOPTS:
	case IPV6_RTHDR:
	case IPV6_DSTOPTS:
		so->optlen = sizeof(struct ipv6_opt_hdr);
		so->optlen += rand() % ((8 * 255) - so->optlen);
		so->optlen &= ~0x7;
		break;
	case IPV6_2292PKTOPTIONS:
		if (RAND_BOOL())
			so->optlen = 0;	// update
		else
			so->optlen = rand() % 64*1024;
		break;
	case IPV6_IPSEC_POLICY:
	case IPV6_XFRM_POLICY:
		so->optlen = rand() % page_size;
		break;

	}
}
#endif
