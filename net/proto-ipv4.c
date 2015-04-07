#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <linux/mroute.h>
#include "sanitise.h"
#include "compat.h"
#include "maps.h"
#include "net.h"
#include "config.h"
#include "random.h"
#include "utils.h"	// ARRAY_SIZE

/* workaround for <linux/in.h> vs. <netinet/in.h> */
#ifndef IP_MULTICAST_ALL
#define IP_MULTICAST_ALL 49
#endif

static int previous_ip;
static unsigned int ip_lifetime = 0;

struct addrtext {
	const char *name;
	int classmask;
};

#define SLASH8 0xffffff
#define SLASH12 0xfffff
#define SLASH16 0xffff
#define SLASH24 0xff
#define SLASH32 0

static in_addr_t new_ipv4_addr(void)
{
	in_addr_t v4;
	const struct addrtext addresses[] = {
		{ "0.0.0.0", SLASH8 },
		{ "10.0.0.0", SLASH8 },
		{ "127.0.0.0", SLASH8 },
		{ "169.254.0.0", SLASH16 },	/* link-local */
		{ "172.16.0.0", SLASH12 },
		{ "192.88.99.0", SLASH24 },	/* 6to4 anycast */
		{ "192.168.0.0", SLASH16 },
		{ "224.0.0.0", SLASH24 },	/* multi-cast */
		{ "255.255.255.255", SLASH32 },
	};

	int entry = rand() % ARRAY_SIZE(addresses);
	const char *p = addresses[entry].name;

	inet_pton(AF_INET, p, &v4);

	if (addresses[entry].classmask != SLASH32)
		v4 |= htonl(rand() % addresses[entry].classmask);

	return v4;
}

in_addr_t random_ipv4_address(void)
{
	int addr;

	if (ip_lifetime != 0) {
		ip_lifetime--;
		return previous_ip;
	}

	addr = new_ipv4_addr();

	previous_ip = addr;
	ip_lifetime = 5;

	return addr;
}

void ipv4_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_in *ipv4;
	struct in_addr serv_addr;

	ipv4 = zmalloc(sizeof(struct sockaddr_in));

	ipv4->sin_family = PF_INET;
	ipv4->sin_addr.s_addr = random_ipv4_address();
	ipv4->sin_port = htons(rand() % 65535);

	/* Client side if we supplied server_addr */
	if (inet_pton(PF_INET, server_addr, &serv_addr) == 1)
		ipv4->sin_addr = serv_addr;
	/* Server side if we supplied port without addr, so listen on INADDR_ANY */
	else if (server_port != 0)
		ipv4->sin_addr.s_addr = htonl(INADDR_ANY);

	/* Fuzz from port to (port + 100) if supplied */
	if (server_port != 0)
		ipv4->sin_port = htons(server_port + rand() % 100);

	*addr = (struct sockaddr *) ipv4;
	*addrlen = sizeof(struct sockaddr_in);
}

struct ipproto {
	unsigned int proto;
	unsigned int type;
};

void inet_rand_socket(struct socket_triplet *st)
{
	struct ipproto ipprotos[] = {
		{ .proto = IPPROTO_IP, .type = SOCK_RAW },
		{ .proto = IPPROTO_ICMP, },
		{ .proto = IPPROTO_IGMP, },
		{ .proto = IPPROTO_IPIP, },
		{ .proto = IPPROTO_TCP, .type = SOCK_STREAM },
		{ .proto = IPPROTO_EGP, },
		{ .proto = IPPROTO_PUP, },
		{ .proto = IPPROTO_UDP, .type = SOCK_DGRAM },
		{ .proto = IPPROTO_IDP, },
		{ .proto = IPPROTO_TP, },
		{ .proto = IPPROTO_DCCP, .type = SOCK_DCCP },
		{ .proto = IPPROTO_IPV6, },
		{ .proto = IPPROTO_RSVP, },
		{ .proto = IPPROTO_GRE, },
		{ .proto = IPPROTO_ESP, },
		{ .proto = IPPROTO_AH, },
		{ .proto = IPPROTO_MTP, },
		{ .proto = IPPROTO_BEETPH, },
		{ .proto = IPPROTO_ENCAP, },
		{ .proto = IPPROTO_PIM, },
		{ .proto = IPPROTO_COMP, },
		{ .proto = IPPROTO_SCTP, .type = SOCK_SEQPACKET },
		{ .proto = IPPROTO_UDPLITE, },
		{ .proto = IPPROTO_RAW, .type = SOCK_RAW },
	};
	unsigned char val;

	val = rand() % ARRAY_SIZE(ipprotos);
	st->protocol = ipprotos[val].proto;
	if (ipprotos[val].type != 0) {
		st->type = ipprotos[val].type;
		return;
	}

	//TODO: Fill out the rest of the array, then nuke this next bit..

	switch (rand() % 4) {
	case 0: st->type = SOCK_STREAM;     // TCP/SCTP
		break;
	case 1: st->type = SOCK_DGRAM;      // UDP
		break;
	case 2: st->type = SOCK_SEQPACKET;      // SCTP
		break;
	case 3: st->type = SOCK_RAW;
		break;
	}

}

//TODO: Pair the sizeof's of the associated arrays
static const unsigned int ip_opts[] = { IP_TOS, IP_TTL, IP_HDRINCL, IP_OPTIONS,
	IP_ROUTER_ALERT, IP_RECVOPTS, IP_RETOPTS, IP_PKTINFO,
	IP_PKTOPTIONS, IP_MTU_DISCOVER, IP_RECVERR, IP_RECVTTL,
	IP_RECVTOS, IP_MTU, IP_FREEBIND, IP_IPSEC_POLICY,
	IP_XFRM_POLICY, IP_PASSSEC, IP_TRANSPARENT,
	IP_ORIGDSTADDR, IP_MINTTL, IP_NODEFRAG,
	IP_MULTICAST_IF, IP_MULTICAST_TTL, IP_MULTICAST_LOOP,
	IP_ADD_MEMBERSHIP, IP_DROP_MEMBERSHIP,
	IP_UNBLOCK_SOURCE, IP_BLOCK_SOURCE,
	IP_ADD_SOURCE_MEMBERSHIP, IP_DROP_SOURCE_MEMBERSHIP,
	IP_MSFILTER,
	MCAST_JOIN_GROUP, MCAST_BLOCK_SOURCE, MCAST_UNBLOCK_SOURCE, MCAST_LEAVE_GROUP, MCAST_JOIN_SOURCE_GROUP, MCAST_LEAVE_SOURCE_GROUP, MCAST_MSFILTER,
	IP_MULTICAST_ALL, IP_UNICAST_IF,
	MRT_INIT, MRT_DONE, MRT_ADD_VIF, MRT_DEL_VIF,
	MRT_ADD_MFC, MRT_DEL_MFC, MRT_VERSION, MRT_ASSERT,
	MRT_PIM, MRT_TABLE, MRT_ADD_MFC_PROXY, MRT_DEL_MFC_PROXY,
};

void ip_setsockopt(struct sockopt *so)
{
	unsigned char val;
	struct ip_mreqn *mr;
	struct ip_mreq_source *ms;
	int mcaddr;

	so->level = SOL_IP;

	val = rand() % ARRAY_SIZE(ip_opts);
	so->optname = ip_opts[val];

	switch (ip_opts[val]) {
	case IP_PKTINFO:
	case IP_RECVTTL:
	case IP_RECVOPTS:
	case IP_RECVTOS:
	case IP_RETOPTS:
	case IP_TOS:
	case IP_TTL:
	case IP_HDRINCL:
	case IP_MTU_DISCOVER:
	case IP_RECVERR:
	case IP_ROUTER_ALERT:
	case IP_FREEBIND:
	case IP_PASSSEC:
	case IP_TRANSPARENT:
	case IP_MINTTL:
	case IP_NODEFRAG:
	case IP_UNICAST_IF:
	case IP_MULTICAST_TTL:
	case IP_MULTICAST_ALL:
	case IP_MULTICAST_LOOP:
	case IP_RECVORIGDSTADDR:
		if (RAND_BOOL())
			so->optlen = sizeof(int);
		else
			so->optlen = sizeof(char);
		break;

	case IP_OPTIONS:
		so->optlen = rand() % 40;
		break;

	case IP_MULTICAST_IF:
	case IP_ADD_MEMBERSHIP:
	case IP_DROP_MEMBERSHIP:
		mcaddr = 0xe0000000 | rand() % 0xff;

		mr = (struct ip_mreqn *) so->optval;
		mr->imr_multiaddr.s_addr = mcaddr;
		mr->imr_address.s_addr = random_ipv4_address();
		mr->imr_ifindex = rand32();

		so->optlen = sizeof(struct ip_mreqn);
		break;

	case MRT_ADD_VIF:
	case MRT_DEL_VIF:
		so->optlen = sizeof(struct vifctl);
		break;

	case MRT_ADD_MFC:
	case MRT_ADD_MFC_PROXY:
	case MRT_DEL_MFC:
	case MRT_DEL_MFC_PROXY:
		so->optlen = sizeof(struct mfcctl);
		break;

	case MRT_TABLE:
		so->optlen = sizeof(__u32);
		break;

	case IP_MSFILTER:
		//FIXME: Read size from sysctl /proc/sys/net/core/optmem_max
		so->optlen = rand() % sizeof(unsigned long)*(2*UIO_MAXIOV+512);
		so->optlen |= IP_MSFILTER_SIZE(0);
		break;

	case IP_BLOCK_SOURCE:
	case IP_UNBLOCK_SOURCE:
	case IP_ADD_SOURCE_MEMBERSHIP:
	case IP_DROP_SOURCE_MEMBERSHIP:
		mcaddr = 0xe0000000 | rand() % 0xff;

		ms = (struct ip_mreq_source *) so->optval;
		ms->imr_multiaddr.s_addr = mcaddr;
		ms->imr_interface.s_addr = random_ipv4_address();
		ms->imr_sourceaddr.s_addr = random_ipv4_address();

		so->optlen = sizeof(struct ip_mreq_source);
		break;

	case MCAST_JOIN_GROUP:
	case MCAST_LEAVE_GROUP:
		so->optlen = sizeof(struct group_req);
		break;

	case MCAST_JOIN_SOURCE_GROUP:
	case MCAST_LEAVE_SOURCE_GROUP:
	case MCAST_BLOCK_SOURCE:
	case MCAST_UNBLOCK_SOURCE:
		so->optlen = sizeof(struct group_source_req);
		break;

	case MCAST_MSFILTER:
		//FIXME: Read size from sysctl /proc/sys/net/core/optmem_max
		so->optlen = rand() % sizeof(unsigned long)*(2*UIO_MAXIOV+512);
		so->optlen |= GROUP_FILTER_SIZE(0);
		break;

	default:
		break;
	}
}
