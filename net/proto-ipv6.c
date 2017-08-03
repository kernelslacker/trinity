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
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "arch.h"
#include "net.h"
#include "random.h"
#include "tls.h"
#include "utils.h"	// ARRAY_SIZE
#include "uid.h"
#include "compat.h"

struct addrtext {
	const char *name;
};

static void gen_random_ipv6_address(struct in6_addr *v6)
{
	const char *p;

	/* 90% of the time, just do localhost */
	if (!(ONE_IN(10))) {
		inet_pton(AF_INET6, "::1", v6);
		return;
	}

	if (RAND_BOOL()) {
		/* v4 in v6 somehow. */

		in_addr_t v4;
		const struct addrtext v4_in_v6_addresses[] = {
			{ "::" },		/* deprecated ipv4 style ::v4 */
			{ "::ffff:0:0" },	/* v4 in v6 ::ffff:0:0/96 */
			{ "::ffff:0:0:0" },	/* stateless IP/ICMP translation (SIIT) ::ffff:0:0:0/96 */
			{ "2002::" },		/* 2002::/16 "6to4" */
		};

		p = RAND_ELEMENT(v4_in_v6_addresses, name);
		inet_pton(AF_INET6, p, v6);

		v4 = random_ipv4_address();
		v6->s6_addr32[3] = htonl(v4);

	} else {
		/* actual v6 addresses. */

		const struct addrtext v6_addresses[] = {
			{ "::" },		/* ::/128 unspecified */
			{ "fe80::" },		/* fe80::/10 link-local */
			{ "fc00::" },		/* fc00::/7  unique local address (ULA) */
			{ "64:ff9b::" },	/* 64:ff9b::/96 "Well known" prefix */
			{ "0100::" },		/* 0100::/64 remotely triggered blackhole */
		};

		p = RAND_ELEMENT(v6_addresses, name);
		inet_pton(AF_INET6, p, v6);
	}
}

static void ipv6_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_in6 *ipv6;

	ipv6 = zmalloc(sizeof(struct sockaddr_in6));

	ipv6->sin6_family = PF_INET6;

	gen_random_ipv6_address(&ipv6->sin6_addr);
	ipv6->sin6_port = htons(rnd() % 65535);
	ipv6->sin6_flowinfo = rnd();
	ipv6->sin6_scope_id = rnd();

	*addr = (struct sockaddr *) ipv6;
	*addrlen = sizeof(struct sockaddr_in6);
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
	{ .name = IPV6_HDRINCL, },

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

	{ .name = IP6T_SO_SET_REPLACE, },
	{ .name = IP6T_SO_SET_ADD_COUNTERS, },

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
	{ .name = IPV6_RECVFRAGSIZE, },
};

static void __inet6_setsockopt(struct sockopt *so)
{
	unsigned char val;

	so->level = SOL_IPV6;

	val = rnd() % ARRAY_SIZE(inet6_opts);
	so->optname = inet6_opts[val].name;
	so->optlen = sockoptlen(inet6_opts[val].len);

	switch (so->optname) {
	case IPV6_HOPOPTS:
	case IPV6_RTHDRDSTOPTS:
	case IPV6_RTHDR:
	case IPV6_DSTOPTS:
		so->optlen = sizeof(struct ipv6_opt_hdr);
		so->optlen += rnd() % ((8 * 255) - so->optlen);
		so->optlen &= ~0x7;
		break;
	case IPV6_2292PKTOPTIONS:
		if (RAND_BOOL())
			so->optlen = 0;	// update
		else
			so->optlen = rnd() % 64*1024;
		break;
	case IPV6_IPSEC_POLICY:
	case IPV6_XFRM_POLICY:
		so->optlen = rnd() % page_size;
		break;
	}
}

static void inet6_ulp_setsockopt(struct sockopt *so)
{
	// For now, we only support TLS sockets. Extend if/when more ULPs appear.
	struct tls12_crypto_info_aes_gcm_128 *crypto_info;

	crypto_info = (struct tls12_crypto_info_aes_gcm_128 *) so->optval;
	crypto_info->info.version = TLS_1_2_VERSION;
	crypto_info->info.cipher_type = TLS_CIPHER_AES_GCM_128;

	so->level = SOL_TLS;
	so->optname = TLS_TX;
	so->optlen = sizeof(struct tls12_crypto_info_aes_gcm_128);
}

static void inet6_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	if (RAND_BOOL()) {
		__inet6_setsockopt(so);
	} else {
		inet6_ulp_setsockopt(so);
	}
}

static struct socket_triplet ipv6_triplets[] = {
	{ .family = PF_INET6, .protocol = IPPROTO_IP, .type = SOCK_DGRAM },
	{ .family = PF_INET6, .protocol = IPPROTO_IP, .type = SOCK_SEQPACKET },
	{ .family = PF_INET6, .protocol = IPPROTO_IP, .type = SOCK_STREAM },

	{ .family = PF_INET6, .protocol = IPPROTO_TCP, .type = SOCK_STREAM },

	{ .family = PF_INET6, .protocol = IPPROTO_UDP, .type = SOCK_DGRAM },

	{ .family = PF_INET6, .protocol = IPPROTO_DCCP, .type = SOCK_DCCP },

	{ .family = PF_INET6, .protocol = IPPROTO_SCTP, .type = SOCK_SEQPACKET },

	{ .family = PF_INET6, .protocol = IPPROTO_UDPLITE, .type = SOCK_DGRAM},
};

static struct socket_triplet ipv6_privileged_triplets[] = {
	{ .family = PF_INET6, .protocol = 0, .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = 1, .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = 2, .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = 3, .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = 4, .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = 5, .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = 6, .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = 7, .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = 8, .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = 9, .type = SOCK_RAW },
	//TBD: Is it worth doing all 256 of these ?
};

const struct netproto proto_inet6 = {
	.name = "inet6",
	.setsockopt = inet6_setsockopt,
	.gen_sockaddr = ipv6_gen_sockaddr,
	.valid_triplets = ipv6_triplets,
	.nr_triplets = ARRAY_SIZE(ipv6_triplets),
	.valid_privileged_triplets = ipv6_privileged_triplets,
	.nr_privileged_triplets = ARRAY_SIZE(ipv6_privileged_triplets),
};
#endif
