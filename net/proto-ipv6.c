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
#include "uid.h"
#include "compat.h"

#ifndef SOL_TCP
#define SOL_TCP 6
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef SOL_SCTP
#define SOL_SCTP 132
#endif
#ifndef SOL_UDPLITE
#define SOL_UDPLITE 136
#endif
#ifndef SOL_DCCP
#define SOL_DCCP 269
#endif

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
		v6->s6_addr32[3] = v4;

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
	ipv6->sin6_port = htons(rand() % 65536);
	ipv6->sin6_flowinfo = rand();
	ipv6->sin6_scope_id = rand();

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
	{ .name = MCAST_LEAVE_GROUP, .len = sizeof(struct group_req) },
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
	{ .name = IPV6_MULTICAST_ALL, },
	{ .name = IPV6_ROUTER_ALERT_ISOLATE, },
	{ .name = IPV6_RECVERR_RFC4884, },
	{ .name = IPV6_FREEBIND, },
};

static void __inet6_setsockopt(struct sockopt *so)
{
	unsigned char val;

	so->level = SOL_IPV6;

	val = rand() % ARRAY_SIZE(inet6_opts);
	so->optname = inet6_opts[val].name;
	so->optlen = sockoptlen(inet6_opts[val].len);

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
			so->optlen = rand() % (64 * 1024);
		break;
	case IPV6_IPSEC_POLICY:
	case IPV6_XFRM_POLICY:
		so->optlen = rand() % page_size;
		break;
	}
}

static void inet6_ulp_setsockopt(struct sockopt *so)
{
	unsigned char *p = (unsigned char *) so->optval;

	so->level = SOL_TLS;

	switch (rand() % 4) {
	case 0: so->optname = TLS_TX; break;
	case 1: so->optname = TLS_RX; break;
	case 2: so->optname = TLS_TX_ZEROCOPY_RO; break;
	case 3: so->optname = TLS_RX_EXPECT_NO_PAD; break;
	}

	switch (rand() % 6) {
	case 0: {
		struct tls12_crypto_info_aes_gcm_128 *ci = (struct tls12_crypto_info_aes_gcm_128 *) p;

		generate_rand_bytes(p, sizeof(*ci));
		ci->info.version = RAND_BOOL() ? TLS_1_2_VERSION : TLS_1_3_VERSION;
		ci->info.cipher_type = TLS_CIPHER_AES_GCM_128;
		so->optlen = sizeof(*ci);
		break;
	}
	case 1: {
		struct tls12_crypto_info_aes_gcm_256 *ci = (struct tls12_crypto_info_aes_gcm_256 *) p;

		generate_rand_bytes(p, sizeof(*ci));
		ci->info.version = RAND_BOOL() ? TLS_1_2_VERSION : TLS_1_3_VERSION;
		ci->info.cipher_type = TLS_CIPHER_AES_GCM_256;
		so->optlen = sizeof(*ci);
		break;
	}
	case 2: {
		struct tls12_crypto_info_aes_ccm_128 *ci = (struct tls12_crypto_info_aes_ccm_128 *) p;

		generate_rand_bytes(p, sizeof(*ci));
		ci->info.version = TLS_1_2_VERSION;
		ci->info.cipher_type = TLS_CIPHER_AES_CCM_128;
		so->optlen = sizeof(*ci);
		break;
	}
	case 3: {
		struct tls12_crypto_info_chacha20_poly1305 *ci = (struct tls12_crypto_info_chacha20_poly1305 *) p;

		generate_rand_bytes(p, sizeof(*ci));
		ci->info.version = RAND_BOOL() ? TLS_1_2_VERSION : TLS_1_3_VERSION;
		ci->info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
		so->optlen = sizeof(*ci);
		break;
	}
	case 4: {
		struct tls12_crypto_info_sm4_gcm *ci = (struct tls12_crypto_info_sm4_gcm *) p;

		generate_rand_bytes(p, sizeof(*ci));
		ci->info.version = TLS_1_3_VERSION;
		ci->info.cipher_type = TLS_CIPHER_SM4_GCM;
		so->optlen = sizeof(*ci);
		break;
	}
	case 5: {
		struct tls12_crypto_info_sm4_ccm *ci = (struct tls12_crypto_info_sm4_ccm *) p;

		generate_rand_bytes(p, sizeof(*ci));
		ci->info.version = TLS_1_3_VERSION;
		ci->info.cipher_type = TLS_CIPHER_SM4_CCM;
		so->optlen = sizeof(*ci);
		break;
	}
	}
}

static void inet6_setsockopt(struct sockopt *so, struct socket_triplet *triplet)
{
	/* Dispatch to protocol-specific options based on socket protocol.
	 * Without this, IPv6 TCP sockets never get TCP_NODELAY, TCP_CONGESTION,
	 * etc., and IPv6 UDP sockets never get UDP_SEGMENT, UDP_GRO, etc.
	 */
	switch (rand() % 3) {
	case 0:
		__inet6_setsockopt(so);
		break;
	case 1:
		switch (triplet->protocol) {
		case IPPROTO_TCP:
			so->level = SOL_TCP;
			tcp_setsockopt(so, triplet);
			break;
		case IPPROTO_UDP:
			so->level = SOL_UDP;
			udp_setsockopt(so, triplet);
			break;
		case IPPROTO_UDPLITE:
			so->level = SOL_UDPLITE;
			udplite_setsockopt(so, triplet);
			break;
		case IPPROTO_SCTP:
			so->level = SOL_SCTP;
			sctp_setsockopt(so, triplet);
			break;
		case IPPROTO_DCCP:
			so->level = SOL_DCCP;
			dccp_setsockopt(so, triplet);
			break;
		case IPPROTO_MPTCP:
			so->level = SOL_MPTCP;
			mptcp_setsockopt(so, triplet);
			break;
		default:
			__inet6_setsockopt(so);
			break;
		}
		break;
	case 2:
		inet6_ulp_setsockopt(so);
		break;
	}
}

static struct socket_triplet ipv6_triplets[] = {
	{ .family = PF_INET6, .protocol = IPPROTO_IP, .type = SOCK_DGRAM },
	{ .family = PF_INET6, .protocol = IPPROTO_IP, .type = SOCK_SEQPACKET },
	{ .family = PF_INET6, .protocol = IPPROTO_IP, .type = SOCK_STREAM },

	{ .family = PF_INET6, .protocol = IPPROTO_TCP, .type = SOCK_STREAM },

	{ .family = PF_INET6, .protocol = IPPROTO_MPTCP, .type = SOCK_STREAM },

	{ .family = PF_INET6, .protocol = IPPROTO_UDP, .type = SOCK_DGRAM },

	{ .family = PF_INET6, .protocol = IPPROTO_DCCP, .type = SOCK_DCCP },

	{ .family = PF_INET6, .protocol = IPPROTO_SCTP, .type = SOCK_SEQPACKET },

	{ .family = PF_INET6, .protocol = IPPROTO_UDPLITE, .type = SOCK_DGRAM},
};

static struct socket_triplet ipv6_privileged_triplets[] = {
	{ .family = PF_INET6, .protocol = IPPROTO_ICMPV6,  .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = IPPROTO_TCP,     .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = IPPROTO_UDP,     .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = IPPROTO_DCCP,    .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = IPPROTO_GRE,     .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = IPPROTO_ESP,     .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = IPPROTO_AH,      .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = IPPROTO_SCTP,    .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = IPPROTO_UDPLITE, .type = SOCK_RAW },
	{ .family = PF_INET6, .protocol = IPPROTO_RAW,     .type = SOCK_RAW },
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
