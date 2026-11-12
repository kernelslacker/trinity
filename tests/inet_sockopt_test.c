/*
 * Self-check for the inet option dispatch, which draws a socket its
 * protocol's options a third of the time: inet_create() and
 * inet6_create() make a protocol of 0 the first one registered for the
 * socket's type, TCP for a stream socket, UDP for a datagram one and
 * SCTP, once loaded, for a seqpacket one, so such a socket takes that
 * protocol's options; a raw socket takes none of its protocol's, but the
 * raw layer's at SOL_RAW; and rawv6_setsockopt() takes ICMPV6_FILTER from
 * a raw ICMPv6 socket, and no other socket does, an IPv4 one least of all.
 */

#include <linux/icmpv6.h>	/* ICMPV6_FILTER */
#include <netinet/in.h>
#include <netinet/tcp.h>	/* SOL_TCP */
#include <netinet/udp.h>	/* SOL_UDP */
#include <string.h>
#include <sys/socket.h>

#include "debug.h"		/* BUG */
#include "net.h"		/* proto_ipv4, proto_inet6, struct sockopt */
#include "utils-macros.h"	/* ARRAY_SIZE */

#include "kernel/socket.h"	/* SOL_SCTP */

#define INET_ROUNDS	3000
#define INET_OPTVAL_LEN	4096

void inet_sockopt_self_check(void);
void inet_sockopt_self_check(void)
{
	static const struct {
		const struct netproto *proto;
		struct socket_triplet triplet;
		unsigned int level;
	} shapes[] = {
		{ &proto_ipv4, { .family = PF_INET, .type = SOCK_STREAM },
		  SOL_TCP },
		{ &proto_ipv4, { .family = PF_INET, .type = SOCK_DGRAM },
		  SOL_UDP },
		{ &proto_ipv4, { .family = PF_INET, .type = SOCK_SEQPACKET },
		  SOL_SCTP },
		{ &proto_ipv4, { .family = PF_INET, .type = SOCK_RAW,
				 .protocol = IPPROTO_ICMP },
		  SOL_RAW },
		{ &proto_ipv4, { .family = PF_INET, .type = SOCK_RAW,
				 .protocol = IPPROTO_TCP },
		  SOL_RAW },
		{ &proto_inet6, { .family = PF_INET6, .type = SOCK_STREAM },
		  SOL_TCP },
		{ &proto_inet6, { .family = PF_INET6, .type = SOCK_DGRAM },
		  SOL_UDP },
		{ &proto_inet6, { .family = PF_INET6, .type = SOCK_SEQPACKET },
		  SOL_SCTP },
		{ &proto_inet6, { .family = PF_INET6, .type = SOCK_RAW,
				  .protocol = IPPROTO_UDP },
		  SOL_RAW },
		{ &proto_inet6, { .family = PF_INET6, .type = SOCK_RAW,
				  .protocol = IPPROTO_ICMPV6 },
		  SOL_ICMPV6 },
	};
	struct socket_triplet ipv6_in_ipv4 = {
		.family = PF_INET, .type = SOCK_RAW, .protocol = IPPROTO_IPV6,
	};
	static unsigned char optval[INET_OPTVAL_LEN];
	unsigned int i, s;

	for (s = 0; s < ARRAY_SIZE(shapes); s++) {
		struct socket_triplet triplet = shapes[s].triplet;
		unsigned int own = 0;

		for (i = 0; i < INET_ROUNDS; i++) {
			struct sockopt so = { .optval = (unsigned long) optval };

			memset(optval, 0, sizeof(optval));
			shapes[s].proto->setsockopt(&so, &triplet);
			if (so.level == shapes[s].level)
				own++;
		}
		if (own < INET_ROUNDS / 8)
			BUG("inet: a socket is rarely drawn its protocol's options");
	}

	for (i = 0; i < INET_ROUNDS; i++) {
		struct sockopt so = { .optval = (unsigned long) optval };

		memset(optval, 0, sizeof(optval));
		proto_ipv4.setsockopt(&so, &ipv6_in_ipv4);
		if (so.level == SOL_ICMPV6)
			BUG("inet: an IPv4 socket is drawn an ICMPv6 option");
	}
}
