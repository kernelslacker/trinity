/*
 * SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, char __user *, optval, int, optlen)
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <bits/socket.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <netinet/udp.h>
#include <netipx/ipx.h>
#include <netatalk/at.h>
#include <netax25/ax25.h>
#include <netrose/rose.h>
#include <netrom/netrom.h>
#include <linux/tipc.h>
#include <linux/filter.h>
#include <linux/icmpv6.h>

#include "trinity.h"
#include "sanitise.h"
#include "compat.h"
#include "shm.h"

#define SOL_TCP		6
#define SOL_SCTP        132
#define SOL_UDPLITE     136
#define SOL_NETBEUI     267
#define SOL_LLC         268
#define SOL_DCCP        269
#define SOL_NETLINK     270
#define SOL_RXRPC       272
#define SOL_PPPOL2TP    273
#define SOL_BLUETOOTH   274
#define SOL_PNPIPE      275
#define SOL_RDS         276
#define SOL_IUCV        277
#define SOL_CAIF        278
#define SOL_ALG         279

#define NR_SOL_IP_OPTS 19
static int ip_opts[NR_SOL_IP_OPTS] = { IP_TOS, IP_TTL, IP_HDRINCL, IP_OPTIONS,
	IP_ROUTER_ALERT, IP_RECVOPTS, IP_RETOPTS, IP_PKTINFO,
	IP_PKTOPTIONS, IP_MTU_DISCOVER, IP_RECVERR, IP_RECVTTL,
	IP_RECVTOS, IP_MTU, IP_FREEBIND, IP_IPSEC_POLICY,
	IP_XFRM_POLICY, IP_PASSSEC, IP_TRANSPARENT };

#define NR_SOL_SOCKET_OPTS 46
static int socket_opts[NR_SOL_SOCKET_OPTS] = { SO_DEBUG, SO_REUSEADDR, SO_TYPE, SO_ERROR,
	SO_DONTROUTE, SO_BROADCAST, SO_SNDBUF, SO_RCVBUF,
	SO_SNDBUFFORCE, SO_RCVBUFFORCE, SO_KEEPALIVE, SO_OOBINLINE,
	SO_NO_CHECK, SO_PRIORITY, SO_LINGER, SO_BSDCOMPAT,
	SO_PASSCRED, SO_PEERCRED, SO_RCVLOWAT, SO_SNDLOWAT,
	SO_RCVTIMEO, SO_SNDTIMEO, SO_SECURITY_AUTHENTICATION, SO_SECURITY_ENCRYPTION_TRANSPORT,
	SO_SECURITY_ENCRYPTION_NETWORK, SO_BINDTODEVICE, SO_ATTACH_FILTER, SO_DETACH_FILTER,
	SO_PEERNAME, SO_TIMESTAMP, SO_ACCEPTCONN, SO_PEERSEC,
	SO_PASSSEC, SO_TIMESTAMPNS, SO_MARK, SO_TIMESTAMPING,
	SO_PROTOCOL, SO_DOMAIN, SO_RXQ_OVFL, SO_WIFI_STATUS,
	SO_PEEK_OFF, SO_NOFCS };

#define NR_SOL_TCP_OPTS 23
static int tcp_opts[NR_SOL_TCP_OPTS] = { TCP_NODELAY, TCP_MAXSEG, TCP_CORK, TCP_KEEPIDLE,
	TCP_KEEPINTVL, TCP_KEEPCNT, TCP_SYNCNT, TCP_LINGER2,
	TCP_DEFER_ACCEPT, TCP_WINDOW_CLAMP, TCP_INFO, TCP_QUICKACK,
	TCP_CONGESTION, TCP_MD5SIG, TCP_COOKIE_TRANSACTIONS, TCP_THIN_LINEAR_TIMEOUTS,
	TCP_THIN_DUPACK, TCP_USER_TIMEOUT, TCP_REPAIR, TCP_REPAIR_QUEUE,
	TCP_QUEUE_SEQ, TCP_REPAIR_OPTIONS, TCP_FASTOPEN};

#define NR_SOL_UDP_OPTS 2
static int udp_opts[NR_SOL_UDP_OPTS] = { UDP_CORK, UDP_ENCAP };

#define NR_SOL_UDPLITE_OPTS 4
static int udplite_opts[NR_SOL_UDPLITE_OPTS] = { UDP_CORK, UDP_ENCAP, UDPLITE_SEND_CSCOV, UDPLITE_RECV_CSCOV };

#define NR_SOL_IPV6_OPTS 24
static int ipv6_opts[NR_SOL_IPV6_OPTS] = {
	IPV6_ADDRFORM, IPV6_2292PKTINFO, IPV6_2292HOPOPTS, IPV6_2292DSTOPTS,
	IPV6_2292RTHDR, IPV6_2292PKTOPTIONS, IPV6_CHECKSUM, IPV6_2292HOPLIMIT,
	IPV6_NEXTHOP, IPV6_AUTHHDR, IPV6_FLOWINFO, IPV6_UNICAST_HOPS,
	IPV6_MULTICAST_IF, IPV6_MULTICAST_HOPS, IPV6_MULTICAST_LOOP, IPV6_ADD_MEMBERSHIP,
	IPV6_DROP_MEMBERSHIP, IPV6_ROUTER_ALERT, IPV6_MTU_DISCOVER, IPV6_MTU,
	IPV6_RECVERR, IPV6_V6ONLY, IPV6_JOIN_ANYCAST, IPV6_LEAVE_ANYCAST };

#define NR_SOL_ICMPV6_OPTS 1
static int icmpv6_opts[NR_SOL_ICMPV6_OPTS] = { ICMPV6_FILTER };

void sanitise_setsockopt(int childno)
{
	int level;
	unsigned char bit;

	shm->a4[childno] = (unsigned long) page_rand;
	shm->a5[childno] = sizeof(int);	// at the minimum, we want an int (overridden below)

	switch (rand() % 33) {
	case 0:	level = SOL_IP;	break;
	case 1:	level = SOL_SOCKET; break;
	case 2:	level = SOL_TCP; break;
	case 3:	level = SOL_UDP; break;
	case 4:	level = SOL_IPV6; break;
	case 5:	level = SOL_ICMPV6; break;
	case 6:	level = SOL_SCTP; break;
	case 7:	level = SOL_UDPLITE; break;
	case 8:	level = SOL_RAW; break;
	case 9:	level = SOL_IPX; break;
	case 10: level = SOL_AX25; break;
	case 11: level = SOL_ATALK; break;
	case 12: level = SOL_NETROM; break;
	case 13: level = SOL_ROSE; break;
	case 14: level = SOL_DECNET; break;
	case 15: level = SOL_X25; break;
	case 16: level = SOL_PACKET; break;
	case 17: level = SOL_ATM; break;
	case 18: level = SOL_AAL; break;
	case 19: level = SOL_IRDA; break;
	case 20: level = SOL_NETBEUI; break;
	case 21: level = SOL_LLC; break;
	case 22: level = SOL_DCCP; break;
	case 23: level = SOL_NETLINK; break;
	case 24: level = SOL_TIPC; break;
	case 25: level = SOL_RXRPC; break;
	case 26: level = SOL_PPPOL2TP; break;
	case 27: level = SOL_BLUETOOTH; break;
	case 28: level = SOL_PNPIPE; break;
	case 29: level = SOL_RDS; break;
	case 30: level = SOL_IUCV; break;
	case 31: level = SOL_CAIF; break;
	case 32: level = SOL_ALG; break;
	default:
		level = rand();
		break;
	}

	shm->a2[childno] = level;

	switch (level) {
	case SOL_IP:
		bit = rand() % NR_SOL_IP_OPTS;
		shm->a3[childno] = 1 << (ip_opts[bit]);
		break;

	case SOL_SOCKET:
		bit = rand() % NR_SOL_SOCKET_OPTS;
		shm->a3[childno] = 1 << (socket_opts[bit]);

		/* Adjust length according to operation set. */
		switch (shm->a3[childno]) {
		case SO_LINGER:	shm->a5[childno] = sizeof(struct linger);
			break;
		case SO_RCVTIMEO:
		case SO_SNDTIMEO:
			shm->a5[childno] = sizeof(struct timeval);
			break;
		case SO_ATTACH_FILTER:
			shm->a5[childno] = sizeof(struct sock_fprog);
			break;
		default:
			break;
		}
		break;

	case SOL_TCP:
		bit = rand() % NR_SOL_TCP_OPTS;
		shm->a3[childno] = 1 << (tcp_opts[bit]);
		break;

	case SOL_UDP:
		bit = rand() % NR_SOL_UDP_OPTS;
		shm->a3[childno] = 1 << (udp_opts[bit]);

		switch (shm->a3[childno]) {
		case UDP_CORK:
			break;
		case UDP_ENCAP:
			page_rand[0] = (rand() % 3) + 1;	// Encapsulation types.
			break;
		default:
			break;
		}
		break;

	case SOL_IPV6:
		bit = rand() % NR_SOL_IPV6_OPTS;
		shm->a3[childno] = 1 << (ipv6_opts[bit]);
		break;

	case SOL_ICMPV6:
		bit = rand() % NR_SOL_ICMPV6_OPTS;
		shm->a3[childno] = 1 << (icmpv6_opts[bit]);
		break;

	case SOL_UDPLITE:
		bit = rand() % NR_SOL_UDPLITE_OPTS;
		shm->a3[childno] = 1 << (udplite_opts[bit]);

		switch (shm->a3[childno]) {
		case UDP_CORK:
			break;
		case UDP_ENCAP:
			page_rand[0] = (rand() % 3) + 1;	// Encapsulation types.
			break;
		case UDPLITE_SEND_CSCOV:
			break;
		case UDPLITE_RECV_CSCOV:
			break;
		default:
			break;
		}

		break;

	case SOL_SCTP:

	case SOL_RAW:
	case SOL_IPX:
	case SOL_AX25:
	case SOL_ATALK:
	case SOL_NETROM:
	case SOL_ROSE:
	case SOL_DECNET:
	case SOL_X25:
	case SOL_PACKET:
	case SOL_ATM:
	case SOL_AAL:
	case SOL_IRDA:
	case SOL_NETBEUI:
	case SOL_LLC:
	case SOL_DCCP:
	case SOL_NETLINK:
	case SOL_TIPC:
	case SOL_RXRPC:
	case SOL_PPPOL2TP:
	case SOL_BLUETOOTH:
	case SOL_PNPIPE:
	case SOL_RDS:
	case SOL_IUCV:
	case SOL_CAIF:
	case SOL_ALG:

	default:
		shm->a3[childno] = 1 << (rand() % 16);	/* random operation. */
	}

	/* optval should be nonzero to enable a boolean option, or zero if the option is to be disabled.
	 * Let's disable it half the time.
	 */
	if (rand() % 2)
		shm->a4[childno] = 0;

	shm->a4[childno] = sizeof(int);
}

struct syscall syscall_setsockopt = {
	.name = "setsockopt",
	.num_args = 5,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "level",
	.arg3name = "optname",
	.arg4name = "optval",
	.arg4type = ARG_ADDRESS,
	.arg5name = "optlen",
	.sanitise = sanitise_setsockopt,
};
