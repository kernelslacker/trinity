/*
 * SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, char __user *, optval, int, optlen)
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <bits/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netipx/ipx.h>
#include <netatalk/at.h>
#include <netax25/ax25.h>
#include <netrose/rose.h>
#include <netrom/netrom.h>
#include <linux/tipc.h>
#include <linux/filter.h>
#include "trinity.h"
#include "sanitise.h"
#include "compat.h"
#include "shm.h"

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

void sanitise_setsockopt(int childno)
{
	int level;

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
	case SOL_SOCKET:
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

	case SOL_IP:
	case SOL_TCP:
	case SOL_UDP:
	case SOL_IPV6:
	case SOL_ICMPV6:
	case SOL_SCTP:
	case SOL_UDPLITE:
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
		shm->a3[childno] = rand() % 255;	/* random operation. */
	}
}

struct syscall syscall_setsockopt = {
	.name = "setsockopt",
	.num_args = 5,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "level",
	.arg3name = "optname",
	.arg3type = ARG_OP,
	.arg3list = {
		.num = 46,
		.values = { SO_DEBUG, SO_REUSEADDR, SO_TYPE, SO_ERROR,
			    SO_DONTROUTE, SO_BROADCAST, SO_SNDBUF, SO_RCVBUF,
			    SO_SNDBUFFORCE, SO_RCVBUFFORCE, SO_KEEPALIVE, SO_OOBINLINE,
			    SO_NO_CHECK, SO_PRIORITY, SO_LINGER, SO_BSDCOMPAT,
			    SO_PASSCRED, SO_PEERCRED, SO_RCVLOWAT, SO_SNDLOWAT,
			    SO_RCVTIMEO, SO_SNDTIMEO, SO_SECURITY_AUTHENTICATION, SO_SECURITY_ENCRYPTION_TRANSPORT,
			    SO_SECURITY_ENCRYPTION_NETWORK, SO_BINDTODEVICE, SO_ATTACH_FILTER, SO_DETACH_FILTER,
			    SO_PEERNAME, SO_TIMESTAMP, SO_ACCEPTCONN, SO_PEERSEC,
			    SO_PASSSEC, SO_TIMESTAMPNS, SO_MARK, SO_TIMESTAMPING,
			    SO_PROTOCOL, SO_DOMAIN, SO_RXQ_OVFL, SO_WIFI_STATUS,
			    SO_PEEK_OFF, SO_NOFCS },
	},
	.arg4name = "optval",
	.arg4type = ARG_ADDRESS,
	.arg5name = "optlen",
	.arg5type = ARG_LEN,
	.sanitise = sanitise_setsockopt,
};
