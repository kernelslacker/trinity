#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <stdlib.h>
#include "sanitise.h"
#include "compat.h"
#include "net.h"
#include "maps.h"
#include "config.h"
#include "params.h"	// do_specific_proto

void generate_sockaddr(unsigned long *addr, unsigned long *addrlen, int pf)
{
	/* If we want sockets of a specific type, we'll want sockaddrs that match. */
	if (do_specific_proto == TRUE)
		pf = specific_proto;

	/* If we got no hint passed down, pick a random proto. */
	if (pf == -1)
		pf = rand() % TRINITY_PF_MAX;

	switch (pf) {

	case PF_UNSPEC:
		//TODO
		break;

	case PF_UNIX:
		unix_gen_sockaddr(addr, addrlen);
		break;

	case PF_INET:
		ipv4_gen_sockaddr(addr, addrlen);
		break;

	case PF_AX25:
		ax25_gen_sockaddr(addr, addrlen);
		break;

	case PF_IPX:
		ipx_gen_sockaddr(addr, addrlen);
		break;

	case PF_APPLETALK:
		atalk_gen_sockaddr(addr, addrlen);
		break;

	case PF_NETROM:
		//TODO
		break;

	case PF_BRIDGE:
		//TODO
		break;

	case PF_ATMPVC:
		atmpvc_gen_sockaddr(addr, addrlen);
		break;

	case PF_X25:
		x25_gen_sockaddr(addr, addrlen);
		break;

	case PF_INET6:
		ipv6_gen_sockaddr(addr, addrlen);
		break;

	case PF_ROSE:
		rose_gen_sockaddr(addr, addrlen);
		break;

	case PF_DECnet:
		decnet_gen_sockaddr(addr, addrlen);
		break;

	case PF_NETBEUI:
		llc_gen_sockaddr(addr, addrlen);
		break;

	case PF_SECURITY:
		//TODO
		break;

	case PF_KEY:
		break;

	case PF_NETLINK:
		netlink_gen_sockaddr(addr, addrlen);
		break;

	case PF_PACKET:
		packet_gen_sockaddr(addr, addrlen);
		break;

	case PF_ASH:
		//TODO
		break;

	case PF_ECONET:
		econet_gen_sockaddr(addr, addrlen);
		break;

	case PF_ATMSVC:
		atmsvc_gen_sockaddr(addr, addrlen);
		break;

	case PF_RDS:
		//TODO
		break;

	case PF_SNA:
		//TODO
		break;

	case PF_IRDA:
		irda_gen_sockaddr(addr, addrlen);
		break;

	case PF_PPPOX:
		pppox_gen_sockaddr(addr, addrlen);
		break;

	case PF_WANPIPE:
		//TODO
		break;

	case PF_LLC:
		llc_gen_sockaddr(addr, addrlen);
		break;

	case PF_CAN:
		can_gen_sockaddr(addr, addrlen);
		break;

	case PF_TIPC:
		tipc_gen_sockaddr(addr, addrlen);
		break;

	case PF_BLUETOOTH:
		//TODO
		break;

	case PF_IUCV:
		//TODO
		break;

	case PF_RXRPC:
		//TODO
		break;

	case PF_ISDN:
		//TODO
		break;

	case PF_PHONET:
		phonet_gen_sockaddr(addr, addrlen);
		break;

	case PF_IEEE802154:
		//TODO
		break;

#ifdef USE_CAIF
	case PF_CAIF:
		caif_gen_sockaddr(addr, addrlen);
		break;
#endif

#ifdef USE_IF_ALG
	case PF_ALG:
		alg_gen_sockaddr(addr, addrlen);
		break;
#endif

	case PF_NFC:
		nfc_gen_sockaddr(addr, addrlen);
		break;

	case PF_VSOCK:
		//TODO
		break;

	default:
		break;
	}
}
