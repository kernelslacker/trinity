/*
 * SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
 */
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/irda.h>
#include <linux/dn.h>
#include <linux/netlink.h>
#include "compat.h"
#include "log.h"
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "config.h"
#include "params.h"

/* note: also called from generate_sockets() & sanitise_socketcall() */
void sanitise_socket(int childno)
{
	unsigned long family, type, protocol;
	struct proto_type pt;

	if (do_specific_proto == TRUE)
		family = specific_proto;
	else
		family = rand() % TRINITY_PF_MAX;

	type = rand() % TYPE_MAX;
	protocol = rand() % PROTO_MAX;

	switch (family) {

	case AF_APPLETALK:
		appletalk_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;

	case AF_AX25:
		ax25_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;

#ifdef USE_CAIF
	case AF_CAIF:
		caif_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;
#endif

	case AF_CAN:
		can_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;

	case AF_DECnet:
		decnet_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;

	case AF_INET:
		inet_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;

	case AF_INET6:
		inet6_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;

	case AF_IPX:
		ipx_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;

	case AF_IRDA:
		irda_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;

	case AF_LLC:
		llc_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;

	//TODO;
/*	case AF_IB:
		break;
*/
	case AF_NETLINK:
		netlink_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;

	case AF_NFC:
		nfc_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;

	case AF_PACKET:
		packet_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;

	case AF_PHONET:
		phonet_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;

	case AF_RDS:
		rds_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;

	case AF_TIPC:
		tipc_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;

	case AF_UNIX:
		unix_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;

	case AF_X25:
		x25_rand_socket(&pt);
		type = pt.type;
		protocol = pt.protocol;
		break;


	default:
		switch (rand() % 6) {
		case 0:	type = SOCK_DGRAM;	break;
		case 1:	type = SOCK_STREAM;	break;
		case 2:	type = SOCK_SEQPACKET;	break;
		case 3:	type = SOCK_RAW;	break;
		case 4:	type = SOCK_RDM;	break;
		case 5:	type = SOCK_PACKET;	break;
		default: break;
		}

		break;
	}

	if ((rand() % 100) < 25)
		type |= SOCK_CLOEXEC;
	if ((rand() % 100) < 25)
		type |= SOCK_NONBLOCK;

	shm->a1[childno] = family;
	shm->a2[childno] = type;
	shm->a3[childno] = protocol;
}

struct syscall syscall_socket = {
	.name = "socket",
	.num_args = 3,
	.arg1name = "family",
	.arg2name = "type",
	.arg3name = "protocol",
	.sanitise = sanitise_socket,
};
