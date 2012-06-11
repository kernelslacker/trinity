/*
 * SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
 */

#include <stdlib.h>
#include <linux/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "trinity.h"
#include "sanitise.h"
#include "compat.h"

/* note: also called from generate_sockets() & sanitise_socketcall() */
void sanitise_socket(
        unsigned long *family,
        unsigned long *type,
        unsigned long *protocol,
        __unused__ unsigned long *a4,
        __unused__ unsigned long *a5,
        __unused__ unsigned long *a6)
{
	*family = rand() % PF_MAX;
	*type = rand() % TYPE_MAX;
	*protocol = rand() % PROTO_MAX;

	switch (*family) {

	case AF_X25:
		*type = SOCK_SEQPACKET;
		break;

	case AF_INET:
		switch (rand() % 3) {
		case 0:	*type = SOCK_STREAM;	// TCP
			if ((rand() % 2) == 0)
				*protocol = 0;
			else
				*protocol = IPPROTO_TCP;
			break;
		case 1:	*type = SOCK_DGRAM;	// UDP
			if ((rand() % 2) == 0)
				*protocol = 0;
			else
				*protocol = IPPROTO_UDP;
			break;
		case 2:	*type = SOCK_RAW;
			break;
		default:break;
		}
		break;


	case AF_INET6:
		switch (rand() % 3) {
		case 0:	*type = SOCK_STREAM;	// TCP
			*protocol = 0;
			break;
		case 1:	*type = SOCK_DGRAM;	// UDP
			if ((rand() % 2) == 0)
				*protocol = 0;
			else
				*protocol = IPPROTO_UDP;
			break;
		case 2:	*type = SOCK_RAW;
			break;
		default:break;
		}
		break;

	case AF_NETLINK:
		switch (rand() % 2) {
		case 0:	*type = SOCK_RAW;
			break;
		case 1:	*type = SOCK_DGRAM;
		default:break;
		}
		*protocol = rand() % 22;
		break;

	case AF_UNIX:
		switch (rand() % 3) {
		case 0:	*type = SOCK_STREAM;
			break;
		case 1:	*type = SOCK_DGRAM;
			break;
		case 2:	*type = SOCK_SEQPACKET;
			break;
		default:break;
		}
		break;

	case AF_APPLETALK:
		switch (rand() % 2) {
		case 0:	*type = SOCK_DGRAM;
			*protocol = 0;
			break;
		case 1:	*type = SOCK_RAW;
			break;
		default:break;
		}
		break;

	case AF_NFC:
		switch (rand() % 2) {
		case 0:	*protocol = NFC_SOCKPROTO_LLCP;
			switch (rand() % 2) {
				*type = SOCK_DGRAM;
				break;
			case 1:	*type = SOCK_STREAM;
				break;
			default: break;
			}
			break;

		case 1:	*protocol = NFC_SOCKPROTO_RAW;
			*type = SOCK_SEQPACKET;
			break;
		default:
			BUG("impossible.");
		}
		break;

	default:
		switch (rand() % 6) {
		case 0:	*type = SOCK_DGRAM;	break;
		case 1:	*type = SOCK_STREAM;	break;
		case 2:	*type = SOCK_SEQPACKET;	break;
		case 3:	*type = SOCK_RAW;	break;
		case 4:	*type = SOCK_RDM;	break;
		case 5:	*type = SOCK_PACKET;	break;
		default: break;
		}

		break;
	}

	if ((rand() % 100) < 25)
		*type |= SOCK_CLOEXEC;
	if ((rand() % 100) < 25)
		*type |= SOCK_NONBLOCK;
}

struct syscall syscall_socket = {
	.name = "socket",
	.num_args = 3,
	.arg1name = "family",
	.arg2name = "type",
	.arg3name = "protocol",
	.sanitise = sanitise_socket,
};
