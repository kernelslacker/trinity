/*
 * SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, char __user *, optval, int, optlen)
 */

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "linux/filter.h"
#include "trinity.h"
#include "sanitise.h"
#include "shm.h"

void sanitise_setsockopt(int childno)
{
	if (rand() % 2)
		shm->a2[childno] = SOL_SOCKET;
	else
		shm->a2[childno] = rand() % 256;

	shm->a4[childno] = (unsigned long) page_rand;

	shm->a5[childno] = sizeof(int);	// at the minimum, we want an int.

	/* Adjust length according to operation set. */
	if (shm->a2[childno] == SOL_SOCKET) {
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
