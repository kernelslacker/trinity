/*
 * SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, char __user *, optval, int, optlen)
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include "sanitise.h"
#include "compat.h"
#include "maps.h"
#include "shm.h"
#include "net.h"
#include "config.h"
#include "random.h"

static void sanitise_setsockopt(int childno)
{
	int level;
	struct sockopt so;

	so.optval = (unsigned long) page_rand;
	// pick a size for optlen. At the minimum, we want an int (overridden below)
	if (rand_bool())
		so.optlen = sizeof(int);
	else
		so.optlen = rand() % 256;

	/* First we pick a level  */

	switch (rand() % 35) {

	case 0:	ip_setsockopt(&so);
		break;

	case 1:	socket_setsockopt(&so);
		break;

	case 2:	tcp_setsockopt(&so);
		break;

	case 3:	udp_setsockopt(&so);
		break;

	case 4:	inet6_setsockopt(&so);
		break;

	case 5:	icmpv6_setsockopt(&so);
		break;

	case 6:	sctp_setsockopt(&so);
		break;

	case 7:	udplite_setsockopt(&so);
		break;

	case 8:	raw_setsockopt(&so);
		break;

	case 9:	ipx_setsockopt(&so);
		break;

	case 10: ax25_setsockopt(&so);
		break;

	case 11: atalk_setsockopt(&so);
		break;

	case 12:
		netrom_setsockopt(&so);
		break;

	case 13:
		rose_setsockopt(&so);
		break;

	case 14:
		decnet_setsockopt(&so);
		break;

	case 15:
		x25_setsockopt(&so);
		break;

	case 16:
		packet_setsockopt(&so);
		break;

	case 17:
		atm_setsockopt(&so);
		break;

	case 18:
		aal_setsockopt(&so);
		break;

	case 19:
		irda_setsockopt(&so);
		break;

	case 20:
		netbeui_setsockopt(&so);
		break;

	case 21:
		llc_setsockopt(&so);
		break;

	case 22:
		dccp_setsockopt(&so);
		break;

	case 23:
		netlink_setsockopt(&so);
		break;

	case 24:
		tipc_setsockopt(&so);
		break;

	case 25:
		rxrpc_setsockopt(&so);
		break;

	case 26:
		pppol2tp_setsockopt(&so);
		break;

	case 27:
		bluetooth_setsockopt(&so);
		break;

	case 28:
		pnpipe_setsockopt(&so);
		break;

	case 29:
		rds_setsockopt(&so);
		break;

	case 30:
		iucv_setsockopt(&so);
		break;

	case 31:
		caif_setsockopt(&so);
		break;

	case 32:
		alg_setsockopt(&so);
		break;

	case 33:
		nfc_setsockopt(&so);
		break;

	default:
		level = rand();
		so.level = level;
		so.optname = (rand() % 0x100);	/* random operation. */
		break;
	}


	/*
	 * 10% of the time, mangle the options.
	 * This should catch new options we don't know about, and also maybe some missing bounds checks.
	 */
	if ((rand() % 100) < 10)
		so.optname |= (1 << (rand() % 32));


	/* optval should be nonzero to enable a boolean option, or zero if the option is to be disabled.
	 * Let's disable it half the time.
	 */
	if (rand() % 2)
		so.optval = 0;


	/* copy the generated values to the shm. */
	shm->a2[childno] = so.level;
	shm->a3[childno] = so.optname;
	shm->a4[childno] = so.optval;
	shm->a5[childno] = so.optlen;
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
	.flags = NEED_ALARM,
};
