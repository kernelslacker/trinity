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
#include "syscalls/setsockopt.h"

static void sanitise_setsockopt(int childno)
{
	int level;
	unsigned char val;
	struct sockopt so;

	shm->a4[childno] = (unsigned long) page_rand;
	// pick a size for optlen. At the minimum, we want an int (overridden below)
	if (rand_bool())
		shm->a5[childno] = sizeof(int);
	else
		shm->a5[childno] = rand() % 256;

	/* First we pick a level  */

	switch (rand() % 35) {

	case 0:	ip_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 1:	socket_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 2:	tcp_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 3:	udp_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 4:	inet6_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 5:	icmpv6_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 6:	sctp_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 7:	udplite_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 8:	raw_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 9:	ipx_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 10: ax25_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 11: atalk_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 12:
		netrom_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 13:
		rose_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 14:
		decnet_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 15:
		x25_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 16:
		packet_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 17:
		atm_setsockopt(&so);
		shm->a2[childno] = so.level;
		shm->a3[childno] = so.optname;
		shm->a4[childno] = so.optval;
		shm->a5[childno] = so.optlen;
		break;

	case 18: level = SOL_AAL;
		shm->a2[childno] = level;
		/* no setsockopt */
		break;

	case 19: level = SOL_IRDA;
		shm->a2[childno] = level;
		val = rand() % NR_SOL_IRDA_OPTS;
		shm->a3[childno] = irda_opts[val];
		break;

	case 20: level = SOL_NETBEUI;
		shm->a2[childno] = level;
		/* no setsockopt */
		break;

	case 21: level = SOL_LLC;
		shm->a2[childno] = level;
		val = rand() % NR_SOL_LLC_OPTS;
		shm->a3[childno] = llc_opts[val];
		break;

	case 22: level = SOL_DCCP;
		shm->a2[childno] = level;
		val = rand() % NR_SOL_DCCP_OPTS;
		shm->a3[childno] = dccp_opts[val];
		break;

	case 23: level = SOL_NETLINK;
		shm->a2[childno] = level;
		val = rand() % NR_SOL_NETLINK_OPTS;
		shm->a3[childno] = netlink_opts[val];
		break;

	case 24: level = SOL_TIPC;
		shm->a2[childno] = level;
		shm->a4[childno] = sizeof(__u32);
		val = rand() % NR_SOL_TIPC_OPTS;
		shm->a3[childno] = tipc_opts[val];
		break;

	case 25: level = SOL_RXRPC;
		shm->a2[childno] = level;
		val = rand() % NR_SOL_RXRPC_OPTS;
		shm->a3[childno] = rxrpc_opts[val];
		break;

	case 26: level = SOL_PPPOL2TP;
		shm->a2[childno] = level;
		shm->a4[childno] = sizeof(int);
		val = rand() % NR_SOL_PPPOL2TP_OPTS;
		shm->a3[childno] = pppol2tp_opts[val];
		break;

	case 27: level = SOL_BLUETOOTH;
		switch(rand() % 5) {
		case 0: level = SOL_HCI; break;
		case 1: level = SOL_L2CAP; break;
		case 2: level = SOL_SCO; break;
		case 3: level = SOL_RFCOMM; break;
		case 4:	/* leave level unchanged */
			;;
		default:
			break;
		}
		shm->a2[childno] = level;

		switch (level) {
		case SOL_HCI:
			val = rand() % NR_SOL_BLUETOOTH_HCI_OPTS;
			shm->a3[childno] = bluetooth_hci_opts[val];
			break;

		case SOL_L2CAP:
			val = rand() % NR_SOL_BLUETOOTH_L2CAP_OPTS;
			shm->a3[childno] = bluetooth_l2cap_opts[val];
			break;

		case SOL_SCO:	/* no options currently */
			break;

		case SOL_RFCOMM:
			val = rand() % NR_SOL_BLUETOOTH_RFCOMM_OPTS;
			shm->a3[childno] = bluetooth_rfcomm_opts[val];
			break;

		case SOL_BLUETOOTH:
			val = rand() % NR_SOL_BLUETOOTH_OPTS;
			shm->a3[childno] = bluetooth_opts[val];
			break;

		default: break;
		}
		break;

	case 28: level = SOL_PNPIPE;
		shm->a2[childno] = level;
		/* no setsockopt */
		break;

	case 29: level = SOL_RDS;
		shm->a2[childno] = level;
#ifdef USE_RDS
		val = rand() % NR_SOL_RDS_OPTS;
		shm->a3[childno] = rds_opts[val];
#endif
		break;


	case 30: level = SOL_IUCV;
		shm->a2[childno] = level;
		val = rand() % NR_SOL_IUCV_OPTS;
		shm->a3[childno] = iucv_opts[val];
		shm->a4[childno] = sizeof(int);
		break;

	case 31: level = SOL_CAIF;
#ifdef USE_CAIF
		shm->a2[childno] = level;

		val = rand() % NR_SOL_CAIF_OPTS;
		shm->a3[childno] = caif_opts[val];
#endif
		break;

	case 32: level = SOL_ALG;
		/* no setsockopt */
		break;

	case 33: level = SOL_NFC;
		//TODO.
		break;

	default:
		level = rand();
		shm->a2[childno] = level;
		shm->a3[childno] = (rand() % 0x100);	/* random operation. */
		break;
	}

	/*
	 * 10% of the time, mangle the options.
	 * This should catch new options we don't know about, and also maybe some missing bounds checks.
	 */
	if ((rand() % 100) < 10)
		shm->a3[childno] |= (1 << (rand() % 32));


	/* optval should be nonzero to enable a boolean option, or zero if the option is to be disabled.
	 * Let's disable it half the time.
	 */
	if (rand() % 2)
		shm->a4[childno] = 0;
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
