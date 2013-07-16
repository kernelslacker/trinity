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

	case 7:	level = SOL_UDPLITE;
		shm->a2[childno] = level;
		val = rand() % NR_SOL_UDPLITE_OPTS;
		shm->a3[childno] = udplite_opts[val];

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

	case 8:	level = SOL_RAW;
		shm->a2[childno] = level;
		shm->a3[childno] = ICMP_FILTER;	// that's all (for now?)
		break;

	case 9:	level = SOL_IPX;
		shm->a2[childno] = level;
		shm->a3[childno] = IPX_TYPE;
		break;

	case 10: level = SOL_AX25;
		shm->a2[childno] = level;
		val = rand() % NR_SOL_AX25_OPTS;
		shm->a3[childno] = ax25_opts[val];
		break;

	case 11: level = SOL_ATALK;
		shm->a2[childno] = level;
		/* sock_no_setsockopt */
		break;

	case 12: level = SOL_NETROM;
		shm->a2[childno] = level;
		val = rand() % NR_SOL_NETROM_OPTS;
		shm->a3[childno] = netrom_opts[val];
		break;

	case 13: level = SOL_ROSE;
		shm->a2[childno] = level;
		val = rand() % NR_SOL_ROSE_OPTS;
		shm->a3[childno] = rose_opts[val];
		break;

	case 14: level = SOL_DECNET;
		shm->a2[childno] = level;
		// TODO: set size correctly
		val = rand() % NR_SOL_DECNET_OPTS;
		shm->a3[childno] = decnet_opts[val];
		break;

	case 15: level = SOL_X25;
		shm->a2[childno] = level;
		page_rand[0] = rand() % 2;	/* Just a bool */
		shm->a4[childno] = sizeof(int);
		break;

	case 16: level = SOL_PACKET;
		shm->a2[childno] = level;
		val = rand() % NR_SOL_PACKET_OPTS;
		shm->a3[childno] = packet_opts[val];

		/* Adjust length according to operation set. */
		switch (shm->a3[childno]) {
		case PACKET_VERSION:
			page_rand[0] = rand() % 3; /* tpacket versions 1/2/3 */
			break;
		case PACKET_TX_RING:
		case PACKET_RX_RING:
#ifdef TPACKET3_HDRLEN
			if (rand() % 3 == 0)
				shm->a5[childno] = sizeof(struct tpacket_req3);
			else
#endif
				shm->a5[childno] = sizeof(struct tpacket_req);
			break;
		default:
			break;
		}
		break;

	case 17: level = SOL_ATM;
		shm->a2[childno] = level;
		val = rand() % NR_SOL_ATM_OPTS;
		shm->a3[childno] = atm_opts[val];
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
