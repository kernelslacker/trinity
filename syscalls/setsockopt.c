/*
 * SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, char __user *, optval, int, optlen)
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "trinity.h"
#include "sanitise.h"
#include "compat.h"
#include "shm.h"
#include "syscalls/setsockopt.h"

void sanitise_setsockopt(int childno)
{
	int level;
	unsigned char val;

	shm->a4[childno] = (unsigned long) page_rand;
	shm->a5[childno] = sizeof(int);	// at the minimum, we want an int (overridden below)

	/* First we pick a level  */

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


	/* Now, use that level to determine which options to set. */

	switch (level) {
	case SOL_IP:
		val = rand() % NR_SOL_IP_OPTS;
		shm->a3[childno] = ip_opts[val];
		break;

	case SOL_SOCKET:
		val = rand() % NR_SOL_SOCKET_OPTS;
		shm->a3[childno] = socket_opts[val];

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
		val = rand() % NR_SOL_TCP_OPTS;
		shm->a3[childno] = tcp_opts[val];
		break;

	case SOL_UDP:
		val = rand() % NR_SOL_UDP_OPTS;
		shm->a3[childno] = udp_opts[val];

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
		val = rand() % NR_SOL_IPV6_OPTS;
		shm->a3[childno] = ipv6_opts[val];
		break;

	case SOL_ICMPV6:
		val = rand() % NR_SOL_ICMPV6_OPTS;
		shm->a3[childno] = icmpv6_opts[val];
		break;

	case SOL_SCTP:
		val = rand() % NR_SOL_SCTP_OPTS;
		shm->a3[childno] = sctp_opts[val];
		break;

	case SOL_UDPLITE:
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

	case SOL_RAW:
		shm->a3[childno] = ICMP_FILTER;	// that's all (for now?)
		break;

	case SOL_IPX:
		shm->a3[childno] = IPX_TYPE;
		break;

	case SOL_AX25:
		val = rand() % NR_SOL_AX25_OPTS;
		shm->a3[childno] = ax25_opts[val];
		break;

	case SOL_ATALK:	/* sock_no_setsockopt */
		break;

	case SOL_NETROM:
		val = rand() % NR_SOL_NETROM_OPTS;
		shm->a3[childno] = netrom_opts[val];
		break;

	case SOL_ROSE:
		val = rand() % NR_SOL_ROSE_OPTS;
		shm->a3[childno] = rose_opts[val];
		break;

	case SOL_DECNET:
		// TODO: set size correctly
		val = rand() % NR_SOL_DECNET_OPTS;
		shm->a3[childno] = decnet_opts[val];
		break;

	case SOL_X25:
		page_rand[0] = rand() % 2;	/* Just a bool */
		shm->a4[childno] = sizeof(int);
		break;

	case SOL_PACKET:
		val = rand() % NR_SOL_PACKET_OPTS;
		shm->a3[childno] = packet_opts[val];
		break;

	case SOL_ATM:
		val = rand() % NR_SOL_ATM_OPTS;
		shm->a3[childno] = atm_opts[val];
		break;

	case SOL_AAL:	/* no setsockopt */
		break;

	case SOL_IRDA:
		val = rand() % NR_SOL_IRDA_OPTS;
		shm->a3[childno] = irda_opts[val];
		break;

	case SOL_NETBEUI:	/* no setsockopt */
		break;

	case SOL_LLC:
		val = rand() % NR_SOL_LLC_OPTS;
		shm->a3[childno] = llc_opts[val];
		break;

	case SOL_DCCP:
		val = rand() % NR_SOL_DCCP_OPTS;
		shm->a3[childno] = dccp_opts[val];
		break;

	case SOL_NETLINK:
		val = rand() % NR_SOL_NETLINK_OPTS;
		shm->a3[childno] = netlink_opts[val];
		break;

	case SOL_TIPC:
		shm->a4[childno] = sizeof(__u32);
		val = rand() % NR_SOL_TIPC_OPTS;
		shm->a3[childno] = tipc_opts[val];
		break;

	case SOL_RXRPC:
		val = rand() % NR_SOL_RXRPC_OPTS;
		shm->a3[childno] = rxrpc_opts[val];
		break;

	case SOL_PPPOL2TP:
		shm->a4[childno] = sizeof(int);
		val = rand() % NR_SOL_PPPOL2TP_OPTS;
		shm->a3[childno] = pppol2tp_opts[val];
		break;

	case SOL_BLUETOOTH:
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

	case SOL_PNPIPE	/* no setsockopt */:
		break;

	case SOL_RDS:
		val = rand() % NR_SOL_RDS_OPTS;
		shm->a3[childno] = rds_opts[val];
		break;

	case SOL_IUCV:
		val = rand() % NR_SOL_IUCV_OPTS;
		shm->a3[childno] = iucv_opts[val];
		shm->a4[childno] = sizeof(int);
		break;

	case SOL_CAIF:
		val = rand() % NR_SOL_CAIF_OPTS;
		shm->a3[childno] = caif_opts[val];
		break;

	case SOL_ALG:	/* no setsockopt */
		break;


	default:
		shm->a3[childno] = (rand() % 0xff);	/* random operation. */
	}

	shm->a2[childno] = level;


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
	.flags = NEED_ALARM,
};
