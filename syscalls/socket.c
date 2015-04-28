/*
 * SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
 */
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "config.h"
#include "debug.h"
#include "log.h"
#include "net.h"
#include "params.h"
#include "domains.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

struct socket_ptr {
	unsigned int family;
	void (*func)(struct socket_triplet *st);
};
static const struct socket_ptr socketptrs[] = {
	{ .family = AF_UNIX, .func = &unix_rand_socket },
	{ .family = AF_INET, .func = &inet_rand_socket },
	{ .family = AF_AX25, .func = &ax25_rand_socket },
	{ .family = AF_IPX, .func = &ipx_rand_socket },
#ifdef USE_APPLETALK
	{ .family = AF_APPLETALK, .func = &atalk_rand_socket },
#endif
//TODO	{ .family = AF_NETROM, .func = &netrom_rand_socket },
//TODO	{ .family = AF_BRIDGE, .func = &bridge_rand_socket },
//TODO	{ .family = AF_ATMPVC, .func = &atmpvc_rand_socket },
	{ .family = AF_X25, .func = &x25_rand_socket },
#ifdef USE_IPV6
	{ .family = AF_INET6, .func = &inet6_rand_socket },
#endif
//TODO	{ .family = AF_ROSE, .func = &rose_rand_socket },
	{ .family = AF_DECnet, .func = &decnet_rand_socket },
//TODO	{ .family = AF_NETBEUI, .func = &netbeui_rand_socket },
//TODO	{ .family = AF_SECURITY, .func = &security_rand_socket },
//TODO	{ .family = AF_KEY, .func = &key_rand_socket },
	{ .family = AF_NETLINK, .func = &netlink_rand_socket },
	{ .family = AF_PACKET, .func = &packet_rand_socket },
//TODO	{ .family = AF_ASH, .func = &ash_rand_socket },
//DEAD	{ .family = AF_ECONET, .func = &econet_rand_socket },
//TODO	{ .family = AF_ATMSVC, .func = &atmsvc_rand_socket },
	{ .family = AF_RDS, .func = &rds_rand_socket },
//TODO	{ .family = AF_SNA, .func = &sna_rand_socket },
	{ .family = AF_IRDA, .func = &irda_rand_socket },
//TODO	{ .family = AF_PPPOX, .func = &pppox_rand_socket },
//TODO	{ .family = AF_WANPIPE, .func = &wanpipe_rand_socket },
	{ .family = AF_LLC, .func = &llc_rand_socket },
//TODO	{ .family = AF_IB, .func = &ib_rand_socket },
//TODO	{ .family = AF_MPLS, .func = &mpls_rand_socket },
	{ .family = AF_CAN, .func = &can_rand_socket },
	{ .family = AF_TIPC, .func = &tipc_rand_socket },
//TODO	{ .family = AF_BLUETOOTH, .func = &bluetooth_rand_socket },
//TODO	{ .family = AF_IUCV, .func = &iucv_rand_socket },
//TODO	{ .family = AF_RXRPC, .func = &rxrpc_rand_socket },
//TODO	{ .family = AF_ISDN, .func = &isdn_rand_socket },
//TODO	{ .family = AF_PHONET, .func = &phonet_rand_socket },
//TODO	{ .family = AF_IEEE802154, .func = &ieee802154_rand_socket },
#ifdef USE_CAIF
	{ .family = AF_CAIF, .func = &caif_rand_socket },
#endif
//TODO	{ .family = AF_ALG, .func = &alg_rand_socket },
	{ .family = AF_NFC, .func = &nfc_rand_socket },
//TODO	{ .family = AF_VSOCK, .func = &vsock_rand_socket },
};

void rand_proto_type(struct socket_triplet *st)
{
	int n;

	/*
	 * One special moment on packet sockets. They
	 * can be created with SOCK_PACKET, so if
	 * PF_PACKET is disabled, choose some other type.
	 */

	st->protocol = rand() % PROTO_MAX;

	if (st->family == PF_INET && no_domains[PF_PACKET])
		n = 5;
	else
		n = 6;

	switch (rand() % n) {
	case 0:	st->type = SOCK_DGRAM;	break;
	case 1:	st->type = SOCK_STREAM;	break;
	case 2:	st->type = SOCK_SEQPACKET;	break;
	case 3:	st->type = SOCK_RAW;	break;
	case 4:	st->type = SOCK_RDM;	break;
	/*
	 * Make sure it's last one.
	 */
	case 5:	st->type = SOCK_PACKET;	break;
	default: break;
	}
}

/* note: also called from generate_sockets() */
int sanitise_socket_triplet(struct socket_triplet *st)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(socketptrs); i++) {
		if (socketptrs[i].family == st->family) {
			socketptrs[i].func(st);
			return 0;
		}
	}

	/* Couldn't find func, fall back to random. */
	return -1;
}

/* note: also called from sanitise_socketcall() */
void gen_socket_args(struct socket_triplet *st)
{
	if (do_specific_domain == TRUE)
		st->family = specific_domain;

	else {
		st->family = rand() % TRINITY_PF_MAX;

		/*
		 * If we get a disabled family, try to find
		 * first next allowed.
		 */
		BUG_ON(st->family >= ARRAY_SIZE(no_domains));
		if (no_domains[st->family]) {
			st->family = find_next_enabled_domain(st->family);
			if (st->family == -1u) {
				outputerr("No available socket family found\n");
				exit(EXIT_FAILURE);
			}
		}
	}

	/* sometimes, still gen rand crap */
	if (ONE_IN(100)) {
		rand_proto_type(st);
		goto done;
	}

	/* otherwise.. sanitise based on the family. */
	if (sanitise_socket_triplet(st) < 0)
		rand_proto_type(st);	/* Couldn't find func, fall back to random. */


done:
	if (ONE_IN(4))
		st->type |= SOCK_CLOEXEC;
	if (ONE_IN(4))
		st->type |= SOCK_NONBLOCK;
}


static void sanitise_socket(struct syscallrecord *rec)
{
	struct socket_triplet st = { .family = 0, .type = 0, .protocol = 0 };

	gen_socket_args(&st);

	rec->a1 = st.family;
	rec->a2 = st.type;
	rec->a3 = st.protocol;
}

struct syscallentry syscall_socket = {
	.name = "socket",
	.num_args = 3,
	.arg1name = "family",
	.arg2name = "type",
	.arg3name = "protocol",
	.sanitise = sanitise_socket,
};
