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
	void (*func)(struct socket_triplet *st);
};

static const struct socket_ptr socketptrs[] = {
	[AF_UNIX] = { .func = &unix_rand_socket },
	[AF_INET] = { .func = &inet_rand_socket },
	[AF_AX25] = { .func = &ax25_rand_socket },
	[AF_IPX] = { .func = &ipx_rand_socket },
#ifdef USE_APPLETALK
	[AF_APPLETALK] = { .func = &atalk_rand_socket },
#endif
	[AF_NETROM] = { .func = NULL },
	[AF_BRIDGE] = { .func = NULL },
	[AF_ATMPVC] = { .func = NULL },
	[AF_X25] = { .func = &x25_rand_socket },
#ifdef USE_IPV6
	[AF_INET6] = { .func = &inet6_rand_socket },
#endif
	[AF_ROSE] = { .func = NULL },
	[AF_DECnet] = { .func = &decnet_rand_socket },
	[AF_NETBEUI] = { .func = NULL },
	[AF_SECURITY] = { .func = NULL },
	[AF_KEY] = { .func = NULL },
	[AF_NETLINK] = { .func = &netlink_rand_socket },
	[AF_PACKET] = { .func = &packet_rand_socket },
	[AF_ASH] = { .func = NULL },
	[AF_ECONET] = { .func = NULL },	// DEAD
	[AF_ATMSVC] = { .func = NULL },
	[AF_RDS] = { .func = &rds_rand_socket },
	[AF_SNA] = { .func = NULL },
	[AF_IRDA] = { .func = &irda_rand_socket },
	[AF_PPPOX] = { .func = NULL },
	[AF_WANPIPE] = { .func = NULL },
	[AF_LLC] = { .func = &llc_rand_socket },
	[AF_IB] = { .func = NULL },
	[AF_MPLS] = { .func = NULL },
	[AF_CAN] = { .func = &can_rand_socket },
	[AF_TIPC] = { .func = &tipc_rand_socket },
	[AF_BLUETOOTH] = { .func = NULL },
	[AF_IUCV] = { .func = NULL },
	[AF_RXRPC] = { .func = NULL },
	[AF_ISDN] = { .func = NULL },
	[AF_PHONET] = { .func = NULL },
	[AF_IEEE802154] = { .func = NULL },
#ifdef USE_CAIF
	[AF_CAIF] = { .func = &caif_rand_socket },
#endif
	[AF_ALG] = { .func = NULL },
	[AF_NFC] = { .func = &nfc_rand_socket },
	[AF_VSOCK] = { .func = NULL },
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

	i = st->family;

	if (socketptrs[i].func != NULL) {
		socketptrs[i].func(st);
		return 0;
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
