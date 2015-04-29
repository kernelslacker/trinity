/*
 * SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, char __user *, optval, int, optlen)
 */

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/tipc.h>
#include <netinet/udp.h>
#include <netipx/ipx.h>
#include "config.h"
#include "arch.h"
#include "log.h"
#include "maps.h"
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

struct ip_sso_funcptr {
	unsigned int proto;
	void (*func)(struct sockopt *so);
};

static const struct ip_sso_funcptr ip_ssoptrs[] = {
	{ .proto = IPPROTO_IP, .func = &ip_setsockopt },
	{ .proto = IPPROTO_ICMP, .func = NULL },
	{ .proto = IPPROTO_IGMP, .func = NULL },
	{ .proto = IPPROTO_IPIP, .func = NULL },
	{ .proto = IPPROTO_TCP, .func = &tcp_setsockopt },
	{ .proto = IPPROTO_EGP, .func = NULL },
	{ .proto = IPPROTO_PUP, .func = NULL },
	{ .proto = IPPROTO_UDP, .func = &udp_setsockopt },
	{ .proto = IPPROTO_IDP, .func = NULL },
	{ .proto = IPPROTO_TP, .func = NULL },
	{ .proto = IPPROTO_DCCP, .func = &dccp_setsockopt },
#ifdef USE_IPV6
	{ .proto = IPPROTO_IPV6, .func = &icmpv6_setsockopt },
#endif
	{ .proto = IPPROTO_RSVP, .func = NULL },
	{ .proto = IPPROTO_GRE, .func = NULL },
	{ .proto = IPPROTO_ESP, .func = NULL },
	{ .proto = IPPROTO_AH, .func = NULL },
	{ .proto = IPPROTO_MTP, .func = NULL },
	{ .proto = IPPROTO_BEETPH, .func = NULL },
	{ .proto = IPPROTO_ENCAP, .func = NULL },
	{ .proto = IPPROTO_PIM, .func = NULL },
	{ .proto = IPPROTO_COMP, .func = NULL },
	{ .proto = IPPROTO_SCTP, .func = &sctp_setsockopt },
	{ .proto = IPPROTO_UDPLITE, .func = &udplite_setsockopt },
	{ .proto = IPPROTO_RAW, .func = &raw_setsockopt },
};

static void ip_sso_demultiplexer(struct sockopt *so)
{
	//TODO: Later, be smarter, and look up the rest of the triplet.
	int randsso = rand() % ARRAY_SIZE(ip_ssoptrs);
	if (ip_ssoptrs[randsso].func != NULL)
		ip_ssoptrs[randsso].func(so);
}

struct sso_funcptr {
	unsigned int family;
	void (*func)(struct sockopt *so);
};

static const struct sso_funcptr ssoptrs[] = {
	{ .family = AF_UNIX, .func = NULL },
	{ .family = AF_INET, .func = &ip_sso_demultiplexer },
	{ .family = AF_AX25, .func = &ax25_setsockopt },
	{ .family = AF_IPX, .func = &ipx_setsockopt },
#ifdef USE_APPLETALK
	{ .family = AF_APPLETALK, .func = &atalk_setsockopt },
#endif
#ifdef USE_NETROM
	{ .family = AF_NETROM, .func = &netrom_setsockopt },
#endif
	{ .family = AF_BRIDGE, .func = NULL },
	{ .family = AF_ATMPVC, .func = NULL },
	{ .family = AF_X25, .func = &x25_setsockopt },
#ifdef USE_IPV6
	{ .family = AF_INET6, .func = &inet6_setsockopt },
#endif
#ifdef USE_ROSE
	{ .family = AF_ROSE, .func = &rose_setsockopt },
#endif
	{ .family = AF_DECnet, .func = &decnet_setsockopt },
	{ .family = AF_NETBEUI, .func = &netbeui_setsockopt },
	{ .family = AF_SECURITY, .func = NULL },
	{ .family = AF_KEY, .func = NULL },
	{ .family = AF_NETLINK, .func = &netlink_setsockopt },
	{ .family = AF_PACKET, .func = &packet_setsockopt },
	{ .family = AF_ASH, .func = NULL },
	{ .family = AF_ECONET, .func = NULL },
	{ .family = AF_ATMSVC, .func = NULL },
	{ .family = AF_RDS, .func = &rds_setsockopt },
	{ .family = AF_SNA, .func = NULL },
	{ .family = AF_IRDA, .func = &irda_setsockopt },
	{ .family = AF_PPPOX, .func = NULL },
	{ .family = AF_WANPIPE, .func = NULL },
	{ .family = AF_LLC, .func = &llc_setsockopt },
	{ .family = AF_IB, .func = NULL },
	{ .family = AF_MPLS, .func = NULL },
	{ .family = AF_CAN, .func = NULL },
	{ .family = AF_TIPC, .func = &tipc_setsockopt },
	{ .family = AF_BLUETOOTH, .func = &bluetooth_setsockopt },
	{ .family = AF_IUCV, .func = &iucv_setsockopt },
	{ .family = AF_RXRPC, .func = &rxrpc_setsockopt },
	{ .family = AF_ISDN, .func = NULL },
	{ .family = AF_PHONET, .func = NULL },
	{ .family = AF_IEEE802154, .func = NULL },
#ifdef USE_CAIF
	{ .family = AF_CAIF, .func = &caif_setsockopt },
#endif
	{ .family = AF_ALG, .func = &alg_setsockopt },
	{ .family = AF_NFC, .func = &nfc_setsockopt },
	{ .family = AF_VSOCK, .func = NULL },
};

//TODO: How shall we match these ?
//	{ .func = &atm_setsockopt },
//	{ .func = &aal_setsockopt },
//	{ .func = &pppol2tp_setsockopt },
//	{ .func = &pnpipe_setsockopt },

/*
 * We do this if for eg, we've ended up being passed
 * an fd that isn't a socket (ie, triplet==NULL).
 * It can also happen if we land on an sso func that
 * isn't implemented for a particular family yet.
 */
static void do_random_sso(struct sockopt *so)
{
	int i;

	i = rand() % ARRAY_SIZE(ssoptrs);

	if (ssoptrs[i].func == NULL) {
		socket_setsockopt(so);
		return;
	}

	ssoptrs[i].func(so);
}

static void call_sso_ptr(struct sockopt *so, struct socket_triplet *triplet)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ssoptrs); i++) {
		if (ssoptrs[i].family == triplet->family) {
			if (ssoptrs[i].func != NULL)
				ssoptrs[i].func(so);
			else    // unimplented yet, or no sso for this family.
				do_random_sso(so);
		}
	}
}

/*
 * Call a proto specific setsockopt routine from the table above.
 *
 * Called from random setsockopt() syscalls, and also during socket
 * creation on startup from sso_socket()
 *
 */
void do_setsockopt(struct sockopt *so, struct socket_triplet *triplet)
{
	/* get a page for the optval to live in.
	 * TODO: push this down into the per-proto .func calls
	 */
	so->optval = (unsigned long) zmalloc(page_size);

	// pick a size for optlen. At the minimum, we want an int (overridden below)
	if (RAND_BOOL())
		so->optlen = sizeof(int);
	else
		so->optlen = rand() % 256;

	if (ONE_IN(100)) {
		so->level = rand();
		so->optname = RAND_BYTE();	/* random operation. */
	} else {
		if (triplet != NULL) {
			call_sso_ptr(so, triplet);
		} else {
			// fd probably isn't a socket.
			do_random_sso(so);
		}
	}

	/*
	 * 10% of the time, mangle the options.
	 * This should catch new options we don't know about, and also maybe some missing bounds checks.
	 */
	if (ONE_IN(10))
		so->optname |= (1UL << (rand() % 32));

	/* optval should be nonzero to enable a boolean option, or zero if the option is to be disabled.
	 * Let's disable it half the time.
	 */
	if (RAND_BOOL()) {
		free((void *) so->optval);
		so->optval = 0;
	}
}

static void sanitise_setsockopt(struct syscallrecord *rec)
{
	struct sockopt so = { 0, 0, 0, 0 };
	struct socketinfo *si;
	struct socket_triplet *triplet = NULL;
	int fd;

	if (ONE_IN(1000)) {
		fd = get_random_fd();
	} else {
		si = (struct socketinfo *) rec->a1;
		fd = si->fd;
		triplet = &si->triplet;
	}

	rec->a1 = fd;

	do_setsockopt(&so, triplet);

	/* copy the generated values to the shm. */
	rec->a2 = so.level;
	rec->a3 = so.optname;
	rec->a4 = so.optval;
	rec->a5 = so.optlen;
}

static void post_setsockopt(struct syscallrecord *rec)
{
	freeptr(&rec->a4);
}

struct syscallentry syscall_setsockopt = {
	.name = "setsockopt",
	.num_args = 5,
	.arg1name = "fd",
	.arg1type = ARG_SOCKETINFO,
	.arg2name = "level",
	.arg3name = "optname",
	.arg4name = "optval",
	.arg5name = "optlen",
	.sanitise = sanitise_setsockopt,
	.post = post_setsockopt,
	.flags = NEED_ALARM,
};
