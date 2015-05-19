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
#include <netax25/ax25.h>
#include "config.h"
#ifdef USE_APPLETALK
#include <netatalk/at.h>
#endif
#ifdef USE_NETROM
#include <netrom/netrom.h>
#endif
#ifdef USE_ROSE
#include <netrose/rose.h>
#endif
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
	unsigned int sol;
	void (*func)(struct sockopt *so);
};

static const struct ip_sso_funcptr ip_ssoptrs[] = {
	{ .proto = IPPROTO_IP, .sol = SOL_IP, .func = &ip_setsockopt },
	{ .proto = IPPROTO_ICMP, .func = NULL },
	{ .proto = IPPROTO_IGMP, .func = NULL },
	{ .proto = IPPROTO_IPIP, .func = NULL },
	{ .proto = IPPROTO_TCP, .sol = SOL_TCP, .func = &tcp_setsockopt },
	{ .proto = IPPROTO_EGP, .func = NULL },
	{ .proto = IPPROTO_PUP, .func = NULL },
	{ .proto = IPPROTO_UDP, .sol = SOL_UDP, .func = &udp_setsockopt },
	{ .proto = IPPROTO_IDP, .func = NULL },
	{ .proto = IPPROTO_TP, .func = NULL },
	{ .proto = IPPROTO_DCCP, .sol = SOL_DCCP, .func = &dccp_setsockopt },
#ifdef USE_IPV6
	{ .proto = IPPROTO_IPV6, .sol = SOL_ICMPV6, .func = &icmpv6_setsockopt },
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
	{ .proto = IPPROTO_SCTP, .sol = SOL_SCTP, .func = &sctp_setsockopt },
	{ .proto = IPPROTO_UDPLITE, .sol = SOL_UDPLITE, .func = &udplite_setsockopt },
	{ .proto = IPPROTO_RAW, .sol = SOL_RAW, .func = &raw_setsockopt },
};

struct sso_funcptr {
	unsigned int family;
	unsigned int sol;
	void (*func)(struct sockopt *so);
};

static const struct sso_funcptr ssoptrs[] = {
	{ .family = AF_UNIX, .func = NULL },
	{ .family = AF_INET, .func = NULL },	// special cased below.
	{ .family = AF_AX25, .sol = SOL_AX25, .func = &ax25_setsockopt },
	{ .family = AF_IPX, .sol = SOL_IPX, .func = &ipx_setsockopt },
#ifdef USE_APPLETALK
	{ .family = AF_APPLETALK, .sol = SOL_ATALK, .func = NULL },
#endif
#ifdef USE_NETROM
	{ .family = AF_NETROM, .sol = SOL_NETROM, .func = &netrom_setsockopt },
#endif
	{ .family = AF_BRIDGE, .func = NULL },
	{ .family = AF_ATMPVC, .sol = SOL_ATM, .func = &atm_setsockopt },
	{ .family = AF_X25, .sol = SOL_X25, .func = &x25_setsockopt },
#ifdef USE_IPV6
	{ .family = AF_INET6, .sol = SOL_IPV6, .func = &inet6_setsockopt },
#endif
#ifdef USE_ROSE
	{ .family = AF_ROSE, .sol = SOL_ROSE, .func = &rose_setsockopt },
#endif
	{ .family = AF_DECnet, .sol = SOL_DECNET, .func = &decnet_setsockopt },
	{ .family = AF_NETBEUI, .sol = SOL_NETBEUI, .func = NULL },
	{ .family = AF_SECURITY, .func = NULL },
	{ .family = AF_KEY, .func = NULL },
	{ .family = AF_NETLINK, .sol = SOL_NETLINK, .func = &netlink_setsockopt },
	{ .family = AF_PACKET, .sol = SOL_PACKET, .func = &packet_setsockopt },
	{ .family = AF_ASH, .func = NULL },
	{ .family = AF_ECONET, .func = NULL },
	{ .family = AF_ATMSVC, SOL_ATM, .func = &atm_setsockopt },
	{ .family = AF_RDS, .sol = SOL_RDS, .func = &rds_setsockopt },
	{ .family = AF_SNA, .func = NULL },
	{ .family = AF_IRDA, .sol = SOL_IRDA, .func = &irda_setsockopt },
	{ .family = AF_PPPOX, .sol = SOL_PPPOL2TP, .func = &pppol2tp_setsockopt },
	{ .family = AF_WANPIPE, .func = NULL },
	{ .family = AF_LLC, .sol = SOL_LLC, .func = &llc_setsockopt },
	{ .family = AF_IB, .func = NULL },
	{ .family = AF_MPLS, .func = NULL },
	{ .family = AF_CAN, .func = NULL },
	{ .family = AF_TIPC, .sol = SOL_TIPC, .func = &tipc_setsockopt },
	{ .family = AF_BLUETOOTH, .sol = SOL_BLUETOOTH, .func = &bluetooth_setsockopt },
	{ .family = AF_IUCV, .sol = SOL_IUCV, .func = &iucv_setsockopt },
	{ .family = AF_RXRPC, .sol = SOL_RXRPC, .func = &rxrpc_setsockopt },
	{ .family = AF_ISDN, .func = NULL },
	{ .family = AF_PHONET, .sol = SOL_PNPIPE, .func = NULL },
	{ .family = AF_IEEE802154, .func = NULL },
#ifdef USE_CAIF
	{ .family = AF_CAIF, .sol = SOL_CAIF, .func = &caif_setsockopt },
#endif
	{ .family = AF_ALG, .sol = SOL_ALG, .func = NULL },
	{ .family = AF_NFC, .sol = SOL_NFC, .func = NULL },
	{ .family = AF_VSOCK, .func = NULL },
};

/*
 * If we have a .len set, use it.
 * If not, pick some random size.
 */
unsigned int get_so_len(unsigned int len)
{
	if (len != 0)
		return len;

	if (RAND_BOOL())
		return sizeof(char);
	else
		return sizeof(int);
}

/*
 * We do this if for eg, we've ended up being passed
 * an fd that isn't a socket (ie, triplet==NULL).
 * It can also happen if we land on an sso func that
 * isn't implemented for a particular family yet.
 */
static void do_random_sso(struct sockopt *so)
{
	unsigned int i;

retry:
	switch (rand() % 4) {
	case 0:	/* do a random protocol, even if it doesn't match this socket. */
		i = rand() % ARRAY_SIZE(ssoptrs);
		if (ssoptrs[i].func != NULL) {
			so->level = ssoptrs[i].sol;
			ssoptrs[i].func(so);
		} else {
			goto retry;
		}
		break;

	case 1:	/* do a random IP protocol, even if it doesn't match this socket. */
		i = rand() % ARRAY_SIZE(ip_ssoptrs);
		if (ip_ssoptrs[i].func != NULL) {
			so->level = ip_ssoptrs[i].sol;
			ip_ssoptrs[i].func(so);
		} else {
			goto retry;
		}
		break;

	case 2:	/* Last resort: Generic socket options. */
		socket_setsockopt(so);
		break;

	case 3:	/* completely random operation. */
		so->level = rand();
		so->optname = RAND_BYTE();
		break;
	}
}

static void call_sso_ptr(struct sockopt *so, struct socket_triplet *triplet)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ssoptrs); i++) {
		if (ssoptrs[i].family == triplet->family) {
			if (ssoptrs[i].func != NULL) {
				so->level = ssoptrs[i].sol;
				ssoptrs[i].func(so);
				return;
			} else {	// unimplemented yet, or no sso for this family.
				do_random_sso(so);
				return;
			}
		}
	}
}

static void call_inet_sso_ptr(struct sockopt *so, struct socket_triplet *triplet)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ip_ssoptrs); i++) {
		if (ip_ssoptrs[i].proto == triplet->protocol) {
			if (ip_ssoptrs[i].func != NULL) {
				so->level = ip_ssoptrs[i].sol;
				ip_ssoptrs[i].func(so);
				return;
			} else {	// unimplemented yet, or no sso for this proto.
				do_random_sso(so);
				return;
			}
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
		do_random_sso(so);
	} else {
		if (triplet != NULL) {
			if (triplet->family == AF_INET) {
				call_inet_sso_ptr(so, triplet);
			} else {
				call_sso_ptr(so, triplet);
			}
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
