/*
 * SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, char __user *, optval, int, optlen)
 */

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include "arch.h"
#include "config.h"
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

struct sso_funcptr {
	void (*func)(struct sockopt *so);
};

static const struct sso_funcptr ssoptrs[] = {
	{ .func = &ip_setsockopt },
	{ .func = &socket_setsockopt },
	{ .func = &tcp_setsockopt },
	{ .func = &udp_setsockopt },
#ifdef USE_IPV6
	{ .func = &inet6_setsockopt },
#endif
#ifdef USE_IPV6
	{ .func = &icmpv6_setsockopt },
#endif
	{ .func = &sctp_setsockopt },
	{ .func = &udplite_setsockopt },
	{ .func = &raw_setsockopt },
	{ .func = &ipx_setsockopt },
	{ .func = &ax25_setsockopt },
#ifdef USE_APPLETALK
	{ .func = &atalk_setsockopt },
#endif
#ifdef USE_NETROM
	{ .func = &netrom_setsockopt },
#endif
#ifdef USE_ROSE
	{ .func = &rose_setsockopt },
#endif
	{ .func = &decnet_setsockopt },
	{ .func = &x25_setsockopt },
	{ .func = &packet_setsockopt },
	{ .func = &atm_setsockopt },
	{ .func = &aal_setsockopt },
	{ .func = &irda_setsockopt },
	{ .func = &netbeui_setsockopt },
	{ .func = &llc_setsockopt },
	{ .func = &dccp_setsockopt },
	{ .func = &netlink_setsockopt },
	{ .func = &tipc_setsockopt },
	{ .func = &rxrpc_setsockopt },
	{ .func = &pppol2tp_setsockopt },
	{ .func = &bluetooth_setsockopt },
	{ .func = &pnpipe_setsockopt },
	{ .func = &rds_setsockopt },
	{ .func = &iucv_setsockopt },
	{ .func = &caif_setsockopt },
	{ .func = &alg_setsockopt },
	{ .func = &nfc_setsockopt },
};

/*
 * Call a proto specific setsockopt routine from the table above.
 *
 * Called from random setsockopt() syscalls, and also during socket
 * creation on startup from sso_socket()
 *
 * TODO: pass in the proto, so we can match it to the right .func
 */
void do_setsockopt(struct sockopt *so)
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
		ssoptrs[rand() % ARRAY_SIZE(ssoptrs)].func(so);
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

	do_setsockopt(&so);

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
	.arg1type = ARG_FD,
	.arg2name = "level",
	.arg3name = "optname",
	.arg4name = "optval",
	.arg5name = "optlen",
	.sanitise = sanitise_setsockopt,
	.post = post_setsockopt,
	.flags = NEED_ALARM,
};
