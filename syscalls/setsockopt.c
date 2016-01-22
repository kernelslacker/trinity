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

/*
 * If we have a .len set, use it.
 * If not, pick some random size.
 */
unsigned int sockoptlen(unsigned int len)
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
static void do_random_sso(struct sockopt *so, struct socket_triplet *triplet)
{
	unsigned int i;
	const struct netproto *proto;

retry:
	switch (rnd() % 4) {
	case 0:	/* do a random protocol, even if it doesn't match this socket. */
		i = rnd() % PF_MAX;
		proto = net_protocols[i].proto;
		if (proto != NULL) {
			if (proto->setsockopt != NULL) {
				proto->setsockopt(so, triplet);
				return;
			}
		}
		goto retry;

	case 1:	/* do a random IP protocol, even if it doesn't match this socket. */
		proto = net_protocols[PF_INET].proto;
		proto->setsockopt(so, triplet);
		break;

	case 2:	/* Last resort: Generic socket options. */
		socket_setsockopt(so, triplet);
		break;

	case 3:	/* completely random operation. */
		so->level = rnd();
		so->optname = RAND_BYTE();
		break;
	}
}

static void call_sso_ptr(struct sockopt *so, struct socket_triplet *triplet)
{
	const struct netproto *proto;

	proto = net_protocols[triplet->family].proto;

	if (proto != NULL) {
		if (proto->setsockopt != NULL) {
			proto->setsockopt(so, triplet);
			return;
		}
	}

	do_random_sso(so, triplet);
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
	so->optname = 0;

	/* get a page for the optval to live in.
	 * TODO: push this down into the per-proto .func calls
	 */
	so->optval = (unsigned long) zmalloc(page_size);

	/* At the minimum, we want len to be a char or int.
	 * It gets (overridden below in the per-proto sso->func, so this
	 * is just for the unannotated protocols.
	 */
	so->optlen = sockoptlen(0);

	if (ONE_IN(100)) {
		do_random_sso(so, triplet);
	} else {
		if (triplet != NULL) {
			call_sso_ptr(so, triplet);
		} else {
			// fd probably isn't a socket.
			do_random_sso(so, triplet);
		}
	}

	/*
	 * 10% of the time, mangle the options.
	 * This should catch new options we don't know about, and also maybe some missing bounds checks.
	 */
	if (ONE_IN(10))
		so->optname |= (1UL << (rnd() % 32));

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
