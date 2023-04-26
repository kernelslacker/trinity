/*
 * SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, char __user *, optval, int, optlen)
 */

#include <stdlib.h>
#include <linux/filter.h>
#include "arch.h"
#include "net.h"
#include "compat.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY

static const unsigned int socket_opts[] = {
	SO_DEBUG, SO_REUSEADDR, SO_TYPE, SO_ERROR,
	SO_DONTROUTE, SO_BROADCAST, SO_SNDBUF, SO_RCVBUF,
	SO_SNDBUFFORCE, SO_RCVBUFFORCE, SO_KEEPALIVE, SO_OOBINLINE,
	SO_NO_CHECK, SO_PRIORITY, SO_LINGER, SO_BSDCOMPAT,
	SO_REUSEPORT, SO_PASSCRED, SO_PEERCRED, SO_RCVLOWAT, SO_SNDLOWAT,
	SO_RCVTIMEO, SO_SNDTIMEO, SO_SECURITY_AUTHENTICATION, SO_SECURITY_ENCRYPTION_TRANSPORT,
	SO_SECURITY_ENCRYPTION_NETWORK, SO_BINDTODEVICE, SO_ATTACH_FILTER, SO_DETACH_FILTER,
	SO_PEERNAME, SO_TIMESTAMP, SO_ACCEPTCONN, SO_PEERSEC,
	SO_PASSSEC, SO_TIMESTAMPNS, SO_MARK, SO_TIMESTAMPING,
	SO_PROTOCOL, SO_DOMAIN, SO_RXQ_OVFL, SO_WIFI_STATUS,
	SO_PEEK_OFF, SO_NOFCS, SO_LOCK_FILTER, SO_SELECT_ERR_QUEUE,
	SO_BUSY_POLL, SO_MAX_PACING_RATE, SO_BPF_EXTENSIONS, SO_INCOMING_CPU,
	SO_ATTACH_BPF, SO_ATTACH_REUSEPORT_CBPF, SO_ATTACH_REUSEPORT_EBPF,
	SO_CNX_ADVICE, SCM_TIMESTAMPING_OPT_STATS, SO_MEMINFO, SO_INCOMING_NAPI_ID,
	SO_COOKIE, SCM_TIMESTAMPING_PKTINFO, SO_PEERGROUPS, SO_ZEROCOPY,
	SO_TXTIME, SO_BINDTOIFINDEX, SO_TIMESTAMP_NEW, SO_TIMESTAMPNS_NEW,
	SO_TIMESTAMPING_NEW, SO_RCVTIMEO_NEW, SO_SNDTIMEO_NEW,
	SO_DETACH_REUSEPORT_BPF, SO_PREFER_BUSY_POLL, SO_BUSY_POLL_BUDGET,
	SO_NETNS_COOKIE, SO_BUF_LOCK,
};

static void socket_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_SOCKET;

	so->optname = RAND_ARRAY(socket_opts);

	/* Adjust length according to operation set. */
	switch (so->optname) {

	case SO_LINGER:
		so->optlen = sizeof(struct linger);
		break;

	case SO_RCVTIMEO:
	case SO_SNDTIMEO:
		so->optlen = sizeof(struct timeval);
		break;

	case SO_ATTACH_FILTER: {
		unsigned long *optval = NULL, optlen = 0;

#ifdef USE_BPF
		bpf_gen_filter(&optval, &optlen);
#endif

		so->optval = (unsigned long) optval;
		so->optlen = optlen;
		break;
	}
	default:
		break;
	}
}
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
		i = rnd() % TRINITY_PF_MAX;
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

	/* Sometimes just do generic options */
	if (ONE_IN(10)) {
		socket_setsockopt(so, triplet);
		return;
	}

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

	si = (struct socketinfo *) rec->a1;
	if (si == NULL) {
		rec->a1 = get_random_fd();
		rec->a4 = (unsigned long) zmalloc(page_size);
		return;
	}

	if (ONE_IN(1000)) {
		fd = get_random_fd();
	} else {
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
