/*
 * obscure_af_churn - systematic abuse-pattern walker over every active
 * AF_* family.
 *
 * Per-family childops target a specific bug class on a specific family;
 * an abuse shape that surfaces a bug in family X only reaches family Y
 * after a human notices the pattern is structural and writes a second
 * childop.  This walker generalises the abuse over every family that
 * already passed the runtime viability checks in fds/sockets.c, so a
 * new bug-shape lands on every reachable family in one place.
 *
 * Per invocation: pick one viable family from net_protocols[] (skipping
 * no_domains[] and proto-NULL slots), draw a known-good (family, type,
 * protocol) triplet from that family's valid_triplets, then run all six
 * abuse patterns in sequence.  Each pattern owns its own short-lived
 * socket -- open, abuse, close -- so a failure in one pattern cannot
 * contaminate the next.
 *
 * Abuse patterns:
 *
 *   AP_SENDMSG_NO_BIND       socket() then sendmsg() with no prior bind.
 *                            Per-family send paths that assume bind has
 *                            run will walk a half-initialised socket.
 *   AP_BIND_THEN_SENDMSG     baseline canonical sequence; success-oracle
 *                            for the family on this kernel build.
 *   AP_CONNECT_NO_LISTEN     connect() to a sockaddr fabricated by
 *                            proto->gen_sockaddr with no peer bound.
 *                            Exercises the connect error-cleanup path.
 *   AP_IOCTL_ROTATION        a small set of generic socket ioctls
 *                            (FIONREAD, FIONBIO, SIOCATMARK, SIOCGSTAMP,
 *                            TIOCOUTQ, SIOCGPGRP).  Hits the generic
 *                            ioctl dispatcher's per-family hooks.
 *   AP_SETSOCKOPT_ZERO_LEN   setsockopt with optlen=0 on SOL_SOCKET or
 *                            IPPROTO_TCP -- the boundary several
 *                            implementations forget to bound-check
 *                            before issuing copy_from_user.
 *   AP_CLOSE_VIA_DUP         dup the fd, close the original, then op on
 *                            the dup.  Standard UAF-on-recently-freed-
 *                            socket shape.
 *
 * Counters per pattern:
 *   pattern_runs                always +1 per attempt.
 *   pattern_kernel_rejected     syscall returned <0 (expected steady
 *                               state for the ill-formed patterns).
 *   pattern_unexpected_success  syscall returned >=0 where it was
 *                               constructed to fail; bug-flag worth a
 *                               human look.  AP_BIND_THEN_SENDMSG is
 *                               canonical-success and its success count
 *                               is normal traffic.
 *
 * Per-iteration cost: 6 patterns x (1 socket + 1-3 syscalls + 1 close)
 * ~ 30 syscalls.  child.c arms alarm(1) per invocation and that bounds
 * any blocking syscall regardless of which pattern is in flight.
 *
 * Per-family viability is read directly from no_domains[] and
 * net_protocols[].proto->{nr_triplets,valid_triplets}; this op never
 * mutates either.  fds/sockets.c::probe_unsupported_pf_families and
 * auto_disable_empty_pf_pools have already run by the time the first
 * child enters the dispatch loop, so iterating pf in [0, TRINITY_PF_MAX)
 * with a no_domains skip yields only families that produced at least
 * one usable socket at startup.
 *
 * DORMANT in dormant_op_disabled[].  Smoke-test before fleet enable.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <linux/sockios.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>

#include "child.h"
#include "deferred-free.h"
#include "net.h"
#include "params.h"		/* no_domains[] */
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/socket.h"
#ifndef SIOCGSTAMP
# ifdef SIOCGSTAMP_OLD
#  define SIOCGSTAMP	SIOCGSTAMP_OLD
# else
#  define SIOCGSTAMP	0x8906
# endif
#endif

#define VIABLE_PICK_ATTEMPTS	16

enum abuse_pattern {
	AP_SENDMSG_NO_BIND = 0,
	AP_BIND_THEN_SENDMSG,
	AP_CONNECT_NO_LISTEN,
	AP_IOCTL_ROTATION,
	AP_SETSOCKOPT_ZERO_LEN,
	AP_CLOSE_VIA_DUP,
	NR_AP,
};

/*
 * Generic SIOC* / FION* requests that exist on enough families to be
 * worth rotating through here.  Per-family-specific requests live in
 * the families' own grammar entries; the point of this rotation is the
 * generic-ioctl-dispatcher path, not exotic per-family ones.
 */
static const unsigned long generic_ioctls[] = {
	FIONREAD,
	FIONBIO,
	SIOCATMARK,
	SIOCGSTAMP,
	TIOCOUTQ,
	SIOCGPGRP,
};

static int pick_viable_family(struct socket_triplet *out)
{
	const struct netproto *proto;
	unsigned int attempts;
	unsigned int pf;

	for (attempts = 0; attempts < VIABLE_PICK_ATTEMPTS; attempts++) {
		pf = rnd_modulo_u32(TRINITY_PF_MAX);
		if (no_domains[pf])
			continue;

		proto = net_protocols[pf].proto;
		if (proto == NULL)
			continue;
		if (proto->valid_triplets == NULL || proto->nr_triplets == 0)
			continue;

		*out = proto->valid_triplets[rnd_modulo_u32(proto->nr_triplets)];
		return (int)pf;
	}

	return -1;
}

static void bump_run(enum abuse_pattern ap)
{
	__atomic_add_fetch(&shm->stats.obscure_af_churn_pattern_runs[ap], 1,
			   __ATOMIC_RELAXED);
}

static void bump_rejected(enum abuse_pattern ap)
{
	__atomic_add_fetch(
		&shm->stats.obscure_af_churn_pattern_kernel_rejected[ap], 1,
		__ATOMIC_RELAXED);
}

static void bump_unexpected_success(enum abuse_pattern ap)
{
	__atomic_add_fetch(
		&shm->stats.obscure_af_churn_pattern_unexpected_success[ap], 1,
		__ATOMIC_RELAXED);
}

static int open_one(const struct socket_triplet *t)
{
	return socket(t->family, t->type, t->protocol);
}

static void run_sendmsg_no_bind(const struct socket_triplet *t)
{
	unsigned char buf[64];
	struct iovec iov;
	struct msghdr msg;
	int fd;
	ssize_t r;

	bump_run(AP_SENDMSG_NO_BIND);

	fd = open_one(t);
	if (fd < 0)
		return;

	generate_rand_bytes(buf, sizeof(buf));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	r = sendmsg(fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (r < 0)
		bump_rejected(AP_SENDMSG_NO_BIND);
	else
		bump_unexpected_success(AP_SENDMSG_NO_BIND);

	close(fd);
}

static void run_bind_then_sendmsg(const struct socket_triplet *t)
{
	const struct netproto *proto;
	struct sockaddr *sa = NULL;
	socklen_t salen = 0;
	unsigned char buf[64];
	struct iovec iov;
	struct msghdr msg;
	int fd;
	ssize_t r;

	bump_run(AP_BIND_THEN_SENDMSG);

	proto = net_protocols[t->family].proto;
	if (proto == NULL || proto->gen_sockaddr == NULL)
		return;

	fd = open_one(t);
	if (fd < 0)
		return;

	proto->gen_sockaddr((struct socket_triplet *) t, &sa, &salen);
	if (sa != NULL) {
		if (bind(fd, sa, salen) < 0) {
			/* Bind failures are expected for many type/proto
			 * combinations even with a coherent sockaddr;
			 * treat as kernel-rejected for symmetry. */
			bump_rejected(AP_BIND_THEN_SENDMSG);
			tracked_free_now(sa);
			close(fd);
			return;
		}
		tracked_free_now(sa);
	}

	generate_rand_bytes(buf, sizeof(buf));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	r = sendmsg(fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (r < 0)
		bump_rejected(AP_BIND_THEN_SENDMSG);
	/* Success here is the canonical-good outcome -- not a bug flag. */

	close(fd);
}

static void run_connect_no_listen(const struct socket_triplet *t)
{
	const struct netproto *proto;
	struct sockaddr *sa = NULL;
	socklen_t salen = 0;
	int fd;
	int r;

	/*
	 * connect() on a SOCK_DGRAM socket merely sets the default peer;
	 * there is no handshake, so it returns 0 even with no listener.
	 * Counting that as bump_unexpected_success would drown real
	 * bug-flag signal in predictable per-iteration noise for every
	 * UDP/DCCP/SCTP triplet.
	 */
	if (t->type == SOCK_DGRAM)
		return;

	bump_run(AP_CONNECT_NO_LISTEN);

	proto = net_protocols[t->family].proto;
	if (proto == NULL || proto->gen_sockaddr == NULL)
		return;

	fd = open_one(t);
	if (fd < 0)
		return;

	proto->gen_sockaddr((struct socket_triplet *) t, &sa, &salen);
	if (sa == NULL) {
		close(fd);
		return;
	}

	(void) fcntl(fd, F_SETFL, O_NONBLOCK);
	r = connect(fd, sa, salen);
	if (r < 0 && errno != EINPROGRESS)
		bump_rejected(AP_CONNECT_NO_LISTEN);
	else
		bump_unexpected_success(AP_CONNECT_NO_LISTEN);

	tracked_free_now(sa);
	close(fd);
}

static void run_ioctl_rotation(const struct socket_triplet *t)
{
	unsigned long req;
	int val = 0;
	int fd;
	int r;

	bump_run(AP_IOCTL_ROTATION);

	fd = open_one(t);
	if (fd < 0)
		return;

	req = generic_ioctls[rnd_modulo_u32(ARRAY_SIZE(generic_ioctls))];
	r = ioctl(fd, req, &val);
	if (r < 0)
		bump_rejected(AP_IOCTL_ROTATION);
	/* Success on a generic ioctl is fine; not a bug flag. */

	close(fd);
}

static void run_setsockopt_zero_len(const struct socket_triplet *t)
{
	int level;
	int optname;
	int val = 0;
	int fd;
	int r;

	bump_run(AP_SETSOCKOPT_ZERO_LEN);

	fd = open_one(t);
	if (fd < 0)
		return;

	if (RAND_BOOL()) {
		level = SOL_SOCKET;
		optname = SO_REUSEADDR;
	} else {
		level = IPPROTO_TCP;
		optname = TCP_NODELAY;
	}

	r = setsockopt(fd, level, optname, &val, 0);
	if (r < 0)
		bump_rejected(AP_SETSOCKOPT_ZERO_LEN);
	else
		bump_unexpected_success(AP_SETSOCKOPT_ZERO_LEN);

	close(fd);
}

static void run_close_via_dup(const struct socket_triplet *t)
{
	unsigned char buf[16];
	int fd;
	int dup_fd;
	ssize_t r;

	bump_run(AP_CLOSE_VIA_DUP);

	fd = open_one(t);
	if (fd < 0)
		return;

	dup_fd = dup(fd);
	if (dup_fd < 0) {
		close(fd);
		return;
	}

	close(fd);

	r = recv(dup_fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (r < 0)
		bump_rejected(AP_CLOSE_VIA_DUP);
	else
		bump_unexpected_success(AP_CLOSE_VIA_DUP);

	close(dup_fd);
}

bool obscure_af_churn(struct childdata *child)
{
	struct socket_triplet triplet = { 0, 0, 0 };
	int pf;

	__atomic_add_fetch(&shm->stats.obscure_af_churn_runs, 1,
			   __ATOMIC_RELAXED);

	pf = pick_viable_family(&triplet);
	if (pf < 0) {
		__atomic_add_fetch(&shm->stats.obscure_af_churn_no_viable_pf,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	run_sendmsg_no_bind(&triplet);
	run_bind_then_sendmsg(&triplet);
	run_connect_no_listen(&triplet);
	run_ioctl_rotation(&triplet);
	run_setsockopt_zero_len(&triplet);
	run_close_via_dup(&triplet);

	return true;
}
