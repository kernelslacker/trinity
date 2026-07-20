/*
 * accept-unblocker + pipe-waker connector helpers.
 *
 * See include/unblocker.h for the design contract.  Both helpers are
 * loopback-only, bounded-work, and fire-and-forget; neither must be
 * able to wedge the caller.
 */

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <string.h>

#include "net.h"
#include "objects.h"
#include "shm.h"
#include "socketinfo.h"
#include "unblocker.h"

#include "kernel/socket.h"
/*
 * Loopback predicate.  Returns true for any addr the connector is
 * willing to fire at without rewriting:
 *   - AF_INET in 127.0.0.0/8
 *   - AF_INET6 ::1
 *   - AF_UNIX (pathname or abstract; trinity inherently local)
 *
 * AF_INET wildcards (0.0.0.0) and AF_INET6 wildcards (::) are NOT
 * loopback in this predicate — the caller rewrites those to loopback
 * explicitly before re-checking.  Multicast / broadcast / external
 * addresses fall through to false and skip the fire.
 */
static bool addr_is_loopback(const struct sockaddr *sa, socklen_t len)
{
	if (sa == NULL)
		return false;

	switch (sa->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *sin = (const struct sockaddr_in *) sa;
		uint32_t h;

		if (len < (socklen_t) sizeof(*sin))
			return false;
		h = ntohl(sin->sin_addr.s_addr);
		return (h >> 24) == 127;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) sa;

		if (len < (socklen_t) sizeof(*sin6))
			return false;
		return IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) != 0;
	}
	case AF_UNIX:
		return true;
	default:
		return false;
	}
}

/*
 * Rewrite an INET/INET6 wildcard or external addr to loopback in
 * place, preserving the port.  Returns true on success (addr is now
 * safe to connect to), false if the family has no loopback or the
 * rewrite is not applicable.
 *
 * A listener bound to 0.0.0.0:N accepts loopback connects to
 * 127.0.0.1:N, so this is both safe and effective.  A listener bound
 * to a real NIC addr also accepts loopback because the local stack
 * still routes loopback to the listener's port; rewriting to
 * loopback here is the conservative path that guarantees no external
 * traffic leaves the box even if the original cached addr was a
 * real public IP from a fuzzed bind().
 */
static bool rewrite_to_loopback(struct sockaddr *sa, socklen_t len)
{
	if (sa == NULL)
		return false;

	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *) sa;

		if (len < (socklen_t) sizeof(*sin))
			return false;
		sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		return true;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
		struct in6_addr loop6 = IN6ADDR_LOOPBACK_INIT;

		if (len < (socklen_t) sizeof(*sin6))
			return false;
		sin6->sin6_addr = loop6;
		return true;
	}
	case AF_UNIX:
		/* AF_UNIX is local by construction; no rewrite. */
		return true;
	default:
		return false;
	}
}

/*
 * Probe whether fd is in LISTEN and capture its local addr.  Used
 * when the caller's cached socketinfo is unpopulated (the common case
 * — most pooled sockets transition to LISTEN inside socket_child_ops
 * after add_socket() publishes the read-only slot).
 */
static bool probe_listener(int fd, struct sockaddr_storage *out,
			   socklen_t *out_len)
{
	int v = 0;
	socklen_t vlen = sizeof(v);
	socklen_t alen = sizeof(*out);

	if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &v, &vlen) != 0)
		return false;
	if (v != 1) {
		errno = 0;
		return false;
	}
	if (getsockname(fd, (struct sockaddr *) out, &alen) != 0)
		return false;
	if (alen == 0 || alen > sizeof(*out)) {
		errno = 0;
		return false;
	}
	*out_len = alen;
	return true;
}

/*
 * Pick the family of the socket() the connector opens to fire at the
 * captured addr.  Must match the addr's family — connecting an
 * AF_INET socket to an AF_INET6 addr (or vice-versa) is -EAFNOSUPPORT
 * and wastes the syscall.
 */
static int family_for_addr(const struct sockaddr *sa)
{
	if (sa == NULL)
		return -1;
	switch (sa->sa_family) {
	case AF_INET:
	case AF_INET6:
	case AF_UNIX:
		return sa->sa_family;
	default:
		return -1;
	}
}

void accept_unblocker_fire(int fd, const struct socketinfo *si)
{
	struct sockaddr_storage ss;
	socklen_t slen;
	struct sockaddr *sa;
	int family, cfd, r;

	if (fd < 0)
		return;

	/*
	 * Source the target addr.  Cache hit (rare — needs SO_ACCEPTCONN
	 * == 1 at add_socket() time) saves the two-syscall probe; cache
	 * miss falls through to lazy probe of the live fd.
	 */
	if (si != NULL && si->is_listener &&
	    si->local_len > 0 &&
	    si->local_len <= sizeof(ss)) {
		memcpy(&ss, &si->local, si->local_len);
		slen = si->local_len;
	} else if (!probe_listener(fd, &ss, &slen)) {
		/* Not in LISTEN, or probe failed.  Not an error — most
		 * pool fds are not listeners.  Bump only on the genuine
		 * error case (probe returned an unexpected errno). */
		if (errno != 0 && errno != EINVAL && errno != ENOTSOCK)
			__atomic_add_fetch(&shm->stats.accept_unblocker.probe_failed,
					   1, __ATOMIC_RELAXED);
		return;
	}

	sa = (struct sockaddr *) &ss;

	/*
	 * Loopback-only enforcement.  Hot path is "addr is already
	 * loopback, pass through".  Wildcard/external addrs get
	 * rewritten to loopback (port preserved); rewrite failure or
	 * a family we don't have a loopback for is a hard skip with a
	 * counter bump.
	 */
	if (!addr_is_loopback(sa, slen)) {
		if (!rewrite_to_loopback(sa, slen) ||
		    !addr_is_loopback(sa, slen)) {
			__atomic_add_fetch(&shm->stats.accept_unblocker.loopback_only_skipped,
					   1, __ATOMIC_RELAXED);
			return;
		}
	}

	family = family_for_addr(sa);
	if (family < 0) {
		__atomic_add_fetch(&shm->stats.accept_unblocker.loopback_only_skipped,
				   1, __ATOMIC_RELAXED);
		return;
	}

	/*
	 * Throwaway connector socket.  SOCK_NONBLOCK so connect() can
	 * never wedge us (returns EINPROGRESS once the SYN is queued).
	 * SOCK_CLOEXEC so a concurrent fork in the same child never
	 * inherits this fd.  We do not publish cfd to the obj pool —
	 * it is a private throwaway and is closed before returning.
	 */
	cfd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (cfd < 0) {
		__atomic_add_fetch(&shm->stats.accept_unblocker.probe_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	r = connect(cfd, sa, slen);
	if (r == 0 || (r < 0 && errno == EINPROGRESS)) {
		__atomic_add_fetch(&shm->stats.accept_unblocker.connects_fired,
				   1, __ATOMIC_RELAXED);
	} else {
		/* ECONNREFUSED / ENOENT / EADDRNOTAVAIL on a stale or
		 * dead listener is benign — the listener is gone, the
		 * accept-side has nothing to prime against, move on.
		 * Other errnos are unexpected and worth counting. */
		if (errno != ECONNREFUSED && errno != ENOENT &&
		    errno != EADDRNOTAVAIL && errno != ECONNRESET)
			__atomic_add_fetch(&shm->stats.accept_unblocker.probe_failed,
					   1, __ATOMIC_RELAXED);
	}

	close(cfd);
}

void pipe_waker_poke_one(void)
{
	const unsigned int max_picks = 8;
	unsigned int i;

	if (objects_empty(OBJ_FD_PIPE) == true) {
		__atomic_add_fetch(&shm->stats.pipe_waker.no_target,
				   1, __ATOMIC_RELAXED);
		return;
	}

	for (i = 0; i < max_picks; i++) {
		struct object *obj;
		int fd;
		ssize_t w;
		const char one = 0;
		int flags, restored;

		obj = get_random_object(OBJ_FD_PIPE, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_PIPE))
			continue;

		/* Only writer ends — writing to a reader fd would
		 * either fail or, worse, succeed in surprising ways. */
		if (obj->pipeobj.reader)
			continue;

		fd = obj->pipeobj.fd;
		if (fd < 0)
			continue;

		/*
		 * Ensure non-blocking write so a full pipe (any
		 * concurrent reader stalled / draining slowly) returns
		 * EAGAIN instead of parking the waker.  Restore the
		 * original flags before returning — other consumers of
		 * this fd in the pool may depend on the pipe's blocking
		 * mode.
		 */
		flags = fcntl(fd, F_GETFL, 0);
		if (flags == -1)
			continue;
		if (!(flags & O_NONBLOCK)) {
			if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
				continue;
			restored = flags;
		} else {
			restored = -1;
		}

		w = write(fd, &one, 1);
		if (w == 1)
			__atomic_add_fetch(&shm->stats.pipe_waker.bytes_written,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.pipe_waker.write_failed,
					   1, __ATOMIC_RELAXED);

		if (restored != -1)
			(void) fcntl(fd, F_SETFL, restored);
		return;
	}

	__atomic_add_fetch(&shm->stats.pipe_waker.no_target,
			   1, __ATOMIC_RELAXED);
}
