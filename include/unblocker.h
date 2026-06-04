#pragma once

#include "socketinfo.h"

/*
 * accept-unblocker: fire a fire-and-forget loopback connect() at a
 * pooled listening socket.  The point is to push at least one entry
 * into the listener's accept queue so a concurrent accept() in
 * another child never parks in inet_csk_accept's wait loop.
 *
 * Targeting:
 *   - The cached (is_listener, local) on the passed socketinfo is
 *     used when populated.  Otherwise the live fd is lazy-probed via
 *     getsockopt(SO_ACCEPTCONN)+getsockname().
 *   - Caller may pass si == NULL with a bare fd; the lazy probe path
 *     handles that.
 *
 * Safety:
 *   - Loopback-only: refuses to fire at any addr outside 127.0.0.0/8,
 *     ::1, or AF_UNIX.  For AF_INET/AF_INET6 listeners bound to a
 *     wildcard/external addr the destination is rewritten to loopback
 *     keeping the port.
 *   - Connector socket is SOCK_NONBLOCK|SOCK_CLOEXEC, connect returns
 *     EINPROGRESS instantly, fd is closed immediately.  No wait on
 *     completion; the connector itself cannot wedge.
 *   - Bounded work: one socket() + one connect() + one close per call,
 *     plus an optional getsockopt+getsockname when the cache misses.
 *
 * Returns nothing; counts surface via shm->stats.accept_unblocker_*.
 */
void accept_unblocker_fire(int fd, const struct socketinfo *si);

/*
 * pipe-waker: walk the OBJ_FD_PIPE pool for a writer-end fd and
 * write a single byte non-blocking.  A pipe reader on an empty pipe
 * parks in wait_event_interruptible_exclusive(pipe->rd_wait); the
 * kernel makes that wait killable, but an orphaned blocking reader
 * (O_NONBLOCK cleared, no writers active) is still a wedge vector
 * worth poking.
 *
 * Bounded: one random object pick (up to a small retry budget) + one
 * non-blocking write.  No effect when the pool has no writer-end fd
 * or every pick is racing a parent destructor.
 */
void pipe_waker_poke_one(void);
