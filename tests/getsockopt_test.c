/*
 * Self-check for getsockopt's sanitiser: a compat call reads each pointer
 * slot as its low 32 bits, so the option buffer and the length word it
 * hands the kernel come from the low pool for one, whatever value-result
 * shape it drew: HUGE's 4 MiB is a heap buffer no pool can stand in for,
 * which malloc() maps past 4 GiB until a free raises its threshold.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#include "child.h"		/* struct childdata */
#include "debug.h"		/* BUG */
#include "deferred-free.h"	/* deferred_free_flush */
#include "net.h"		/* struct sockopt, struct socketinfo */
#include "sanitise.h"		/* starts_in_call_pools */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_getsockopt */

extern struct childdata *fake_this_child;	/* fake_shm.c */
extern bool fake_random_fd_empty;		/* fake_stubs.c */

/* getsockopt on i386. */
#define NR_GETSOCKOPT_I386	365

/* Calls to judge by: HUGE is about one value-result shape in 32, so
 * these draw it some 30 times. */
#define CALLS	1024

/* The sanitiser keeps only the level and option do_setsockopt() draws for
 * the socket: these name SO_TYPE. */
void do_setsockopt(struct sockopt *so, struct socket_triplet *triplet)
{
	(void) triplet;
	memset(so, 0, sizeof(*so));
	so->level = SOL_SOCKET;
	so->optname = SO_TYPE;
}

void release_sockopt_optval(struct sockopt *so)
{
	(void) so;
}

void getsockopt_self_check(void);
void getsockopt_self_check(void)
{
	static struct childdata compat;
	struct syscallrecord *rec = &compat.syscall;
	struct socketinfo si = { .fd = 3 };
	unsigned int i;

	/* One call in a thousand asks the fd pool for any fd instead of
	 * the socket's: there is none. */
	fake_random_fd_empty = true;

	/* A sanitiser builds the call in this_child()'s record, whose being
	 * compat sends its buffers to the low pool. */
	fake_this_child = &compat;
	for (i = 0; i < CALLS; i++) {
		memset(rec, 0, sizeof(*rec));
		rec->do32bit = true;
		rec->nr = NR_GETSOCKOPT_I386;
		rec->a1 = (unsigned long) &si;
		syscall_getsockopt.sanitise(rec);
		if (rec->a4 > UINT32_MAX || rec->a5 > UINT32_MAX)
			BUG("getsockopt: a compat call's buffer lies past 4 GiB");
		if ((rec->a4 != 0 && !starts_in_call_pools(rec->a4)) ||
		    !starts_in_call_pools(rec->a5))
			BUG("getsockopt: a compat call's buffer is not the call's pool");

		/* A failed call: the post handler only gives the snapshot back. */
		rec->retval = (unsigned long) -1L;
		rec->errno_post = EFAULT;
		syscall_getsockopt.post(rec);
	}
	fake_this_child = NULL;
	fake_random_fd_empty = false;

	/* The value-result buffers went to deferred free: drained here for
	 * ASAN to find. */
	deferred_free_flush();
}
