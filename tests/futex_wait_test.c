/*
 * Self-check for futex_wait's sanitiser: a compat call reads each pointer
 * slot as its low 32 bits, so the futex word and the clamped timeout it
 * builds must sit below 4 GiB for one.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>

#include "child.h"		/* struct childdata */
#include "debug.h"		/* BUG */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_futex_wait */

extern struct childdata *fake_this_child;	/* fake_shm.c */

/* futex_wait on i386. */
#define NR_FUTEX_WAIT_I386	455

void futex_wait_self_check(void);
void futex_wait_self_check(void)
{
	static struct childdata compat;
	struct syscallrecord *rec = &compat.syscall;
	const struct timespec *ts;

	/* A sanitiser builds the call in this_child()'s record, whose being
	 * compat sends its buffers to the low pool. */
	fake_this_child = &compat;
	memset(rec, 0, sizeof(*rec));
	rec->do32bit = true;
	rec->nr = NR_FUTEX_WAIT_I386;
	syscall_futex_wait.sanitise(rec);
	fake_this_child = NULL;

	if (rec->a1 == 0)
		BUG("futex_wait: the pool gave no futex word");
	if (rec->a1 > UINT32_MAX || rec->a5 > UINT32_MAX)
		BUG("futex_wait: a compat call's futex word or timeout lies past 4 GiB");
	ts = (const struct timespec *) rec->a5;
	if (ts->tv_sec != 0 || ts->tv_nsec < 0 || ts->tv_nsec >= 1000000)
		BUG("futex_wait: a compat call's timeout is not the clamp");
}
