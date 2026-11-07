/*
 * Self-check for lsm_list_modules' sanitiser: a compat call reads each
 * pointer slot as its low 32 bits, so the ids buffer and the size word it
 * hands the kernel come from the low pool for one, whatever value-result
 * shape it drew: HUGE's 4 MiB is a heap buffer no pool can stand in for,
 * which malloc() maps past 4 GiB until a free raises its threshold.
 */

#include <stdint.h>
#include <string.h>

#include "child.h"		/* struct childdata */
#include "debug.h"		/* BUG */
#include "deferred-free.h"	/* deferred_free_flush */
#include "sanitise.h"		/* starts_in_call_pools */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_lsm_list_modules */

extern struct childdata *fake_this_child;	/* fake_shm.c */

/* lsm_list_modules on i386. */
#define NR_LSM_LIST_MODULES_I386	461

/* Calls to judge by: HUGE is about one value-result shape in 32, drawn on
 * four calls in five, so these draw it some 25 times. */
#define CALLS	1024

void lsm_list_modules_self_check(void);
void lsm_list_modules_self_check(void)
{
	static struct childdata compat;
	struct syscallrecord *rec = &compat.syscall;
	unsigned int i;

	/* A sanitiser builds the call in this_child()'s record, whose being
	 * compat sends its buffers to the low pool. */
	fake_this_child = &compat;
	for (i = 0; i < CALLS; i++) {
		memset(rec, 0, sizeof(*rec));
		rec->do32bit = true;
		rec->nr = NR_LSM_LIST_MODULES_I386;
		syscall_lsm_list_modules.sanitise(rec);
		if (rec->a1 > UINT32_MAX || rec->a2 > UINT32_MAX)
			BUG("lsm_list_modules: a compat call's buffer lies past 4 GiB");
		if ((rec->a1 != 0 && !starts_in_call_pools(rec->a1)) ||
		    (rec->a2 != 0 && !starts_in_call_pools(rec->a2)))
			BUG("lsm_list_modules: a compat call's buffer is not the call's pool");

		/* A failed call: the post handler only gives the snapshot back. */
		rec->retval = (unsigned long) -1L;
		syscall_lsm_list_modules.post(rec);
	}
	fake_this_child = NULL;
	/* The value-result buffers went to deferred free: drained here for
	 * ASAN to find. */
	deferred_free_flush();
}
