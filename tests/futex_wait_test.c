/*
 * Self-check for futex_wait's sanitiser: a compat call reads each pointer
 * slot as its low 32 bits, so the futex word and the clamped timeout it
 * builds must sit below 4 GiB for one.  And for futex_wait's and
 * futex_wake's: the kernel implements only FUTEX2_SIZE_U32, so most draws
 * must take it, and a FUTEX2_NUMA word must carry a node it takes.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>

#include "child.h"		/* struct childdata */
#include "debug.h"		/* BUG */
#include "kernel/futex.h"	/* FUTEX2_*, FUTEX_NO_NODE */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_futex_wait, syscall_futex_wake */

extern struct childdata *fake_this_child;	/* fake_shm.c */

/* futex_wait on i386. */
#define NR_FUTEX_WAIT_I386	455

/* Draws, of which at least three in four must take the size the kernel
 * implements. */
#define SIZE_DRAWS	1000

static void sizes_are_mostly_u32(struct syscallentry *entry)
{
	unsigned int i, sized = 0;

	for (i = 0; i < SIZE_DRAWS; i++) {
		struct syscallrecord rec;

		memset(&rec, 0, sizeof(rec));
		entry->sanitise(&rec);
		if ((rec.a4 & FUTEX2_SIZE_MASK) == FUTEX2_SIZE_U32)
			sized++;
		if (entry == &syscall_futex_wait && (rec.a4 & FUTEX2_NUMA) &&
		    ((const uint32_t *) rec.a1)[1] != (uint32_t) FUTEX_NO_NODE)
			BUG("futex_wait: a FUTEX2_NUMA word's node is not FUTEX_NO_NODE");
	}
	if (sized < SIZE_DRAWS * 3 / 4)
		BUG("futex2: most draws took a size the kernel does not implement");
}

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

	sizes_are_mostly_u32(&syscall_futex_wait);
	sizes_are_mostly_u32(&syscall_futex_wake);
}
