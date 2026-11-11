/*
 * Self-check for io_uring_setup's sanitiser
 * (syscalls/io_uring/io_uring_setup.c): what its curated arms draw gets
 * past io_uring_setup()'s checks.  TASKRUN_FLAG goes with COOP_TASKRUN or
 * DEFER_TASKRUN, and a CQSIZE ring's completion queue, rounded up to a
 * power of two as the kernel rounds both, is no smaller than its
 * submission queue.  set_rand_bitmask() is faked to draw no bits here, so
 * the random arm, which is there to reach the rejects, draws no flags.
 */

#include <stdlib.h>
#include <string.h>

#include "debug.h"		/* BUG */
#include "kernel/io_uring.h"	/* IORING_SETUP_*, struct io_uring_params */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_io_uring_setup */

/* Draws, which miss the one combo in 21 that sets either flag, the 60% of
 * the time a curated combo is drawn, one time in about 10^12. */
#define DRAWS	4096

static unsigned long roundup_pow2(unsigned long n)
{
	unsigned long p = 1;

	while (p < n)
		p <<= 1;
	return p;
}

void io_uring_setup_self_check(void);
void io_uring_setup_self_check(void)
{
	unsigned int i, taskrun = 0, cqsize = 0;

	for (i = 0; i < DRAWS; i++) {
		const struct io_uring_params *p;
		struct syscallrecord rec;

		memset(&rec, 0, sizeof(rec));
		syscall_io_uring_setup.sanitise(&rec);
		p = (const struct io_uring_params *) rec.a2;

		if (p->flags & IORING_SETUP_TASKRUN_FLAG) {
			taskrun++;
			if (!(p->flags & (IORING_SETUP_COOP_TASKRUN |
					  IORING_SETUP_DEFER_TASKRUN)))
				BUG("io_uring_setup: TASKRUN_FLAG without COOP_TASKRUN or DEFER_TASKRUN");
		}
		if (p->flags & IORING_SETUP_CQSIZE) {
			cqsize++;
			if (roundup_pow2(p->cq_entries) < roundup_pow2(rec.a1))
				BUG("io_uring_setup: a CQSIZE completion queue smaller than its submission queue");
		}
		/* The release .cleanup makes leaks here: this binary's
		 * zmalloc_tracked() registers nothing with the alloc-track. */
		free((void *) rec.post_state);
	}
	if (taskrun == 0 || cqsize == 0)
		BUG("io_uring_setup: no draw set TASKRUN_FLAG or CQSIZE");
}
