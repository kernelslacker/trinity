/*
 * SYSCALL_DEFINE5(futex_waitv, struct futex_waitv __user *, waiters,
                   unsigned int, nr_futexes, unsigned int, flags,
                   struct __kernel_timespec __user *, timeout, clockid_t, clockid)
 */
#include <linux/futex.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "futex.h"
#include "random.h"
#include "sanitise.h"
#include "compat.h"

#ifndef FUTEX2_SIZE_U8
#define FUTEX2_SIZE_U8		0x00
#define FUTEX2_SIZE_U16		0x01
#define FUTEX2_SIZE_U32		0x02
#define FUTEX2_SIZE_U64		0x03
#endif

#ifndef FUTEX2_NUMA
#define FUTEX2_NUMA		0x04
#endif

#ifndef FUTEX2_MPOL
#define FUTEX2_MPOL		0x08
#endif

#ifndef FUTEX_32
#define FUTEX_32		FUTEX2_SIZE_U32
#endif

#ifndef FUTEX2_PRIVATE
#define FUTEX2_PRIVATE		FUTEX_PRIVATE_FLAG
#endif

/* Sentinel for "no NUMA node preference" in FUTEX2_MPOL waiters. */
#ifndef FUTEX_NO_NODE
#define FUTEX_NO_NODE		(-1)
#endif

static unsigned long futex_waitv_clockids[] = {
	CLOCK_MONOTONIC, CLOCK_REALTIME,
};

static void sanitise_futex_waitv(struct syscallrecord *rec)
{
	struct futex_waitv *waiters;
	struct timespec *ts;
	unsigned int nr, i;
	__u32 *futex_words;

	nr = 1 + (rand() % 8);

	/* Allocate the futex words that waiters will point to. */
	futex_words = (__u32 *) get_writable_address(nr * sizeof(*futex_words));

	waiters = (struct futex_waitv *) get_writable_address(nr * sizeof(*waiters));
	memset(waiters, 0, nr * sizeof(*waiters));

	for (i = 0; i < nr; i++) {
		uint32_t *shared;

		futex_words[i] = rand32();

		/*
		 * Half the waiters point at the per-call private word, the
		 * other half at the shared cross-child pool so multiple
		 * children block on the same VA.  The shared word's value
		 * may race with concurrent writers between the read and the
		 * syscall -- a mismatch returns EAGAIN, which is fine; the
		 * point is to land collisions in the kernel futex hash.
		 */
		if (RAND_BOOL() && (shared = get_shared_futex_word()) != NULL) {
			waiters[i].uaddr = (__u64)(unsigned long) shared;
			waiters[i].val = *shared;
		} else {
			waiters[i].uaddr = (__u64)(unsigned long) &futex_words[i];
			waiters[i].val = futex_words[i];
		}
		waiters[i].flags = FUTEX2_SIZE_U32;
		if (RAND_BOOL())
			waiters[i].flags |= FUTEX2_PRIVATE;
		if (RAND_BOOL()) {
			waiters[i].flags |= FUTEX2_MPOL;
			waiters[i].__reserved = (__u32)FUTEX_NO_NODE;
		}
	}

	/* Short timeout so we don't block forever. */
	ts = (struct timespec *) get_writable_address(sizeof(*ts));
	ts->tv_sec = 0;
	ts->tv_nsec = rand() % 1000000;	/* up to 1ms */

	rec->a1 = (unsigned long) waiters;
	rec->a2 = nr;
	rec->a3 = 0;
	rec->a4 = (unsigned long) ts;
}

struct syscallentry syscall_futex_waitv = {
	.name = "futex_waitv",
	.num_args = 5,
	.argtype = { [4] = ARG_OP },
	.argname = { [0] = "waiters", [1] = "nr_futexes", [2] = "flags", [3] = "timeout", [4] = "clockid" },
	.arg_params[4].list = ARGLIST(futex_waitv_clockids),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM | IGNORE_ENOSYS,
	.sanitise = sanitise_futex_waitv,
	.group = GROUP_IPC,
};
