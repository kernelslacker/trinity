/*
 * SYSCALL_DEFINE5(futex_waitv, struct futex_waitv __user *, waiters,
                   unsigned int, nr_futexes, unsigned int, flags,
                   struct __kernel_timespec __user *, timeout, clockid_t, clockid)
 */
#include <linux/futex.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "futex.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "compat.h"

#ifndef FUTEX_32
#define FUTEX_32		FUTEX2_SIZE_U32
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
	unsigned int nr, i;
	__u32 *futex_words;

	nr = 1 + (rnd_modulo_u32(8));

	/* Allocate the futex words that waiters will point to. */
	futex_words = (__u32 *) get_writable_address(nr * sizeof(*futex_words));

	waiters = (struct futex_waitv *) get_writable_address(nr * sizeof(*waiters));
	if (futex_words == NULL || waiters == NULL)
		return;
	memset(waiters, 0, nr * sizeof(*waiters));

	for (i = 0; i < nr; i++) {
		uint32_t *shared;
		bool is_shared = false;

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
			is_shared = true;
		} else {
			waiters[i].uaddr = (__u64)(unsigned long) &futex_words[i];
			waiters[i].val = futex_words[i];
		}
		waiters[i].flags = FUTEX2_SIZE_U32;
		/*
		 * FUTEX2_PRIVATE routes the waiter through the per-mm hash
		 * bucket; setting it on a uaddr that lives in shared cross-
		 * child memory defeats the whole point of the shared-word pool
		 * (different children would each hash to their own private
		 * bucket and never collide).  Only flag a private waiter when
		 * the uaddr is the per-call word in this child's address space.
		 */
		if (!is_shared && RAND_BOOL())
			waiters[i].flags |= FUTEX2_PRIVATE;
		if (RAND_BOOL()) {
			waiters[i].flags |= FUTEX2_MPOL;
			waiters[i].__reserved = (__u32)FUTEX_NO_NODE;
		}
	}

	rec->a1 = (unsigned long) waiters;
	avoid_shared_buffer_inout(&rec->a1, nr * sizeof(*waiters));
	rec->a2 = nr;
	rec->a3 = 0;

	/*
	 * a4 (timeout) is typed ARG_TIMESPEC; the generator publishes
	 * a writable pool buffer (or NULL ~10%) for us.  NEED_ALARM caps
	 * any blocking arm a large tv_sec bucket would otherwise produce.
	 */
}

struct syscallentry syscall_futex_waitv = {
	.name = "futex_waitv",
	.num_args = 5,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN, [3] = ARG_TIMESPEC, [4] = ARG_OP },
	.argname = { [0] = "waiters", [1] = "nr_futexes", [2] = "flags", [3] = "timeout", [4] = "clockid" },
	.arg_params[4].list = ARGLIST(futex_waitv_clockids),
	.bound_arg = 2,
	.flags = NEED_ALARM | IGNORE_ENOSYS,
	.sanitise = sanitise_futex_waitv,
	.group = GROUP_IPC,
};
