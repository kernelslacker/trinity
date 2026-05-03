/*
 * SYSCALL_DEFINE3(seccomp, unsigned int, op, unsigned int, flags,
 *                          const char __user *, uargs)
 */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/filter.h>
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define SECCOMP_SET_MODE_STRICT		0
#define SECCOMP_SET_MODE_FILTER		1
#define SECCOMP_GET_ACTION_AVAIL	2
#define SECCOMP_GET_NOTIF_SIZES		3

#define SECCOMP_FILTER_FLAG_TSYNC		(1UL << 0)
#define SECCOMP_FILTER_FLAG_LOG			(1UL << 1)
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW		(1UL << 2)
#define SECCOMP_FILTER_FLAG_NEW_LISTENER	(1UL << 3)
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH		(1UL << 4)
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV	(1UL << 5)

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS	0x80000000U
#endif
#ifndef SECCOMP_RET_KILL_THREAD
#define SECCOMP_RET_KILL_THREAD		0x00000000U
#endif
#ifndef SECCOMP_RET_TRAP
#define SECCOMP_RET_TRAP		0x00030000U
#endif
#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO		0x00050000U
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF		0x7fc00000U
#endif
#ifndef SECCOMP_RET_TRACE
#define SECCOMP_RET_TRACE		0x7ff00000U
#endif
#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG			0x7ffc0000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW		0x7fff0000U
#endif

static const uint32_t seccomp_ret_actions[] = {
	SECCOMP_RET_KILL_PROCESS,
	SECCOMP_RET_KILL_THREAD,
	SECCOMP_RET_TRAP,
	SECCOMP_RET_ERRNO,
	SECCOMP_RET_USER_NOTIF,
	SECCOMP_RET_TRACE,
	SECCOMP_RET_LOG,
	SECCOMP_RET_ALLOW,
};

static void sanitise_seccomp(struct syscallrecord *rec)
{
	if (rec->a1 == SECCOMP_SET_MODE_STRICT) {
		rec->a2 = 0;
		rec->a3 = 0;
	}

	if (rec->a1 == SECCOMP_SET_MODE_FILTER) {
		/*
		 * FILTER mode needs uargs pointing to a valid struct sock_fprog
		 * containing a BPF program.  Use bpf_gen_seccomp() which builds
		 * seccomp-flavoured cBPF programs with the Markov chain generator.
		 */
#ifdef USE_BPF
		unsigned long *addr = NULL;
		unsigned long len = 0;

		bpf_gen_seccomp(&addr, &len);
		rec->a3 = (unsigned long) addr;
#endif
	}

	if (rec->a1 == SECCOMP_GET_ACTION_AVAIL) {
		/*
		 * uargs must point to a uint32_t containing the action to probe.
		 * Pick a random valid SECCOMP_RET_* action.
		 */
		uint32_t *action = zmalloc(sizeof(*action));

		*action = seccomp_ret_actions[rand() % ARRAY_SIZE(seccomp_ret_actions)];
		rec->a2 = 0;
		rec->a3 = (unsigned long) action;
	}

	if (rec->a1 == SECCOMP_GET_NOTIF_SIZES) {
		/*
		 * uargs must point to a writable struct seccomp_notif_sizes
		 * (3 x __u16) for the kernel to fill in.
		 */
		rec->a2 = 0;
		rec->a3 = (unsigned long) zmalloc(3 * sizeof(uint16_t));
	}
}

static void post_seccomp(struct syscallrecord *rec)
{
#ifdef USE_BPF
	if (rec->a1 == SECCOMP_SET_MODE_FILTER && rec->a3) {
		struct sock_fprog *fprog = (struct sock_fprog *) rec->a3;

		/*
		 * Snapshot rec->a3 as fprog and reject pid-scribbled values
		 * before deref'ing fprog->filter.  Cluster-1/2/3 guard.
		 */
		if (looks_like_corrupted_ptr(fprog)) {
			outputerr("post_seccomp: rejected suspicious fprog=%p "
				  "(pid-scribbled?)\n", fprog);
			__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
			return;
		}

		/* When SECCOMP_FILTER_FLAG_NEW_LISTENER is set, a successful
		 * SECCOMP_SET_MODE_FILTER returns a notification fd. */
		if ((rec->a2 & SECCOMP_FILTER_FLAG_NEW_LISTENER) &&
		    (int)rec->retval >= 0)
			close((int)rec->retval);

		free(fprog->filter);
		deferred_freeptr(&rec->a3);
	}
#endif
	if (rec->a1 == SECCOMP_GET_ACTION_AVAIL && rec->a3)
		deferred_freeptr(&rec->a3);

	if (rec->a1 == SECCOMP_GET_NOTIF_SIZES && rec->a3)
		deferred_freeptr(&rec->a3);
}

static unsigned long seccomp_ops[] = {
	SECCOMP_SET_MODE_STRICT, SECCOMP_SET_MODE_FILTER,
	SECCOMP_GET_ACTION_AVAIL, SECCOMP_GET_NOTIF_SIZES,
};

static unsigned long seccomp_flags[] = {
	SECCOMP_FILTER_FLAG_TSYNC,
	SECCOMP_FILTER_FLAG_LOG,
	SECCOMP_FILTER_FLAG_SPEC_ALLOW,
	SECCOMP_FILTER_FLAG_NEW_LISTENER,
	SECCOMP_FILTER_FLAG_TSYNC_ESRCH,
	SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
};

struct syscallentry syscall_seccomp = {
	.name = "seccomp",
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_LIST, [2] = ARG_ADDRESS },
	.argname = { [0] = "op", [1] = "flags", [2] = "uargs" },
	.arg_params[0].list = ARGLIST(seccomp_ops),
	.arg_params[1].list = ARGLIST(seccomp_flags),
	.sanitise = sanitise_seccomp,
	.post = post_seccomp,
	.group = GROUP_PROCESS,
};
