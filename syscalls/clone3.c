/*
 * SYSCALL_DEFINE2(clone3, struct clone_args __user *, uargs, size_t, size)
 */

#include <stdlib.h>
#include <signal.h>
#include <linux/sched.h>
#include "arch.h"
#include "clone.h"
#include "fd.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "utils.h"
#include "child.h"
#include "shm.h"
#include "stats_ring.h"
#include "trinity.h"
#include "compat.h"

#ifndef CLONE_ARGS_SIZE_VER0
#define CLONE_ARGS_SIZE_VER0 64
#endif
#ifndef CLONE_ARGS_SIZE_VER1
#define CLONE_ARGS_SIZE_VER1 80
#endif
#ifndef CLONE_ARGS_SIZE_VER2
#define CLONE_ARGS_SIZE_VER2 88
#endif

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
#ifndef CLONE_CLEAR_SIGHAND
#define CLONE_CLEAR_SIGHAND 0x100000000ULL
#endif
#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif
#ifndef CLONE_AUTOREAP
#define CLONE_AUTOREAP		(1ULL << 34)
#define CLONE_NNP		(1ULL << 35)
#define CLONE_PIDFD_AUTOKILL	(1ULL << 36)
#define CLONE_EMPTY_MNTNS	(1ULL << 37)
#endif

static unsigned long clone3_flags[] = {
	CLONE_VM, CLONE_FS, CLONE_FILES, CLONE_SIGHAND,
	CLONE_PIDFD, CLONE_PTRACE, CLONE_VFORK, CLONE_PARENT,
	CLONE_THREAD, CLONE_NEWNS, CLONE_SYSVSEM, CLONE_SETTLS,
	CLONE_PARENT_SETTID, CLONE_CHILD_CLEARTID, CLONE_UNTRACED,
	CLONE_CHILD_SETTID, CLONE_NEWCGROUP, CLONE_NEWUTS,
	CLONE_NEWIPC, CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET,
	CLONE_IO, CLONE_NEWTIME,
	CLONE_CLEAR_SIGHAND, CLONE_INTO_CGROUP,
	CLONE_AUTOREAP, CLONE_NNP, CLONE_PIDFD_AUTOKILL, CLONE_EMPTY_MNTNS,
};

static unsigned long clone3_sizes[] = {
	CLONE_ARGS_SIZE_VER0,
	CLONE_ARGS_SIZE_VER1,
	CLONE_ARGS_SIZE_VER2,
	sizeof(struct clone_args),
};

/*
 * Low-bit ticket on rec->post_state -- see the long comment in
 * sanitise_clone3() about the throttle bookkeeping.  zmalloc returns
 * >=8-byte-aligned pointers so this bit is free to overlay on the
 * args pointer, but the post handler must mask it off before any
 * dereference or deferred_freeptr() of post_state.  The bit constant
 * and the admission / release atomics live in include/shm.h alongside
 * MAX_CONCURRENT_NEWNET.
 */

static void sanitise_clone3(struct syscallrecord *rec)
{
	struct clone_args *args;
	bool newnet_admitted = false;

	args = zmalloc(sizeof(struct clone_args));

	args->flags = set_rand_bitmask(ARRAY_SIZE(clone3_flags), clone3_flags);
	{
		unsigned long f = (unsigned long)args->flags;

		enforce_clone_flag_deps(&f, false);
		args->flags = f;
	}

	/*
	 * Throttle CLONE_NEWNET to MAX_CONCURRENT_NEWNET fleet-wide -- the
	 * kernel's netns cleanup workqueue is the slow path and any
	 * grandchild that succeeds with this flag widens the backlog.  See
	 * the comment on MAX_CONCURRENT_NEWNET in include/shm.h.  The
	 * "did we increment" decision rides in bit 0 of rec->post_state
	 * (set in stash_args_into_post_state below) -- post_state is
	 * already spoken for here as the args pointer for post_clone3 to
	 * free, but zmalloc returns >=8-byte-aligned pointers so the low
	 * three bits are free.  We deliberately do not derive the post-
	 * call decision from args->flags: a sibling syscall can scribble
	 * the args allocation between BEFORE and AFTER, and an unbalanced
	 * decrement would underflow the in-flight counter into a giant
	 * unsigned value and permanently disable the cap.
	 */
	if (args->flags & CLONE_NEWNET) {
		if (try_admit_newnet()) {
			newnet_admitted = true;
		} else {
			struct childdata *c = this_child();

			args->flags &= ~CLONE_NEWNET;
			if (c != NULL && c->stats_ring != NULL)
				stats_ring_enqueue(c->stats_ring,
						   STATS_FIELD_UNSHARE_NEWNET_THROTTLED,
						   0, 1);
			else
				parent_stats.unshare_newnet_throttled++;
		}
	}

	args->exit_signal = rand() % _NSIG;

	/*
	 * clone3_args_valid() rejects a non-zero exit_signal when
	 * CLONE_THREAD or CLONE_PARENT is set. Force it to zero so
	 * the call reaches copy_process() instead of bouncing at the
	 * argument validator.
	 */
	if (args->flags & (CLONE_THREAD | CLONE_PARENT))
		args->exit_signal = 0;

	if (args->flags & CLONE_VM) {
		void *stack = get_writable_address(page_size);

		if (stack != NULL) {
			args->stack = (unsigned long) stack;
			args->stack_size = page_size;
		}
	}

	if (args->flags & CLONE_PIDFD) {
		void *pidfd = get_writable_address(sizeof(int));

		if (pidfd != NULL)
			args->pidfd = (unsigned long) pidfd;
	}

	if (args->flags & CLONE_NEWPID) {
		unsigned int count = RAND_RANGE(1, 3);
		pid_t *set_tid = zmalloc(count * sizeof(pid_t));
		unsigned int i;

		for (i = 0; i < count; i++)
			set_tid[i] = get_pid();
		args->set_tid = (unsigned long) set_tid;
		args->set_tid_size = count;
	}

	if (args->flags & CLONE_INTO_CGROUP)
		args->cgroup = (unsigned int) get_random_fd();

	if (args->flags & CLONE_CHILD_SETTID) {
		void *child_tid = get_writable_address(sizeof(int));

		if (child_tid != NULL)
			args->child_tid = (unsigned long) child_tid;
	}

	if (args->flags & CLONE_PARENT_SETTID) {
		void *parent_tid = get_writable_address(sizeof(int));

		if (parent_tid != NULL)
			args->parent_tid = (unsigned long) parent_tid;
	}

	if (args->flags & CLONE_SETTLS)
		args->tls = (unsigned long) get_address();

	rec->a1 = (unsigned long) args;
	rec->a2 = RAND_ARRAY(clone3_sizes);

	/* Snapshot for the post handler -- a1 may be scribbled by a sibling
	 * syscall before post_clone3() runs.  Bit 0 doubles as the throttle
	 * "we incremented shm->newnet_in_flight" ticket; post_clone3 masks
	 * it off before any dereference / deferred_freeptr. */
	rec->post_state = (unsigned long) args;
	if (newnet_admitted)
		rec->post_state |= NEWNET_INFLIGHT_TICKET;
}

static void post_clone3(struct syscallrecord *rec)
{
	struct clone_args *args;

	/*
	 * Drop the throttle ticket first and atomically, before any
	 * branch that might early-return or call deferred_freeptr() on
	 * post_state.  Two reasons it has to be atomic:
	 *
	 *   1. The ticket bit overlays the args pointer; the pointer
	 *      must be intact for the post handler's downstream
	 *      dereference and deferred_freeptr().  fetch_and clears
	 *      only bit 0 and leaves the rest of post_state alone.
	 *
	 *   2. clone3() returns in BOTH the parent and the newly
	 *      created task; the syscallrecord lives in shared memory
	 *      (children[] is alloc_shared), so both tasks reach this
	 *      hook against the same rec->post_state.
	 *      release_newnet_ticket() test-and-clears in a single RMW
	 *      so only one branch's decrement lands -- a plain
	 *      check-then-clear-then-fetch_sub would let both branches
	 *      decrement for one admission and drift the counter toward
	 *      negative, permanently disabling the cap.
	 */
	release_newnet_ticket(rec);

	/*
	 * Kernel ABI: parent retval is the child pid in [1, PID_MAX_LIMIT=4194304],
	 * 0 in the child, or -1UL on failure. Anything else is a corrupted retval
	 * (sign-extension tear or pid_ns translation bug) — reject before touching
	 * the args snapshot or running the post-cleanup path.
	 */
	if (rec->retval > 4194304UL && rec->retval != (unsigned long)-1L) {
		output(0, "post_clone3: rejected returned pid 0x%lx outside [1, PID_MAX_LIMIT=4194304] (and not -1)\n",
		       rec->retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
		/* still need to release post_state deferred buf if non-zero */
		if (rec->post_state) {
			rec->a1 = 0;
			deferred_freeptr(&rec->post_state);
		}
		return;
	}

	args = (struct clone_args *)(unsigned long) rec->post_state;

	if (args == NULL)
		return;
	if (looks_like_corrupted_ptr(rec, args)) {
		outputerr("post_clone3: rejected suspicious args=%p (pid-scribbled?)\n",
			  args);
		rec->a1 = 0;
		rec->post_state = 0;
		return;
	}

	if (args->set_tid != 0)
		deferred_free_enqueue((void *)(unsigned long) args->set_tid);
	rec->a1 = 0;
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_clone3 = {
	.name = "clone3",
	.group = GROUP_PROCESS,
	.num_args = 2,
	.flags = AVOID_SYSCALL,
	.argtype = { [0] = ARG_STRUCT_PTR_IN, [1] = ARG_STRUCT_SIZE },
	.argname = { [0] = "uargs", [1] = "size" },
	.sanitise = sanitise_clone3,
	.post = post_clone3,
	.rettype = RET_PID_T,
	.ret_objtype = OBJ_PID,
};
