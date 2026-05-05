/*
 * SYSCALL_DEFINE3(timer_create, const clockid_t, which_clock,
	struct sigevent __user *, timer_event_spec,
	timer_t __user *, created_timer_id)
 */
#include <signal.h>
#include <stdint.h>
#include <time.h>

#include "sanitise.h"
#include "random.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"
#include "utils.h"

static void timer_create_sanitise(struct syscallrecord *rec)
{
	struct sigevent *sigev;

	if (RAND_BOOL()) {
		int signo;

		sigev = (struct sigevent *) get_writable_address(sizeof(struct sigevent));

		/* do not let created timer send SIGINT signal */
		do {
			signo = random() % _NSIG;
		} while (signo  == SIGINT);

		sigev->sigev_signo = signo;
	} else
		sigev = NULL;

	rec->a2 = (unsigned long)sigev;

	/*
	 * created_timer_id (a3) is the kernel's output: timer_create writes
	 * the new timer_t there on success.  Random pool can land it inside
	 * an alloc_shared region, so scrub.
	 */
	avoid_shared_buffer(&rec->a3, sizeof(timer_t));

	/*
	 * Snapshot the user out-pointer for the post handler.  Sibling
	 * syscalls in the child can scribble rec->aN between sanitise and
	 * post; reading from a private slot keeps the deref pointed at the
	 * buffer the kernel actually wrote into.
	 */
	rec->post_state = rec->a3;
}

static unsigned long clock_ids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
	CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME, CLOCK_TAI,
	CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM,
};

/*
 * timer_create allocates a kernel k_itimer slab object and writes the
 * resulting timer_t out to *created_timer_id.  The fuzzer never deletes
 * the timer, so each successful call leaks a k_itimer for the lifetime
 * of the child, climbs RLIMIT_SIGPENDING / per-uid limits, and pins
 * slab memory.  Mirror the IPC RMID-style cleanup applied to
 * semget/msgget: on success, dereference the user out-pointer and
 * timer_delete() the freshly-created id.  Sibling syscalls
 * (timer_settime/_gettime/_getoverrun) may occasionally race the
 * deletion; that is the same tradeoff the IPC cleanup accepts and the
 * underlying kernel paths still get exercised.
 */
static void post_timer_create(struct syscallrecord *rec)
{
	timer_t *idp;
	timer_t tid;
	intptr_t tid_int;

	if ((long) rec->retval < 0)
		return;

	idp = (timer_t *) rec->post_state;
	if (looks_like_corrupted_ptr(rec, idp)) {
		rec->post_state = 0;
		return;
	}

	/*
	 * The snapshot above protects the OUT-pointer (idp) from rec->aN
	 * scribbles, but the kernel-written timer_t value at *idp lives in
	 * the user-supplied buffer and is fair game for a sibling syscall
	 * to clobber between the syscall returning and this handler running.
	 * glibc's timer_delete() indexes a per-process timer table by tid,
	 * so a garbage tid faults inside the table lookup before any
	 * defensive return path can run.  A successful timer_create yields
	 * a small non-negative timer_t (typically a single-digit index);
	 * anything outside [0, 65535] is overwhelmingly likely a scribble.
	 */
	tid = *idp;
	tid_int = (intptr_t) tid;
	if (tid_int < 0 || tid_int > 65535) {
		outputerr("post_timer_create: rejected suspicious tid=%p (kernel-write-buffer-scribbled?)\n",
			  (void *) tid);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	timer_delete(tid);
	rec->post_state = 0;
}

struct syscallentry syscall_timer_create = {
	.name = "timer_create",
	.group = GROUP_TIME,
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "which_clock", [1] = "timer_event_spec", [2] = "create_timer_id" },
	.arg_params[0].list = ARGLIST(clock_ids),
	.sanitise = timer_create_sanitise,
	.post = post_timer_create,
};
