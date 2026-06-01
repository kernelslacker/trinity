/*
 * SYSCALL_DEFINE3(timer_create, const clockid_t, which_clock,
	struct sigevent __user *, timer_event_spec,
	timer_t __user *, created_timer_id)
 */
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "objects.h"
#include "publish_resource.h"
#include "rnd.h"
#include "sanitise.h"
#include "random.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"
#include "utils.h"

/*
 * OBJ_TIMERID pool: producer-side cache of live POSIX timer ids
 * returned by timer_create.  Consumed by timer_settime/_gettime/
 * _getoverrun/_delete argument generation so subsequent fuzzed calls
 * hit ids the kernel actually has on hand instead of dead-on-arrival
 * random integers.  Lives in the per-child OBJ_LOCAL pool; the pool
 * destructor calls real timer_delete() on shutdown so produced timers
 * don't leak past child lifetime.  Unlike the previous per-call
 * timer_delete-on-return shape, the live ids stay around long enough
 * for the consumers to actually exercise the kernel's k_itimer paths.
 */
static void timerid_destructor(struct object *obj)
{
	timer_delete((timer_t) (intptr_t) obj->timeridobj.tid);
}

static void init_timerid_pool(void)
{
	struct objhead *head;

	head = get_objhead(OBJ_GLOBAL, OBJ_TIMERID);
	if (head == NULL)
		return;

	/* Wire the destructor on the OBJ_GLOBAL head; child OBJ_LOCAL
	 * pools inherit it from here at child fork time
	 * (init_object_lists() copies destroy/dump from the GLOBAL head). */
	head->destroy = &timerid_destructor;
}

REG_GLOBAL_OBJ(timerid, init_timerid_pool);

void register_timerid(int32_t tid)
{
	if (tid < 0)
		return;

	publish_resource(OBJ_TIMERID, (unsigned long)tid, NULL);
}

int32_t get_random_timerid(void)
{
	struct object *obj;

	if (objects_pool_empty(OBJ_LOCAL, OBJ_TIMERID) == true)
		return (int32_t) (rnd_modulo_u32(32));

	obj = get_random_object(OBJ_TIMERID, OBJ_LOCAL);
	if (obj == NULL)
		return (int32_t) (rnd_modulo_u32(32));
	return obj->timeridobj.tid;
}

static int pick_signo_avoiding_sigint(void)
{
	int signo;

	do {
		signo = rnd_modulo_u32(_NSIG);
	} while (signo == SIGINT);
	return signo;
}

static void timer_create_sanitise(struct syscallrecord *rec)
{
	struct sigevent *sigev;

	sigev = (struct sigevent *) get_writable_address(sizeof(struct sigevent));
	if (sigev != NULL) {
		uint32_t r = rnd_modulo_u32(100);

		sigev->sigev_value.sival_int = (int) rnd_u32();
		sigev->sigev_signo = pick_signo_avoiding_sigint();

		if (r < 25) {
			sigev->sigev_notify = SIGEV_NONE;
		} else if (r < 55) {
			sigev->sigev_notify = SIGEV_SIGNAL;
		} else if (r < 80) {
			sigev->sigev_notify = SIGEV_THREAD_ID;
			sigev->_sigev_un._tid = (pid_t) syscall(SYS_gettid);
		} else {
			sigev->sigev_notify = SIGEV_SIGNAL | SIGEV_THREAD_ID;
			sigev->_sigev_un._tid = (pid_t) syscall(SYS_gettid);
		}
	}

	rec->a2 = (unsigned long)sigev;

	/*
	 * created_timer_id (a3) is the kernel's output: timer_create writes
	 * the new timer_t there on success.  Random pool can land it inside
	 * an alloc_shared region, so scrub.
	 */
	avoid_shared_buffer_out(&rec->a3, sizeof(timer_t));

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
 * Post-derived secondary-object registrar wired via
 * .ret_objtype_via_post.  timer_create allocates a kernel k_itimer
 * slab object and writes the resulting timer_t out to
 * *created_timer_id.  Hand the freshly-minted id to the OBJ_TIMERID
 * pool so timer_settime/_gettime/_getoverrun/_delete consumers can
 * pick it up; the per-child pool destructor issues the real
 * timer_delete() at child teardown so produced timers don't outlive
 * the producing child.  Runs ahead of post_timer_create(), which
 * clears rec->post_state during cleanup.
 */
static void post_timer_create_record_tid(struct syscallrecord *rec)
{
	timer_t *idp;
	intptr_t tid_int;

	if ((long) rec->retval < 0)
		return;

	idp = (timer_t *) rec->post_state;
	if (idp == NULL || looks_like_corrupted_ptr(rec, idp))
		return;

	/*
	 * The snapshot protects the OUT-pointer (idp) from rec->aN
	 * scribbles, but the kernel-written timer_t value at *idp lives in
	 * the user-supplied buffer and is fair game for a sibling syscall
	 * to clobber between the syscall returning and this handler running.
	 * glibc's timer_delete() (called from the pool destructor) indexes
	 * a per-process timer table by tid, so a garbage tid faults inside
	 * the table lookup before any defensive return path can run.  A
	 * successful timer_create yields a small non-negative timer_t
	 * (typically a single-digit index); anything outside [0, 65535] is
	 * overwhelmingly likely a scribble — drop those instead of feeding
	 * them to the pool.  Corruption-bump attribution stays in
	 * post_timer_create() so a single bad call is logged once.
	 */
	tid_int = (intptr_t) *idp;
	if (tid_int < 0 || tid_int > 65535)
		return;

	register_timerid((int32_t) tid_int);
}

/*
 * Cleanup-only sibling of post_timer_create_record_tid().  Owns the
 * scratch-slot teardown and the out-of-range corruption-bump so the
 * registrar above can stay focused on adding tids to the pool.
 * This replaces a previous delete-immediately post handler that
 * prevented any pool-based tracking from being useful.
 */
static void post_timer_create(struct syscallrecord *rec)
{
	timer_t *idp;
	intptr_t tid_int;

	if ((long) rec->retval < 0)
		return;

	idp = (timer_t *) rec->post_state;
	if (looks_like_corrupted_ptr(rec, idp)) {
		rec->post_state = 0;
		return;
	}

	tid_int = (intptr_t) *idp;
	if (tid_int < 0 || tid_int > 65535) {
		outputerr("post_timer_create: rejected suspicious tid=%p (kernel-write-buffer-scribbled?)\n",
			  (void *) (intptr_t) *idp);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

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
	.ret_objtype_via_post = post_timer_create_record_tid,
	.rettype = RET_ZERO_SUCCESS,
};
