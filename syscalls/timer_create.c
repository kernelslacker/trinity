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

#include "deferred-free.h"
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

/*
 * Snapshot for the post handler.  Mirrors the pipe/socketpair shape:
 *
 *   1. The snap struct carries a magic cookie that the post handler
 *      checks before dereferencing snap->idp.  A sibling scribble of
 *      rec->post_state with a heap-shaped pointer to a foreign chunk
 *      survives looks_like_corrupted_ptr() but fails the cookie gate.
 *
 *   2. The snap pointer is registered in the post-state ownership
 *      table at sanitise time and checked in the post handler via
 *      post_state_is_owned().  A cookie-collision foreign chunk would
 *      otherwise sail past the magic check.
 *
 *   3. snap->idp records the out-pointer value as written into rec->a3
 *      at sanitise time.  The post handler compares snap->idp against
 *      the live rec->a3 and bails on mismatch -- a sibling scribble of
 *      rec->a3 between sanitise and post means the kernel either wrote
 *      to a different buffer (so *snap->idp is stale) or rec->a3 was
 *      clobbered after the syscall returned (so *snap->idp may have
 *      been written-to-then-unmapped underneath us).  Either way the
 *      timer_t we'd read is untrustworthy.
 */
#define TIMER_CREATE_POST_STATE_MAGIC	0x54494D52435F4D47UL	/* "TIMRC_MG" */
struct timer_create_post_state {
	unsigned long magic;
	timer_t *idp;
};

static void timer_create_sanitise(struct syscallrecord *rec)
{
	struct sigevent *sigev;
	struct timer_create_post_state *snap;

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
	 * buffer the kernel actually wrote into, and the identity check in
	 * the post handler turns a scribbled rec->a3 into a clean bail
	 * rather than a quiet read from a stale or unmapped address.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = TIMER_CREATE_POST_STATE_MAGIC;
	snap->idp = (timer_t *) rec->a3;
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);
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
 * clears rec->post_state during cleanup.  Does its own shape + magic
 * + ownership + inner-pointer-identity validation before deref so a
 * sibling-stomped post_state doesn't drive register_timerid() with
 * foreign bytes -- corruption attribution stays in post_timer_create()
 * below, which repeats the same checks and owns the inner-ptr-mismatch
 * counter bump.
 */
static void post_timer_create_record_tid(struct syscallrecord *rec)
{
	struct timer_create_post_state *snap =
		(struct timer_create_post_state *) rec->post_state;
	timer_t *idp;
	intptr_t tid_int;

	/* timer_create is RET_ZERO_SUCCESS: the only successful retval is
	 * exactly 0.  Anything else -- including a positive small int left
	 * by a sibling stomp the dispatcher's rzs gate happened to miss --
	 * means the kernel-written *idp may not exist or may hold stale
	 * shm noise.  Tighter than the previous (long)retval < 0 gate,
	 * which admitted a stomped retval=5 as "success" and let a garbage
	 * timer_t through into the OBJ_TIMERID pool. */
	if (rec->retval != 0)
		return;

	if (snap == NULL || looks_like_corrupted_ptr(rec, snap))
		return;

	if (!post_state_is_owned(snap))
		return;

	if (snap->magic != TIMER_CREATE_POST_STATE_MAGIC)
		return;

	/*
	 * Inner-pointer-identity check: snap->idp is the out-pointer we
	 * captured at sanitise; rec->a3 is the live slot.  A mismatch
	 * means a sibling scribble retargeted the kernel's write or
	 * clobbered rec->a3 after return -- *snap->idp would read stale
	 * or unmapped bytes either way.
	 */
	if ((timer_t *) rec->a3 != snap->idp)
		return;

	idp = snap->idp;
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
 * scratch-slot teardown, the out-of-range corruption-bump, and the
 * inner-ptr-mismatch counter so the registrar above can stay focused
 * on adding tids to the pool.  This replaces a previous delete-
 * immediately post handler that prevented any pool-based tracking
 * from being useful.
 */
static void post_timer_create(struct syscallrecord *rec)
{
	struct timer_create_post_state *snap =
		(struct timer_create_post_state *) rec->post_state;
	timer_t *idp;
	intptr_t tid_int;

	/* Same strict success gate as post_timer_create_record_tid:
	 * RET_ZERO_SUCCESS contract means only retval == 0 indicates the
	 * kernel actually wrote *idp.  Reject everything else (including
	 * the rzs-coerced -1UL) before dereferencing post_state. */
	if (rec->retval != 0)
		return;

	if (snap == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_timer_create: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->post_state = 0;
		return;
	}

	if (!post_state_is_owned(snap)) {
		outputerr("post_timer_create: rejected post_state=%p not in "
			  "ownership table (post_state-redirected?)\n", snap);
		rec->post_state = 0;
		return;
	}

	if (snap->magic != TIMER_CREATE_POST_STATE_MAGIC) {
		outputerr("post_timer_create: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	if ((long) rec->retval < 0)
		goto out_free;

	/*
	 * Inner-pointer-identity check: snap->idp is the out-pointer we
	 * captured at sanitise; rec->a3 is the live slot.  A mismatch
	 * means a sibling scribble retargeted the kernel's write or
	 * clobbered rec->a3 after return.  Bump the dedicated mismatch
	 * counter and skip the *idp deref entirely -- the timer_t there
	 * is untrustworthy.
	 */
	if ((timer_t *) rec->a3 != snap->idp) {
		outputerr("post_timer_create: inner-ptr mismatch snap->idp=%p rec->a3=%p "
			  "(sibling-scribbled out-pointer)\n",
			  (void *) snap->idp, (void *) rec->a3);
		__atomic_add_fetch(&shm->stats.timer_create_inner_ptr_mismatch,
				   1, __ATOMIC_RELAXED);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_free;
	}

	idp = snap->idp;
	if (idp == NULL || looks_like_corrupted_ptr(rec, idp))
		goto out_free;

	tid_int = (intptr_t) *idp;
	if (tid_int < 0 || tid_int > 65535) {
		outputerr("post_timer_create: rejected suspicious tid=%p (kernel-write-buffer-scribbled?)\n",
			  (void *) (intptr_t) *idp);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

out_free:
	post_state_unregister(snap);
	deferred_freeptr(&rec->post_state);
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
