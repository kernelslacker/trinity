/*
 * SYSCALL_DEFINE3(timer_create, const clockid_t, which_clock,
	struct sigevent __user *, timer_event_spec,
	timer_t __user *, created_timer_id)
 */
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "deferred-free.h"
#include "objects.h"
#include "prop_ring.h"
#include "publish_resource.h"
#include "rnd.h"
#include "sanitise.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/time.h"
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

/*
 * Sanitise-time fallback called from timer_settime sanitiser when the
 * OBJ_TIMERID pool is empty (no timer_create has landed yet in this
 * child).  Calls the real timer_create(2) directly to mint one fresh
 * timer_t with SIGEV_NONE (no signal delivery, no thread spawn,
 * cheapest disposition), registers it in the per-child OBJ_TIMERID
 * pool so the per-child destructor will real-timer_delete() it on
 * shutdown, and returns the new id for the caller to use as rec->a1.
 * Without this, get_random_timerid()'s pool-empty fallback returns a
 * random small int that almost never matches a kernel-allocated
 * timer_t and short-circuits with -EINVAL inside
 * posix_timer_get_by_id() before the k_itimer arm path runs.
 */
int32_t seed_timerid_if_empty(void)
{
	struct sigevent sev;
	timer_t tid = (timer_t) 0;
	intptr_t tid_int;

	if (objects_pool_empty(OBJ_LOCAL, OBJ_TIMERID) == false)
		return get_random_timerid();

	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_NONE;

	if (timer_create(CLOCK_MONOTONIC, &sev, &tid) != 0)
		return (int32_t) (rnd_modulo_u32(32));

	tid_int = (intptr_t) tid;
	if (tid_int < 0 || tid_int > 65535) {
		(void) timer_delete(tid);
		return (int32_t) (rnd_modulo_u32(32));
	}

	register_timerid((int32_t) tid_int);
	return (int32_t) tid_int;
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
 *      checks before dereferencing *get_arg_snapshot(rec, 3).  A
 *      sibling scribble of rec->post_state with a heap-shaped pointer
 *      to a foreign chunk survives looks_like_corrupted_ptr() but
 *      fails the cookie gate.
 *
 *   2. The snap pointer is registered in the post-state ownership
 *      table at sanitise time and checked in the post handler via
 *      post_state_is_owned().  A cookie-collision foreign chunk would
 *      otherwise sail past the magic check.
 *
 * The OUT-pointer (a3 / created_timer_id) defence is now generic:
 * .arg_snapshot_mask opts a3 into the dispatch-time arg_shadow capture
 * (snapshotted inside __do_syscall() after the final
 * blanket_address_scrub, from the locals about to enter the kernel), and
 * the post handler reads it via get_arg_snapshot(rec, 3).  A sibling
 * scribble of rec->a3 between dispatch and post bumps the generic
 * arg_shadow_stomp tripwire from inside the accessor; the returned
 * value is the kernel-visible address, so the *idp deref still hits the
 * buffer the kernel actually wrote.
 */
#define TIMER_CREATE_POST_STATE_MAGIC	0x54494D52435F4D47UL	/* "TIMRC_MG" */
struct timer_create_post_state {
	unsigned long magic;
};

static void timer_create_sanitise(struct syscallrecord *rec)
{
	struct sigevent *sigev;
	struct timer_create_post_state *snap;

	sigev = (struct sigevent *) get_writable_address(sizeof(struct sigevent));
	if (sigev != NULL) {
		uint32_t r = rnd_modulo_u32(100);

		/* Zero the struct before setting a subset of fields -- the
		 * writable-address pool returns uninitialised bytes, and
		 * sigev_notify_function / sigev_notify_attributes (part of
		 * sigev_value's union tail on some libc layouts) plus the
		 * reserved padding would otherwise reach the kernel as
		 * uninitialised. */
		memset(sigev, 0, sizeof(*sigev));

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
	 * sigevent (a2) is curated INPUT: sigev_notify / sigev_signo / _tid
	 * above pick a deliberate disposition the kernel must validate.
	 * argtype[1] = ARG_ADDRESS, so the post-sanitise blanket_address_scrub
	 * relocates the slot to a fresh pool page without copying the curated
	 * bytes -- the kernel then reads pool garbage at the replacement
	 * address and -EINVALs in posix_timer_event() before any sigev_notify
	 * branch runs.  The _inout helper relocates AND memcpys, so the
	 * blanket pass no-ops on this slot and the curated disposition
	 * survives into the kernel.  Guarded on non-NULL: a get_writable_address
	 * failure legitimately leaves a2 == 0 to exercise the kernel's NULL
	 * path.
	 */
	if (sigev != NULL)
		avoid_shared_buffer_inout(&rec->a2, sizeof(struct sigevent));

	/*
	 * created_timer_id (a3) is the kernel's output: timer_create writes
	 * the new timer_t there on success.  Random pool can land it inside
	 * an alloc_shared region, so scrub.
	 */
	avoid_shared_buffer_out(&rec->a3, sizeof(timer_t));

	/* magic-cookie / private post_state: see post_state_register().
	 * The OUT-pointer is defended via .arg_snapshot_mask + the
	 * dispatch-time arg_shadow capture, not a snap field. */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = TIMER_CREATE_POST_STATE_MAGIC;
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
 * + ownership validation and reads the OUT-pointer via the generic
 * arg_shadow accessor before deref so a sibling-stomped post_state or
 * rec->a3 doesn't drive register_timerid() with foreign bytes --
 * corruption attribution for the snap-struct gates stays in
 * post_timer_create() below; out-of-pointer corruption is bumped
 * generically by arg_shadow_stomp from inside get_arg_snapshot().
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
	 * The OUT-pointer (a3 / created_timer_id) is read via the generic
	 * arg_shadow accessor: it returns the kernel-visible address
	 * snapshotted in __do_syscall() after the final
	 * blanket_address_scrub.  A sibling stomp of rec->a3 between
	 * dispatch and here bumps arg_shadow_stomp from inside the
	 * accessor and the post handler still sees the address the kernel
	 * actually wrote.
	 */
	idp = (timer_t *) get_arg_snapshot(rec, 3);
	if (idp == NULL || looks_like_corrupted_ptr(rec, idp))
		return;

	/*
	 * arg_shadow protects the OUT-pointer (idp) from rec->aN scribbles,
	 * but the kernel-written timer_t value at *idp lives in the
	 * user-supplied buffer and is fair game for a sibling syscall to
	 * clobber between the syscall returning and this handler running.
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

	/* Mirror the freshly-registered timer id into the per-child
	 * prop_ring so the typed consumer in gen_arg_timerid can prefer
	 * recently-returned ids over raw randoms / stale pool draws.
	 * tid_int has already been gated to [0, 65535] above, but the
	 * SCALAR_SYSV_SEM exemplar re-checks the success window as
	 * defence in depth before prop_ring_push_scalar -- do the same
	 * here.  The filters inside prop_ring_push_filtered still
	 * reject pointer-shaped and fd-aliased values. */
	if (tid_int < 0 || tid_int > 65535)
		return;
	prop_ring_push_scalar(rec->nr, tid_int, SCALAR_TIMER_ID);
}

/*
 * Cleanup-only sibling of post_timer_create_record_tid().  Owns the
 * scratch-slot teardown and the out-of-range corruption-bump so the
 * registrar above can stay focused on adding tids to the pool.  Reads
 * the OUT-pointer via the generic arg_shadow accessor; a sibling
 * scribble of rec->a3 between dispatch and here bumps arg_shadow_stomp
 * from inside the accessor.
 */
static void post_timer_create(struct syscallrecord *rec)
{
	struct timer_create_post_state *snap =
		(struct timer_create_post_state *) rec->post_state;
	timer_t *idp;
	intptr_t tid_int;

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

	/* RET_ZERO_SUCCESS contract: only retval == 0 means the kernel wrote
	 * *idp.  A failed timer_create still needs its validated snap freed
	 * and unregistered from the post-state ownership table -- otherwise
	 * routine create failures strand 64-slot ownership entries until the
	 * table fills and post_state_is_owned() starts rejecting good snaps
	 * across every syscall.  Skip the *idp deref but still clean up. */
	if ((long) rec->retval != 0)
		goto out_free;

	/*
	 * Read the OUT-pointer via the generic arg_shadow accessor: it
	 * returns the kernel-visible address captured in __do_syscall() and
	 * bumps arg_shadow_stomp from inside the accessor on any
	 * post-dispatch sibling scribble of rec->a3, so a separate
	 * per-syscall mismatch counter would only ever fire on the same
	 * stomp class the generic tripwire already covers.
	 */
	idp = (timer_t *) get_arg_snapshot(rec, 3);
	if (idp == NULL || looks_like_corrupted_ptr(rec, idp))
		goto out_free;

	tid_int = (intptr_t) *idp;
	if (tid_int < 0 || tid_int > 65535) {
		outputerr("post_timer_create: rejected suspicious tid=%p (kernel-write-buffer-scribbled?)\n",
			  (void *) (intptr_t) *idp);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

out_free:
	post_state_release(rec, snap);
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
	/* a3 (created_timer_id) is the kernel's OUT-pointer; both post
	 * handlers deref through it.  Shadow it so a sibling stomp
	 * between dispatch and post bumps arg_shadow_stomp from inside
	 * get_arg_snapshot() and the handlers still see the address the
	 * kernel actually wrote, not the stomped value. */
	.arg_snapshot_mask = (1u << 2),
};
