/*
 * SYSCALL_DEFINE2(getrlimit, unsigned int, resource, struct rlimit __user *, rlim)
 */
#include <sys/resource.h>
#include <sys/syscall.h>
#include <string.h>
#include "deferred-free.h"
#include "output-poison.h"
#include "random.h"
#include "rlimit-safe.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/resource.h"
#if defined(SYS_getrlimit) || defined(__NR_getrlimit)
#ifndef SYS_getrlimit
#define SYS_getrlimit __NR_getrlimit
#endif
#define HAVE_SYS_GETRLIMIT 1
#endif

#ifdef HAVE_SYS_GETRLIMIT
/*
 * Snapshot of the two getrlimit input args plus the poison seed read by
 * the post oracle, captured at sanitise time and consumed by the post
 * handler.  Lives in rec->post_state, a slot the syscall ABI does not
 * expose, so a sibling syscall scribbling rec->aN between the syscall
 * returning and the post handler running cannot retarget the recheck at
 * a different RLIMIT_* resource, redirect the source memcpy at a foreign
 * user buffer, or smear the poison check against a heap page that
 * happens to still carry a residual pattern from an earlier call.  A
 * poison_seed of 0 means the sanitise-time writability check refused to
 * stamp poison for this call -- the field-recheck oracle still runs, the
 * poison check does not.
 */
#define GETRLIMIT_POST_STATE_MAGIC	0x47524C4DUL	/* "GRLM" */
struct getrlimit_post_state {
	unsigned long magic;
	unsigned int resource;
	void *rlim;
	uint64_t poison_seed;
};
#endif

static unsigned long getrlimit_resources[] = {
	RLIMIT_AS, RLIMIT_CORE, RLIMIT_CPU, RLIMIT_DATA,
	RLIMIT_FSIZE, RLIMIT_LOCKS, RLIMIT_MEMLOCK, RLIMIT_MSGQUEUE,
	RLIMIT_NICE, RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_RSS,
	RLIMIT_RTPRIO, RLIMIT_RTTIME, RLIMIT_SIGPENDING, RLIMIT_STACK,
};

static void sanitise_getrlimit(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_GETRLIMIT
	struct getrlimit_post_state *snap;
	void *buf;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;
#endif

	avoid_shared_buffer_out(&rec->a2, sizeof(struct rlimit));

	/*
	 * Resource (a1) is a read-only input here -- no payload buffer to
	 * fill -- so the per-resource dictionary contribution is simply
	 * "sometimes draw a wholly-random resource value" so the kernel's
	 * `resource >= RLIM_NLIMITS` EINVAL gate stays exercised alongside
	 * the framework's curated list.  ~10% pure-random; the remaining
	 * 90% leave the framework's pick (always a real RLIMIT_*) alone so
	 * the deeper task->signal->rlim[] read path keeps running.
	 */
	if (ONE_IN(10))
		rec->a1 = rand32();
	else if (ONE_IN(10))
		rec->a1 = random_rlimit_resource(getrlimit_resources,
						 ARRAY_SIZE(getrlimit_resources));

#ifdef HAVE_SYS_GETRLIMIT
	/*
	 * Snapshot the two input args + the output-buffer poison seed for
	 * the post oracle.  Without the a1/a2 snap the post handler reads
	 * rec->aN at post-time, when a sibling syscall may have scribbled
	 * the slots: looks_like_corrupted_ptr() cannot tell a real-but-
	 * wrong heap address from the original rlim user-buffer pointer, so
	 * the source memcpy would touch a foreign allocation, and a stomped
	 * resource slot retargets the recheck at a wholly different
	 * RLIMIT_* than the first call ran against.  The poison seed travels
	 * with the pointer so a stomp cannot smear the seed against a heap
	 * page that happens to still carry a residual pattern from an
	 * earlier call.  post_state is private to the post handler.  Gated
	 * on HAVE_SYS_GETRLIMIT to mirror the .post registration -- on
	 * systems without SYS_getrlimit the post handler is not registered
	 * and a snapshot only the post handler can free would leak.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = GETRLIMIT_POST_STATE_MAGIC;
	snap->resource    = (unsigned int) rec->a1;
	snap->rlim        = (void *)(unsigned long) rec->a2;
	snap->poison_seed = 0;

	/*
	 * Stamp a per-call poison pattern into the output buffer the kernel
	 * is about to fill.  The post handler feeds the seed back into
	 * check_output_struct(); a byte-identical poison after a success
	 * return means the kernel skipped copy_to_user() entirely or short-
	 * copied and left an uninitialised tail readable in user memory (a
	 * kernel->user infoleak).  Gate on range_readable_user() so a
	 * writable-pool draw that avoid_shared_buffer_out() moved to an
	 * address that is no longer provably mapped does not SIGSEGV the
	 * sanitiser inside poison_output_struct's byte-walk.  On skip,
	 * poison_seed stays 0 and the post handler no-ops the poison check
	 * while the field-recheck oracle still runs against snap->rlim.
	 * Done after avoid_shared_buffer_out() so the poison lands on the
	 * final buffer the kernel will see.  The window is exactly
	 * sizeof(struct rlimit) so the untouched-tail check does not
	 * false-positive on bytes the kernel was never asked to fill.
	 */
	buf = (void *)(unsigned long) rec->a2;
	if (range_readable_user(buf, sizeof(struct rlimit)))
		snap->poison_seed = poison_output_struct(buf,
							 sizeof(struct rlimit),
							 0);

	post_state_install(rec, snap);
#endif
}

/*
 * Oracle: getrlimit(resource, &rlim) reads task->signal->rlim[resource]
 * under task_lock and copies the {rlim_cur, rlim_max} pair out to the
 * user buffer.  Two independent post checks run against the same success
 * return:
 *
 *   1. Untouched-buffer poison check.  Sanitise stamped a per-call poison
 *      pattern into the output buffer; a byte-identical poison after a
 *      0-retval means the kernel skipped copy_to_user() entirely or
 *      short-copied and left an uninitialised tail readable in user
 *      memory (a kernel->user infoleak).  Runs on every success -- the
 *      check is a repeating 8-byte pattern compare over sizeof(struct
 *      rlimit) with no re-issue -- and bumps the shared
 *      post_handler_untouched_out_buf slot.
 *
 *   2. Field-recheck oracle.  Re-issuing the same query for the same
 *      resource a moment later must produce the same {rlim_cur, rlim_max}
 *      pair unless something in between either (a) had copy_to_user write
 *      past or before the live rlim slot, (b) tore a write from a
 *      parallel prlimit64 setting our own limits, or (c) the userspace
 *      receive buffer was clobbered after the kernel returned.  Sample
 *      one in a hundred to stay in line with the rest of the oracle
 *      family.
 *
 * TOCTOU defeat: the two input args (resource, rlim) and the poison seed
 * are snapshotted at sanitise time into a heap struct in rec->post_state,
 * so a sibling that scribbles rec->aN between syscall return and post
 * entry cannot retarget the recheck at a different RLIMIT_* (the resource
 * scalar), redirect the source memcpy at a foreign user buffer (the rlim
 * pointer), or smear the poison check against an unrelated heap page
 * that happens to still carry a residual pattern.  The user buffer
 * payload is then snapshotted into a stack-local before the re-call
 * writes into a fresh private stack buffer -- a sibling could mutate the
 * user buffer itself mid-syscall and forge a clean compare.
 *
 * Snap gating: the snap is registered in the ownership table at install
 * time and the post handler gates entry through post_state_claim_owned(),
 * which runs the canonical shape -> ownership -> magic check before any
 * inner-field deref -- a stale same-type snapshot still readable in the
 * deferred-free queue, or a sibling scribble of rec->post_state with a
 * heap-shaped pointer at a foreign allocation, is rejected before the
 * resource or rlim fields are touched.
 *
 * If the re-call returns -1 (the original syscall succeeded but the
 * re-call hit a transient failure), give up rather than report a false
 * divergence.
 *
 * Note: a sibling trinity child issuing prlimit64(target_pid=us) is a
 * benign source of divergence -- accept the false-positive rate
 * (1/100 sample x low background prlimit64 rate).
 */
#ifdef HAVE_SYS_GETRLIMIT
static void post_getrlimit(struct syscallrecord *rec)
{
	struct getrlimit_post_state *snap =
		post_state_claim_owned(rec, GETRLIMIT_POST_STATE_MAGIC,
				       __func__);
	struct rlimit local, syscall_buf;

	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->rlim == NULL)
		goto out_free;

	if (!post_snapshot_or_skip(&syscall_buf,
				   (const void *) snap->rlim,
				   sizeof(syscall_buf)))
		goto out_free;

	/*
	 * Untouched-buffer poison check runs on every success sample the
	 * buffer snapshot succeeded on.  poison_seed of 0 means sanitise
	 * chose not to stamp poison (unwritable pointer) -- skip the check
	 * so "we couldn't poison" is not confused with "kernel didn't
	 * write".  Counts against the shared post_handler_untouched_out_buf
	 * slot; the field-recheck arm below is rate-limited but this one
	 * is cheap enough to fire every time.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct(&syscall_buf, sizeof(syscall_buf),
				snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_free;

	memset(&local, 0, sizeof(local));
	if (getrlimit(snap->resource, &local) == -1)
		goto out_free;

	if (local.rlim_cur != syscall_buf.rlim_cur ||
	    local.rlim_max != syscall_buf.rlim_max) {
		output(0,
		       "getrlimit oracle: resource=%u syscall={cur=%lu,max=%lu} recheck={cur=%lu,max=%lu}\n",
		       snap->resource,
		       (unsigned long) syscall_buf.rlim_cur,
		       (unsigned long) syscall_buf.rlim_max,
		       (unsigned long) local.rlim_cur,
		       (unsigned long) local.rlim_max);
		__atomic_add_fetch(&shm->stats.oracle.getrlimit_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}
#endif

struct syscallentry syscall_getrlimit = {
	.name = "getrlimit",
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_STRUCT_PTR_OUT },
	.argname = { [0] = "resource", [1] = "rlim" },
	.arg_params[0].list = ARGLIST(getrlimit_resources),
	.sanitise = sanitise_getrlimit,
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
#ifdef HAVE_SYS_GETRLIMIT
	.post = post_getrlimit,
#endif
};
