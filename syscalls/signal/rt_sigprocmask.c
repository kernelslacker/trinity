/*
 * SYSCALL_DEFINE4(rt_sigprocmask, int, how, sigset_t __user *, set,
	sigset_t __user *, oset, size_t, sigsetsize)
 */
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include "deferred-free.h"
#include "output-poison.h"
#include "proc-status.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/* Kernel sigset_t is a fixed 64-bit mask; sizeof matches on every arch. */
#define KERNEL_SIGSET_SIZE	8

/*
 * Snapshot of the four rt_sigprocmask input args plus the oset poison
 * seed read by the post oracle, captured at sanitise time and consumed
 * by the post handler.  Lives in rec->post_state, a slot the syscall
 * ABI does not expose, so a sibling syscall scribbling rec->aN between
 * the syscall returning and the post handler running cannot retarget
 * the oracle at a foreign oset user buffer, smear the sigsetsize
 * length check, steer the set != NULL gate that decides whether to
 * run the procfs cross-check at all, or redirect the poison check at
 * a residual pattern on an unrelated heap page.  A poison_seed of 0
 * means the sanitise-time writability check refused to stamp poison
 * for this call and the post handler must no-op the untouched-buffer
 * arm.
 */
#define RT_SIGPROCMASK_POST_STATE_MAGIC	0x5254534DUL	/* "RTSM" */
struct rt_sigprocmask_post_state {
	unsigned long magic;
	unsigned long how;
	unsigned long set;
	unsigned long oset;
	unsigned long sigsetsize;
	uint64_t poison_seed;
};

static void sanitise_rt_sigprocmask(struct syscallrecord *rec)
{
	struct rt_sigprocmask_post_state *snap;

	rec->a4 = KERNEL_SIGSET_SIZE;

	/*
	 * oset (a3) is the kernel's writeback target for the previous mask
	 * (a4 bytes wide).  ARG_ADDRESS draws from the random pool, so a
	 * fuzzed pointer can land inside an alloc_shared region and let the
	 * kernel scribble bookkeeping.
	 */
	avoid_shared_buffer_out(&rec->a3, rec->a4);

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	/*
	 * Snapshot the four input args read by the post oracle.  Without
	 * this the post handler reads rec->a2/a3/a4 at post-time, when a
	 * sibling syscall may have scribbled the slots:
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original oset user buffer pointer, so the source
	 * memcpy would touch a foreign allocation that the guard never
	 * inspected, the sigsetsize gate would resolve against a scribbled
	 * value, and a stomped a2 (set) could flip the "skip when set !=
	 * NULL" gate either way -- letting the oracle race against a
	 * concurrent mutation, or silently suppressing a real comparison.
	 * post_state is private to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic      = RT_SIGPROCMASK_POST_STATE_MAGIC;
	snap->how        = rec->a1;
	snap->set        = rec->a2;
	snap->oset       = rec->a3;
	snap->sigsetsize = rec->a4;
	/*
	 * Stamp a per-call poison pattern into the oset OUT-buffer the
	 * kernel is about to fill on success.  Independent of set: the
	 * kernel still writes the previous mask out to oset before it
	 * swaps in the new one, so the poison stamp is meaningful on the
	 * mutating path (set != NULL) as well as the pure-read path.
	 * Gate on range_readable_user() so an ARG_ADDRESS draw of NULL,
	 * or a writable-pool draw that avoid_shared_buffer_out() moved to
	 * an address that is no longer provably mapped, does not SIGSEGV
	 * the sanitiser inside poison_output_struct's byte walk.  On
	 * skip, poison_seed stays 0 (zmalloc_tracked zeros the slot) and
	 * the post handler no-ops the poison check while the procfs
	 * divergence oracle still runs against snap->oset.  Done after
	 * avoid_shared_buffer_out() so the poison lands on the final
	 * buffer the kernel will see.
	 */
	{
		void *buf = (void *)(unsigned long) rec->a3;

		if (range_readable_user(buf, sizeof(sigset_t)))
			snap->poison_seed = poison_output_struct(buf,
								 sizeof(sigset_t),
								 0);
	}
	/*
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_rt_sigprocmask() will then gate the snap
	 * through post_state_claim_owned() and prove ownership before
	 * dereferencing any field.
	 */
	post_state_install(rec, snap);
}

static unsigned long sigprocmask_how[] = {
	SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK,
};

/*
 * Oracle: when set (a2) is NULL, rt_sigprocmask() does not mutate any
 * mask — it just copies the calling thread's current blocked mask
 * (current->blocked, the per-thread sigset_t guarded by siglock) out to
 * oset.  The procfs view of the same fact is /proc/self/status, which
 * exposes current->blocked as "SigBlk:" via proc_pid_status() — also
 * under siglock, formatted via %016lx.  Both views read the same
 * sigset_t through different code paths, so a divergence between the
 * syscall's oset and SigBlk for the same task is its own corruption
 * shape: a torn write to current->blocked, a stale mask after a
 * sigaction race, or a copy_to_user that wrote past/before the live
 * mask.  Mirror of the rt_sigpending procfs oracle pattern.
 *
 * Skip when set != NULL: in that case the syscall mutated current->blocked
 * and oset (if any) holds the *previous* mask, not the live one — racing
 * that against /proc would give false positives.
 */
static void post_rt_sigprocmask(struct syscallrecord *rec)
{
	struct rt_sigprocmask_post_state *snap;
	char procbuf[2048];
	const char *value;
	uint64_t syscall_blocked, proc_blocked;
	sigset_t buf;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, RT_SIGPROCMASK_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	/*
	 * Success gate and per-call output-shape gates hoisted above the
	 * ONE_IN(100) rate limit so the untouched-buffer arm below runs
	 * on every success; the rate limit still guards the expensive
	 * procfs divergence arm at its original 1/100 cadence.
	 */
	if (rec->retval != 0)
		goto out_free;
	if (snap->oset == 0)
		goto out_free;
	if (snap->sigsetsize != KERNEL_SIGSET_SIZE)
		goto out_free;

	/*
	 * Untouched-buffer check: rt_sigprocmask returned success and
	 * oset was non-NULL, but the oset user buffer still byte-for-byte
	 * matches the poison pattern we stamped at sanitise time -- the
	 * kernel never called copy_to_user() into it at all.  Runs on
	 * every success (no ONE_IN gate) because it is a
	 * sizeof(sigset_t) memcmp with no syscall re-issue, same shape
	 * as the times, sysinfo, and get_robust_list oracles.  Bumps
	 * the shared post_handler_untouched_out_buf slot.  Skip when
	 * poison_seed is 0: sanitise refused to stamp (NULL oset or the
	 * writable-pool draw is no longer provably mapped) so there is
	 * no pattern to compare against.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->oset,
					     sizeof(sigset_t),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_free;

	if (snap->set != 0)
		goto out_free;

	if (!post_snapshot_or_skip(&buf,
				   (const void *) snap->oset,
				   sizeof(buf)))
		goto out_free;
	memcpy(&syscall_blocked, &buf, sizeof(syscall_blocked));

	if (proc_status_read(procbuf, sizeof(procbuf)) < 0)
		goto out_free;
	value = proc_status_find_field(procbuf, "SigBlk");
	if (value == NULL)
		goto out_free;
	if (!proc_status_parse_hex_mask(value, &proc_blocked))
		goto out_free;

	if (syscall_blocked != proc_blocked) {
		output(0, "rt_sigprocmask oracle: syscall=0x%016lx but "
		       "/proc/self/status SigBlk=0x%016lx\n",
		       (unsigned long)syscall_blocked,
		       (unsigned long)proc_blocked);
		__atomic_add_fetch(&shm->stats.oracle.rt_sigprocmask_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_rt_sigprocmask = {
	.name = "rt_sigprocmask",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.sanitise = sanitise_rt_sigprocmask,
	.argtype = { [0] = ARG_OP, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "how", [1] = "set", [2] = "oset", [3] = "sigsetsize" },
	.arg_params[0].list = ARGLIST(sigprocmask_how),
	.post = post_rt_sigprocmask,
	.rettype = RET_ZERO_SUCCESS,
};
