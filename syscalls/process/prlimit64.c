/*
 * SYSCALL_DEFINE4(prlimit64, pid_t, pid, unsigned int, resource,
	 const struct rlimit64 __user *, new_rlim,
	 struct rlimit64 __user *, old_rlim)
 */
#include <stdbool.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include "arch.h"
#include "deferred-free.h"
#include "output-poison.h"
#include "pids.h"
#include "random.h"
#include "rlimit-safe.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/resource.h"
#if defined(SYS_prlimit64) || defined(__NR_prlimit64)
#ifndef SYS_prlimit64
#define SYS_prlimit64 __NR_prlimit64
#endif
#define HAVE_SYS_PRLIMIT64 1
#endif

#ifdef HAVE_SYS_PRLIMIT64
/*
 * Snapshot of the four prlimit64 input args plus the poison seed read
 * by the post oracle, captured at sanitise time and consumed by the
 * post handler.  Lives in rec->post_state, a slot the syscall ABI does
 * not expose, so a sibling syscall scribbling rec->aN between the
 * syscall returning and the post handler running cannot redirect the
 * oracle at a foreign old_rlim buffer, retarget the pid self-filter,
 * smear the resource bound used to gate the re-issue, or smear the
 * poison seed against a heap page that happens to still carry a
 * residual pattern from an earlier call.  A poison_seed of 0 means the
 * sanitise-time writability check refused to stamp poison for this
 * call (NULL old_rlim, or the range gate rejected the address) and the
 * post handler must no-op the untouched-buffer check.
 */
#define PRLIMIT64_POST_STATE_MAGIC	0x50524C36UL	/* "PRL6" */
struct prlimit64_post_state {
	unsigned long magic;
	unsigned long pid;
	unsigned long resource;
	unsigned long new_rlim;
	unsigned long old_rlim;
	uint64_t poison_seed;
};
#endif

static unsigned long rlimit_resources[] = {
	RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_DATA, RLIMIT_STACK,
	RLIMIT_CORE, RLIMIT_RSS, RLIMIT_NPROC, RLIMIT_NOFILE,
	RLIMIT_MEMLOCK, RLIMIT_AS, RLIMIT_LOCKS, RLIMIT_SIGPENDING,
	RLIMIT_MSGQUEUE, RLIMIT_NICE, RLIMIT_RTPRIO,
#ifdef RLIMIT_RTTIME
	RLIMIT_RTTIME,
#endif
};

/*
 * Trinity-owned pid set.  prlimit64 treats pid 0 as "current process",
 * mypid() / cached_pid is the explicit self path, mainpid is the
 * trinity main process, and pids[] holds every sibling fuzz child.
 * Lowering a fragile rlimit against any of these self-poisons us; the
 * kernel's per-resource legality gate does not catch it because the
 * call is genuinely legal -- the damage lands on our own runtime, not
 * the kernel.  setrlimit has no pid argument (always self), so this
 * helper stays local to prlimit64.
 */
static bool pid_is_harness_owned(pid_t pid)
{
	if (pid == 0 || pid == mypid() || pid == mainpid)
		return true;
	return find_childno(pid) != CHILD_NOT_FOUND;
}

static rlim64_t random_rlim64(void)
{
	switch (rnd_modulo_u32(5)) {
	case 0: return RLIM64_INFINITY;
	case 1: return 0;
	case 2: return 1 + (rnd_modulo_u32(1024));
	case 3: return (rlim64_t) page_size * (1 + (rnd_modulo_u32(256)));
	default: return rand32();
	}
}

/*
 * Self-poison guard.  prlimit64 against a trinity-owned pid with a
 * harness-fragile resource lowers our own CPU / NOFILE / AS /
 * DATA / STACK / RSS / MEMLOCK -- the kernel accepts the call as
 * legal (the safe-dictionary draws are cur<=max + within per-
 * resource bounds), but the immediate downstream effect on the
 * harness child is mprotect-RW returning ENOMEM in deferred_free,
 * the heap_bounds_init /proc/self/maps open returning EMFILE, or
 * (for a CPU {0,0} cap) update_rlimit_cpu() arming an immediate
 * posix-cpu-timer SIGKILL.  In the non-CPU cases the child does
 * not crash; it limps on with broken heap-tracking and fd
 * machinery for the rest of its life (silent coverage loss).
 * Re-roll the resource to a non-fragile one for harness targets,
 * keeping the full safe/random value range against FSIZE / NPROC /
 * NICE / RTPRIO / LOCKS / SIGPENDING / MSGQUEUE / CORE.  Full-
 * range fragile-resource fuzzing (incl. CPU {0,0}) is preserved
 * for the non-harness "random nearby pid" bucket above, where
 * the tiny-limit kernel coverage path actually wants to land.
 */
static void sanitise_prlimit64_guard_resource(struct syscallrecord *rec)
{
	if (pid_is_harness_owned((pid_t) rec->a1) &&
	    resource_is_fragile(rec->a2))
		rec->a2 = pick_nonfragile_rlimit_resource(
				rlimit_resources,
				ARRAY_SIZE(rlimit_resources));
}

/*
 * Per-resource safe-limit bias.  The framework picks rec->a2 from
 * rlimit_resources[] (a real RLIMIT_*); fold in three buckets:
 *
 *   ~70% safe dictionary draw: pull (cur, max) from the per-resource
 *        table so the universal cur<=max gate and the per-resource
 *        legality bounds (RLIMIT_NICE 1..40, RLIMIT_RTPRIO 0..99,
 *        RLIMIT_NOFILE <= sysctl_nr_open, ...) both pass, letting the
 *        deeper resource-specific handlers actually run.
 *   ~20% real resource, random values: keep the validation path warm
 *        so the cur<=max / privileged-max checks themselves stay
 *        exercised.
 *   ~10% pure-random resource and values: long-tail coverage for the
 *        RLIMIT_* enum boundary and the early `resource >= RLIM_NLIMITS`
 *        rejection.  Bucket-7/9 re-pick the resource; gate those
 *        picks through the harness-fragile filter too so a re-roll
 *        does not undo the self-poison guard above.
 */
static void sanitise_prlimit64_fill_rlim(struct syscallrecord *rec,
					 struct rlimit64 *rlim)
{
	unsigned int bucket = rnd_modulo_u32(10);
	unsigned long long safe_cur, safe_max;
	bool harness_target = pid_is_harness_owned((pid_t) rec->a1);

	if (bucket < 7 &&
	    rlimit_pick_safe_pair((unsigned int) rec->a2,
				  &safe_cur, &safe_max) == 0) {
		rlim->rlim_cur = (rlim64_t) safe_cur;
		rlim->rlim_max = (rlim64_t) safe_max;
	} else {
		if (bucket >= 9)
			rec->a2 = harness_target
				? pick_nonfragile_rlimit_resource(
					rlimit_resources,
					ARRAY_SIZE(rlimit_resources))
				: rand32();
		else if (bucket >= 7)
			rec->a2 = harness_target
				? pick_nonfragile_rlimit_resource(
					rlimit_resources,
					ARRAY_SIZE(rlimit_resources))
				: random_rlimit_resource(
					rlimit_resources,
					ARRAY_SIZE(rlimit_resources));

		rlim->rlim_cur = random_rlim64();
		rlim->rlim_max = random_rlim64();

		/* Half the time, enforce cur <= max for valid calls. */
		if (RAND_BOOL() && rlim->rlim_cur > rlim->rlim_max)
			rlim->rlim_cur = rlim->rlim_max;
	}
}

/* Fill struct rlimit64 with interesting boundary values. */
static void sanitise_prlimit64(struct syscallrecord *rec)
{
	struct rlimit64 *rlim;
#ifdef HAVE_SYS_PRLIMIT64
	struct prlimit64_post_state *snap;

	rec->post_state = 0;
#endif

	rlim = (struct rlimit64 *) get_writable_address(sizeof(*rlim));
	if (rlim == NULL)
		return;

	/*
	 * pid (a1): ARG_PID via get_pid() already biases self/child heavy.
	 * A small bucket retargets at a "random nearby pid" so the kernel's
	 * privilege-check path (ptrace_may_access -> __ptrace_may_access)
	 * stays exercised against PIDs we are unlikely to own.  Resolve
	 * this before resource selection so the harness-owned guard below
	 * sees the real target.
	 */
	if (ONE_IN(20))
		rec->a1 = (unsigned long)(int)(mypid() +
			(int) rnd_modulo_u32(128) - 64);

	sanitise_prlimit64_guard_resource(rec);

	sanitise_prlimit64_fill_rlim(rec, rlim);

	rec->a3 = (unsigned long) rlim;

	/*
	 * new_rlim (a3) is the curated input the kernel reads.  ARG_ADDRESS
	 * slots are subject to the post-sanitise blanket address scrub, which
	 * relocates the pointer to a fresh pool page; the plain _out variant
	 * would publish the new pointer without the curated bytes and the
	 * kernel would read pool garbage.  _inout relocates AND memcpys the
	 * payload, so the scrub no-ops on a3 and the kernel sees the real
	 * (rlim_cur, rlim_max) pair we built above.
	 */
	avoid_shared_buffer_inout(&rec->a3, sizeof(struct rlimit64));

	/*
	 * old_rlim (a4) is the kernel's writeback target for the previous
	 * limit values: ARG_ADDRESS draws from the random pool, so a fuzzed
	 * pointer can land inside an alloc_shared region.  Scrub it.
	 */
	avoid_shared_buffer_out(&rec->a4, sizeof(struct rlimit64));

#ifdef HAVE_SYS_PRLIMIT64
	/*
	 * Snapshot the four input args for the post oracle.  Without this
	 * the post handler reads rec->aN at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original
	 * old_rlim pointer, the pid self-filter would resolve against a
	 * scribbled value, and the resource bound check could be smeared
	 * past RLIMIT_NLIMITS.  post_state is private to the post handler.
	 * Gated on HAVE_SYS_PRLIMIT64 to mirror the .post registration --
	 * on systems without SYS_prlimit64 the post handler is not
	 * registered and a snapshot only the post handler can free would
	 * leak.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic     = PRLIMIT64_POST_STATE_MAGIC;
	snap->pid       = rec->a1;
	snap->resource  = rec->a2;
	snap->new_rlim  = rec->a3;
	snap->old_rlim  = rec->a4;

	/*
	 * Stamp a per-call poison pattern into the old_rlim user buffer
	 * the kernel is about to fill.  The post handler feeds the seed
	 * back into check_output_struct(); a byte-identical poison after
	 * retval == 0 means the kernel returned success without writing
	 * old_rlim -- prlimit64 promises to fill the 16-byte struct
	 * rlimit64 whenever old_rlim is non-NULL, in both mode-A (new
	 * limit + read old) and mode-B (pure read).  Gate on non-NULL
	 * a4 -- old_rlim is nullable (ARG_ADDRESS) -- and then on
	 * range_readable_user() so a pool draw that landed at an address
	 * that is no longer provably mapped does not SIGSEGV the
	 * sanitiser inside poison_output_struct's byte-walk.  On skip,
	 * poison_seed stays 0 (zmalloc_tracked cleared it) and the post
	 * handler no-ops the poison check.
	 */
	if (rec->a4 != 0) {
		void *old_buf = (void *)(unsigned long) rec->a4;

		if (range_readable_user(old_buf, sizeof(struct rlimit64)))
			snap->poison_seed = poison_output_struct(old_buf,
					sizeof(struct rlimit64), 0);
	}

	post_state_install(rec, snap);
#endif
}

/*
 * Oracle: prlimit64(pid, resource, new_rlim, old_rlim) has two modes.
 * When new_rlim != NULL the call MUTATES task->signal->rlim[resource], so
 * a re-issue equality check is meaningless.  When new_rlim == NULL the
 * call is a pure read of the current (rlim_cur, rlim_max) pair, sourced
 * from task->signal->rlim[] under task_lock; for a self-target (pid == 0
 * or pid == gettid()) the only mutator is a parallel prlimit64 / setrlimit
 * against ourselves -- a same-task re-issue ~150ms later through the same
 * code path must produce a byte-identical (rlim_cur, rlim_max) pair unless
 * one of:
 *
 *   - copy_to_user mis-write past or before the rlimit64 user slot.
 *   - 32-on-64 compat sign-extension on either 64-bit limit field.
 *   - Torn write from a parallel setrlimit/prlimit64 against ourselves
 *     (cred_guard_mutex starvation lets two writers interleave).
 *   - Stale rcu read of task->signal after a parallel exec walked through
 *     setup_new_exec()/credential install.
 *   - Sibling-thread scribble of either rec->aN or the user buffer between
 *     syscall return and our post-hook re-read.
 *
 * Mode A (new_rlim != NULL) is gated out by the rec->a3 != 0 check: the
 * sanitiser always wires a non-NULL rlim into a3 today, but if a future
 * sanitiser revision starts emitting mode-B calls the oracle picks them up
 * automatically.  Other-pid targets (pid != 0 && pid != gettid()) are
 * gated out -- another task's limits can be legitimately mutated by a
 * sibling between our two reads, which would surface as a benign
 * divergence storm.  RLIMIT_NLIMITS is checked defensively in case a
 * future kernel/glibc adds resource constants the sanitiser table does not
 * yet know about.
 *
 * TOCTOU defeat: the four input args (pid, resource, new_rlim, old_rlim)
 * are snapshotted at sanitise time into a heap struct in rec->post_state,
 * so a sibling that scribbles rec->aN between syscall return and post
 * entry cannot redirect the oracle at a foreign old_rlim, retarget the
 * pid self-filter, or smear the resource bound that gates the re-issue.
 * The rlimit64 payload at *old_rlim is then snapshotted into a stack-local
 * before re-issuing, and the re-call writes into a fresh private stack
 * buffer (NOT the snapshot's old_rlim -- a sibling could mutate the user
 * buffer itself mid-syscall and forge a clean compare).
 *
 * Snap gating: the snap is registered in the ownership table at install
 * time and the post handler gates entry through post_state_claim_owned(),
 * which runs the canonical shape -> ownership -> magic check before any
 * inner-field deref -- a stale same-type snapshot still readable in the
 * deferred-free queue, or a sibling scribble of rec->post_state with a
 * heap-shaped pointer at a foreign allocation, is rejected before the
 * pid self-filter, resource bound, old_rlim deref, or the re-issue are
 * touched.
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  Per-field bumps with no early-return so simultaneous
 * rlim_cur+rlim_max corruption surfaces in a single sample.
 *
 * False-positive sources at ONE_IN(100):
 *   - Sibling prlimit64(self, ..., new_rlim != NULL, ...) between the two
 *     reads: rc != 0 path swallows the common case (concurrent prlimit on
 *     self serialises through task->signal->cred_guard_mutex and one of
 *     the two reads will see EAGAIN/EPERM).  When BOTH reads succeed and
 *     diverge, that is a real signal of cred-mutex starvation.
 *   - Resource not supported by kernel: returns -EINVAL on the first call,
 *     swallowed by the retval != 0 gate.
 *   - Defensive RLIMIT_NLIMITS bail covers any future RLIMIT_* enum drift.
 */
#ifdef HAVE_SYS_PRLIMIT64
static void post_prlimit64(struct syscallrecord *rec)
{
	struct prlimit64_post_state *snap =
		post_state_claim_owned(rec, PRLIMIT64_POST_STATE_MAGIC,
				       __func__);
	struct rlimit64 first_rlim;
	struct rlimit64 recheck_rlim;
	long rc;

	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_free;

	/*
	 * Untouched-buffer poison check.  prlimit64 is contracted to
	 * fill the 16-byte old_rlim struct on any success where
	 * old_rlim is non-NULL -- true for both mode-A (new_rlim set)
	 * and mode-B (pure read) -- so this gate is INDEPENDENT of the
	 * new_rlim == 0 gate that keys the value-oracle re-issue
	 * below.  A byte-identical poison after success means the
	 * kernel returned 0 without writing old_rlim.  Not sampled by
	 * ONE_IN(100): the check is a 16-byte memcmp with no syscall
	 * re-issue, so it stays cheap enough to fire on every success.
	 * Guarded on poison_seed so the sanitise-refused-to-stamp path
	 * (NULL a4 or the range gate rejected the address) is not
	 * confused with "kernel didn't write".
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((const void *)(unsigned long) snap->old_rlim,
					     sizeof(struct rlimit64),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_free;

	if (snap->new_rlim != 0)
		goto out_free;

	if (snap->old_rlim == 0)
		goto out_free;

	if (snap->pid != 0 &&
	    snap->pid != (unsigned long) syscall(SYS_gettid))
		goto out_free;

	if (snap->resource >= RLIMIT_NLIMITS)
		goto out_free;

	if (!post_snapshot_or_skip(&first_rlim,
				   (const void *)(unsigned long) snap->old_rlim,
				   sizeof(first_rlim)))
		goto out_free;

	memset(&recheck_rlim, 0, sizeof(recheck_rlim));
	rc = syscall(SYS_prlimit64, (pid_t) snap->pid,
		     (unsigned int) snap->resource, NULL, &recheck_rlim);
	if (rc != 0)
		goto out_free;

	if (first_rlim.rlim_cur != recheck_rlim.rlim_cur) {
		output(0,
		       "[oracle:prlimit64] rlim_cur %llu vs %llu (resource=%u)\n",
		       (unsigned long long) first_rlim.rlim_cur,
		       (unsigned long long) recheck_rlim.rlim_cur,
		       (unsigned int) snap->resource);
		__atomic_add_fetch(&shm->stats.oracle.prlimit64_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

	if (first_rlim.rlim_max != recheck_rlim.rlim_max) {
		output(0,
		       "[oracle:prlimit64] rlim_max %llu vs %llu (resource=%u)\n",
		       (unsigned long long) first_rlim.rlim_max,
		       (unsigned long long) recheck_rlim.rlim_max,
		       (unsigned int) snap->resource);
		__atomic_add_fetch(&shm->stats.oracle.prlimit64_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}
#endif

struct syscallentry syscall_prlimit64 = {
	.name = "prlimit64",
	.num_args = 4,
	.argtype = { [0] = ARG_PID, [1] = ARG_OP, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS },
	.argname = { [0] = "pid", [1] = "resource", [2] = "new_rlim", [3] = "old_rlim" },
	.arg_params[1].list = ARGLIST(rlimit_resources),
	.group = GROUP_PROCESS,
	.sanitise = sanitise_prlimit64,
#ifdef HAVE_SYS_PRLIMIT64
	.post = post_prlimit64,
#endif
	.rettype = RET_ZERO_SUCCESS,
};
