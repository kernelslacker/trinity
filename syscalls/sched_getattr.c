/*
 * SYSCALL_DEFINE3(sched_getattr, pid_t, pid, struct sched_attr __user *, uattr, unsigned int, size)
 */
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <linux/sched/types.h>
#include <linux/types.h>
#include "arch.h"
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define SCHED_ATTR_SIZE_VER0	48

#ifndef SCHED_GETATTR_FLAG_DL_DYNAMIC
#define SCHED_GETATTR_FLAG_DL_DYNAMIC	0x01
#endif

#if defined(SYS_sched_getattr) || defined(__NR_sched_getattr)
#ifndef SYS_sched_getattr
#define SYS_sched_getattr __NR_sched_getattr
#endif
#define HAVE_SYS_SCHED_GETATTR 1
#endif

static unsigned long sched_getattr_flags[] = {
	0, SCHED_GETATTR_FLAG_DL_DYNAMIC,
};

#ifdef HAVE_SYS_SCHED_GETATTR
/*
 * Snapshot of the three sched_getattr input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot retarget the pid self-filter, redirect the
 * source memcpy at a foreign user buffer, or smear the size word that
 * bounds the comparison.
 */
struct sched_getattr_post_state {
	unsigned long pid;
	unsigned long attr;
	unsigned long size;
};
#endif

static void sanitise_sched_getattr(struct syscallrecord *rec)
{
	unsigned long range = page_size - SCHED_ATTR_SIZE_VER0;
#ifdef HAVE_SYS_SCHED_GETATTR
	struct sched_getattr_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;
#endif

	rec->a3 = (rand() % range) + SCHED_ATTR_SIZE_VER0;
	avoid_shared_buffer(&rec->a2, rec->a3);

#ifdef HAVE_SYS_SCHED_GETATTR
	/*
	 * Snapshot all three input args for the post oracle.  Without this
	 * the post handler reads rec->aN at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * attr pointer, so the source memcpy would touch a foreign
	 * allocation; a stomped pid retargets the gettid() self-filter; and
	 * a stomped size word smears the SCHED_ATTR_SIZE_VER0 floor check
	 * and the cpy_len bound used to seed the re-issue.  post_state is
	 * private to the post handler.  Gated on HAVE_SYS_SCHED_GETATTR to
	 * mirror the .post body -- on systems without SYS_sched_getattr the
	 * post handler is a no-op stub and a snapshot only the post handler
	 * can free would leak.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->pid  = rec->a1;
	snap->attr = rec->a2;
	snap->size = rec->a3;
	rec->post_state = (unsigned long) snap;
#endif
}

/*
 * Oracle: sched_getattr(pid, uattr, size, flags) reads the target task's
 * scheduling attributes (policy, nice/priority, deadline runtime/deadline/
 * period, util_min/util_max) from task_struct fields and copies a struct
 * sched_attr out to user memory.  When pid == 0 the kernel resolves the
 * target to the calling task; the underlying task_struct fields only mutate
 * via sched_setattr (or cgroup-driven deadline changes), so a same-task read
 * re-issued ~150ms later through the same code path must produce a byte-
 * identical struct sched_attr unless one of:
 *
 *   - copy_to_user mis-write past or before the live struct sched_attr slot
 *     (partial write, wrong-offset fill, residual stack data).
 *   - 32-bit-on-64-bit compat sign-extension on the u64 sched_runtime /
 *     sched_deadline / sched_period words.
 *   - struct-layout mismatch shifting sched_period into the sched_deadline
 *     slot, on a kernel/glibc skew.
 *   - sibling-thread scribble of the user receive buffer between syscall
 *     return and our post-hook re-read.
 *   - stale rcu read of task->dl.{runtime,deadline,period} after a parallel
 *     sched_setattr against a different task that aliases through a stale
 *     rcu pointer.
 *
 * Restrict to self (pid == 0 or pid == gettid()): cross-target sampling
 * races sched_setattr from siblings, cgroup migration, and nice changes
 * driven by other children, all of which legitimately mutate the result and
 * would surface as false divergence.  The caller's own sched_setattr between
 * the two reads is the only legitimate same-task mutator and is vanishingly
 * rare in trinity workload at the 1/100 sample rate.
 *
 * TOCTOU defeat: the three input args (pid, attr, size) are snapshotted at
 * sanitise time into a heap struct in rec->post_state, so a sibling that
 * scribbles rec->aN between syscall return and post entry cannot retarget
 * the pid self-filter, redirect the source memcpy at a foreign user buffer,
 * or smear the size word that bounds the comparison.  The user buffer at
 * snap->attr is still user memory a sibling can scribble between calls, so
 * snapshot up to min(snap->size, sizeof(user_snap)) bytes into a stack-local
 * buffer before re-issuing.  The re-call uses a fresh private stack buffer
 * (do NOT pass snap->attr -- a sibling could mutate it mid-syscall and
 * forge a clean compare).  Pass the FULL kernel_snap size so the kernel
 * writes whatever it would write at maximum size and reflects that back in
 * the leading size word.
 *
 * The audit row says 'stable equality' on a2; flags drives which fields
 * the kernel populates (DL_DYNAMIC etc), so a divergence on the canonical-
 * baseline read with flags=0 is interesting independently of any flag drift
 * on the original call.  Use flags=0 for the re-issue.
 *
 * Reject undersize requests (snap->size < SCHED_ATTR_SIZE_VER0): the kernel
 * itself rejects them with E2BIG/EINVAL, so the original retval == 0 gate
 * already excludes them, but be defensive.  An rc != 0 re-call is treated
 * as 'give up' (the task may have been the target of a sched_setattr in
 * between, or hit some other transient).  Compare both the leading size
 * word (kernel-written, must match) and the first cmp_len bytes of the
 * struct payload, but bump the anomaly counter only once per divergent
 * sample.  Sample one in a hundred to stay in line with the rest of the
 * oracle family.
 */
static void post_sched_getattr(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_SCHED_GETATTR
	struct sched_getattr_post_state *snap =
		(struct sched_getattr_post_state *) rec->post_state;
	unsigned char user_snap[256];
	unsigned char kernel_snap[256];
	__u32 user_size_returned;
	__u32 kernel_size_returned;
	size_t cpy_len, cmp_len;
	int memcmp_result;
	long rc;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_sched_getattr: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->attr == 0)
		goto out_free;

	if ((pid_t) snap->pid != 0 && (pid_t) snap->pid != gettid())
		goto out_free;

	if (snap->size < SCHED_ATTR_SIZE_VER0)
		goto out_free;

	{
		void *uattr = (void *)(unsigned long) snap->attr;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * field.  Reject pid-scribbled attr before deref.
		 */
		if (looks_like_corrupted_ptr(uattr)) {
			outputerr("post_sched_getattr: rejected suspicious uattr=%p (post_state-scribbled?)\n",
				  uattr);
			__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
			goto out_free;
		}
	}

	cpy_len = (size_t) snap->size;
	if (cpy_len > sizeof(user_snap))
		cpy_len = sizeof(user_snap);
	memcpy(user_snap, (const void *)(unsigned long) snap->attr, cpy_len);
	memcpy(&user_size_returned, user_snap, sizeof(user_size_returned));

	memset(kernel_snap, 0, sizeof(kernel_snap));
	rc = syscall(SYS_sched_getattr, 0, kernel_snap,
		     (unsigned int) sizeof(kernel_snap), 0u);
	if (rc != 0)
		goto out_free;

	memcpy(&kernel_size_returned, kernel_snap, sizeof(kernel_size_returned));

	cmp_len = user_size_returned;
	if (kernel_size_returned < cmp_len)
		cmp_len = kernel_size_returned;
	if (cpy_len < cmp_len)
		cmp_len = cpy_len;
	if (sizeof(kernel_snap) < cmp_len)
		cmp_len = sizeof(kernel_snap);

	memcmp_result = memcmp(user_snap, kernel_snap, cmp_len);

	if (memcmp_result != 0 || user_size_returned != kernel_size_returned) {
		output(0,
		       "[oracle:sched_getattr] size %u vs %u cmp_len %zu memcmp_diff %d\n",
		       user_size_returned, kernel_size_returned,
		       cmp_len, memcmp_result);
		__atomic_add_fetch(&shm->stats.sched_getattr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
#else
	(void) rec;
#endif
}

struct syscallentry syscall_sched_getattr = {
	.name = "sched_getattr",
	.group = GROUP_SCHED,
	.num_args = 4,
	.argtype = { [0] = ARG_PID, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "pid", [1] = "param", [2] = "size", [3] = "flags" },
	.arg_params[3].list = ARGLIST(sched_getattr_flags),
	.sanitise = sanitise_sched_getattr,
	.post = post_sched_getattr,
};
