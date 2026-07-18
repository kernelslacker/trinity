/*
 * SYSCALL_DEFINE3(sched_getattr, pid_t, pid, struct sched_attr __user *, uattr, unsigned int, size)
 */
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <linux/sched/types.h>
#include <linux/types.h>
#include <string.h>
#include <sys/types.h>
#include "arch.h"
#include "deferred-free.h"
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "struct_catalog.h"
#include "trinity.h"
#include "utils.h"
#include "utils-mem.h"

#include "kernel/sched.h"
#define SCHED_ATTR_SIZE_VER0	48

/*
 * Width of the poison prefix stamped into the user buffer at sanitise
 * time and checked byte-for-byte on a success return.  Sized to the
 * struct sched_attr v0 layout: the kernel's copy_to_user path on
 * retval == 0 always fills at least this prefix (the leading __u32
 * size word plus the v0 fields), so a fully-intact poison pattern
 * post-syscall proves the kernel returned success without writing.
 * Kept well under CHECK_OUTPUT_STRUCT_SNAP_MAX (512) so the helper
 * never truncates the check.
 */
#define SCHED_GETATTR_POISON_SZ	SCHED_ATTR_SIZE_VER0

/*
 * Cap used when struct_arg_lookup() returns no catalog entry for
 * sched_getattr's arg2 -- mirrors STRUCT_PTR_OUT_FALLBACK_SIZE in
 * generate-args.c, which is the actual allocation gen_arg_struct_ptr_out()
 * makes on a catalog miss.  Kept in sync by hand: if the generator's
 * fallback grows, so must this.
 */
#define SCHED_GETATTR_ATTR_FALLBACK_SIZE	256U

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
 *
 * attr_alloc_size is the real allocation size of the buffer at .attr,
 * resolved at sanitise time (catalog struct_size, or the fallback when
 * the catalog misses; bumped to rec->a3 when avoid_shared_buffer_out()
 * redirected to a fresh writable region sized for the fuzzed length).
 * The post oracle's source memcpy MUST clamp to this -- snap->size is
 * the fuzzed size argument the kernel got, not the size of the buffer
 * backing snap->attr, and the two diverge whenever fuzz picks a size
 * larger than the catalog struct.
 */
#define SCHED_GETATTR_POST_STATE_MAGIC	0x5343484741545452UL	/* "SCHGATTR" */
struct sched_getattr_post_state {
	unsigned long magic;
	unsigned long pid;
	unsigned long attr;
	unsigned long size;
	size_t attr_alloc_size;
	uint64_t poison_seed;
};
#endif

static void sanitise_sched_getattr(struct syscallrecord *rec)
{
	unsigned long range = page_size - SCHED_ATTR_SIZE_VER0;
#ifdef HAVE_SYS_SCHED_GETATTR
	struct sched_getattr_post_state *snap;
	const struct struct_desc *desc;
	unsigned long pre_a2;
	size_t attr_alloc_size;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	pre_a2 = rec->a2;
#endif

	rec->a3 = (rnd_modulo_u32(range)) + SCHED_ATTR_SIZE_VER0;
	avoid_shared_buffer_out(&rec->a2, rec->a3);

#ifdef HAVE_SYS_SCHED_GETATTR
	/*
	 * Resolve the actual allocation size of the buffer at rec->a2:
	 *
	 *   - If avoid_shared_buffer_out() redirected (the pointer changed),
	 *     the replacement came from get_writable_address(rec->a3) which
	 *     guarantees a region of at least rec->a3 bytes.
	 *   - Otherwise rec->a2 is still the buffer gen_arg_struct_ptr_out()
	 *     zmalloc'd: desc->struct_size if the catalog has an entry for
	 *     (nr, arg 2), else STRUCT_PTR_OUT_FALLBACK_SIZE bytes (256).
	 *
	 * Snapshotting this at sanitise time keeps the post oracle's source
	 * memcpy from reading past the live allocation when fuzz picks a
	 * size argument (rec->a3 -> snap->size) larger than the buffer the
	 * generator handed the kernel: ASAN otherwise trips on a 256-byte
	 * read out of a 56-byte sched_attr_v0 allocation.
	 */
	if (rec->a2 != pre_a2) {
		attr_alloc_size = (size_t) rec->a3;
	} else {
		desc = struct_arg_lookup(rec->nr, 2, rec->do32bit, rec);
		attr_alloc_size = desc ? (size_t) desc->struct_size
				       : (size_t) SCHED_GETATTR_ATTR_FALLBACK_SIZE;
	}

	/*
	 * Clamp the size argument the kernel sees to the buffer's actual
	 * allocation.  rec->a3 was picked from [SCHED_ATTR_SIZE_VER0,
	 * page_size) independently of the buffer the generator handed the
	 * kernel at rec->a2 -- when the catalog (or fallback) sized that
	 * buffer smaller than rec->a3 (e.g. a 56-byte sched_attr_v0
	 * zmalloc), the kernel's copy_to_user writes min(user_size,
	 * kernel_attr_size) bytes and overruns the live allocation into
	 * adjacent heap-arena objects.  Bounding user_size at sanitise
	 * time preserves the freedom to fuzz across the SCHED_ATTR_SIZE_VER0
	 * .. attr_alloc_size range while keeping the kernel's write inside
	 * the buffer.
	 */
	if ((size_t) rec->a3 > attr_alloc_size)
		rec->a3 = (unsigned long) attr_alloc_size;

	/*
	 * Snapshot all four post-oracle inputs.  Without this the post
	 * handler reads rec->aN at post-time, when a sibling syscall may
	 * have scribbled the slots: looks_like_corrupted_ptr() cannot tell
	 * a real-but-wrong heap address from the original user attr
	 * pointer, so the source memcpy would touch a foreign allocation;
	 * a stomped pid retargets the gettid() self-filter; and a stomped
	 * size word smears the SCHED_ATTR_SIZE_VER0 floor check and the
	 * cpy_len bound used to seed the re-issue.  attr_alloc_size is
	 * resolvable only at sanitise time -- the buffer is on the
	 * deferred-free queue and the catalog descriptor isn't otherwise
	 * threaded through.  post_state is private to the post handler.
	 * Gated on HAVE_SYS_SCHED_GETATTR to mirror the .post body -- on
	 * systems without SYS_sched_getattr the post handler is a no-op
	 * stub and a snapshot only the post handler can free would leak.
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_sched_getattr() will then gate the snap
	 * through post_state_claim_owned() and prove ownership before
	 * dereferencing any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic           = SCHED_GETATTR_POST_STATE_MAGIC;
	snap->pid             = rec->a1;
	snap->attr            = rec->a2;
	snap->size            = rec->a3;
	snap->attr_alloc_size = attr_alloc_size;
	snap->poison_seed     = 0;

	/*
	 * Stamp a per-call poison prefix over the v0 window the kernel
	 * fills on a success return.  The post handler compares the same
	 * SCHED_GETATTR_POISON_SZ bytes on retval == 0; an untouched
	 * pattern means the kernel returned 0 without copy_to_user'ing
	 * into the caller's buffer.  Skip the stamp when rec->a2 is 0
	 * (nothing to write to), when the buffer alloc is smaller than
	 * the prefix (would overrun a short catalog struct), when the
	 * size argument the kernel receives is smaller than the prefix
	 * (kernel would legitimately leave a tail of the poison in
	 * place), or when range_readable_user cannot prove the range is
	 * mapped -- an avoid_shared_buffer_out relocation into a pool
	 * page that has since been munmapped would otherwise SIGSEGV
	 * poison_output_struct's byte-walk.  On skip poison_seed stays
	 * 0 and the post handler no-ops the arm.
	 */
	if (rec->a2 != 0 &&
	    attr_alloc_size >= SCHED_GETATTR_POISON_SZ &&
	    rec->a3 >= SCHED_GETATTR_POISON_SZ &&
	    range_readable_user((void *)(unsigned long) rec->a2,
				SCHED_GETATTR_POISON_SZ))
		snap->poison_seed =
			poison_output_struct((void *)(unsigned long) rec->a2,
					     SCHED_GETATTR_POISON_SZ, 0);

	post_state_install(rec, snap);
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
	struct sched_getattr_post_state *snap;
	unsigned char user_snap[256];
	unsigned char kernel_snap[256];
	__u32 user_size_returned;
	__u32 kernel_size_returned;
	size_t cpy_len, cmp_len;
	int memcmp_result;
	long rc;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, SCHED_GETATTR_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	/*
	 * Both oracles below require a success return.  Gate on retval
	 * first so the poison-writeback arm can run on every successful
	 * call (a bounded prefix memcmp; cheap enough not to sample) and
	 * the heavier equality re-issue arm below is 1/100 sampled.
	 */
	if ((long) rec->retval != 0)
		goto out_free;

	/*
	 * Poison-writeback oracle: check_output_struct_user_or_skip
	 * returns true iff every byte of the v0 prefix still matches the
	 * pattern poison_output_struct stamped at sanitise time.  A match
	 * on a retval == 0 return means the kernel reported success but
	 * skipped copy_to_user across the region it is contractually
	 * required to fill -- torn copy, early-exit before fill, or
	 * mis-wired compat wrapper.  Silent when sanitise refused to
	 * stamp (poison_seed == 0) or snap->attr is NULL.
	 */
	if (snap->attr != 0 && snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->attr,
					     SCHED_GETATTR_POISON_SZ,
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_free;

	if (snap->attr == 0)
		goto out_free;

	if ((pid_t) snap->pid != 0 && (pid_t) snap->pid != gettid())
		goto out_free;

	if (snap->size < SCHED_ATTR_SIZE_VER0)
		goto out_free;

	/*
	 * cpy_len bound by THREE inputs:
	 *   - snap->size:           the size argument the kernel was given,
	 *                           caps how many bytes the kernel can have
	 *                           legitimately written into the user buffer.
	 *   - sizeof(user_snap):    the local stack buffer the snapshot lands in.
	 *   - snap->attr_alloc_size: the real allocation backing snap->attr.
	 *                           snap->size is fuzz-chosen and routinely
	 *                           exceeds the buffer's actual size (e.g. a
	 *                           256-byte size argument over a 56-byte
	 *                           sched_attr_v0 allocation).  Without this
	 *                           bound memcpy reads past the live region
	 *                           and ASAN reports an out-of-bounds load.
	 */
	cpy_len = (size_t) snap->size;
	if (cpy_len > sizeof(user_snap))
		cpy_len = sizeof(user_snap);
	if (cpy_len > snap->attr_alloc_size)
		cpy_len = snap->attr_alloc_size;
	/*
	 * After the alloc-size clamp cpy_len can drop below the V0 floor
	 * (catalog struct_size shrank under us, fallback path with a tiny
	 * desc, etc.).  The kernel never writes less than V0, so a
	 * truncated source cannot back a meaningful comparison; also keeps
	 * the leading-size memcpy below from reading uninitialised stack
	 * when cpy_len < sizeof(__u32).
	 */
	if (cpy_len < SCHED_ATTR_SIZE_VER0)
		goto out_free;
	if (!post_snapshot_or_skip(user_snap,
				   (const void *)(unsigned long) snap->attr,
				   cpy_len))
		goto out_free;
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
		__atomic_add_fetch(&shm->stats.oracle.sched_getattr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
#else
	(void) rec;
#endif
}

struct syscallentry syscall_sched_getattr = {
	.name = "sched_getattr",
	.group = GROUP_SCHED,
	.num_args = 4,
	.argtype = { [0] = ARG_PID, [1] = ARG_STRUCT_PTR_OUT, [2] = ARG_STRUCT_SIZE, [3] = ARG_LIST },
	.argname = { [0] = "pid", [1] = "param", [2] = "size", [3] = "flags" },
	.arg_params[3].list = ARGLIST(sched_getattr_flags),
	.sanitise = sanitise_sched_getattr,
	.post = post_sched_getattr,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
