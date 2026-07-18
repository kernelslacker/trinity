/*
 * SYSCALL_DEFINE1(sysinfo, struct sysinfo __user *, info)
 */
#include <sys/sysinfo.h>
#include "output-poison.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the one sysinfo input arg plus the poison seed read by the
 * post oracle, captured at sanitise time and consumed by the post handler.
 * Lives in rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning and the
 * post handler running cannot redirect the source memcpy at a foreign user
 * buffer or smear the poison seed against a heap page that happens to
 * still carry a residual pattern from an earlier call.  A poison_seed of
 * 0 means the sanitise-time writability check refused to stamp poison for
 * this call -- the field-diff oracle still runs, the poison check does
 * not.
 */
#define SYSINFO_POST_STATE_MAGIC	0x53595349UL	/* "SYSI" */
struct sysinfo_post_state {
	unsigned long magic;
	unsigned long info;
	uint64_t poison_seed;
};

static void sanitise_sysinfo(struct syscallrecord *rec)
{
	struct sysinfo_post_state *snap;
	void *buf;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a1, sizeof(struct sysinfo));

	/*
	 * Snapshot the one input arg for the post oracle.  Without this
	 * the post handler reads rec->a1 at post-time, when a sibling
	 * syscall may have scribbled the slot: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original info
	 * user-buffer pointer, so the source memcpy would touch a foreign
	 * allocation.  post_state is private to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = SYSINFO_POST_STATE_MAGIC;
	snap->info = rec->a1;
	snap->poison_seed = 0;

	/*
	 * Stamp a per-call poison pattern into the output buffer the kernel
	 * is about to fill.  The post handler feeds the seed back into
	 * check_output_struct(); a byte-identical poison after a success
	 * return means the kernel skipped copy_to_user() entirely or short-
	 * copied and left an uninitialised tail readable in user memory (a
	 * kernel->user infoleak).  Gate on range_readable_user() so a
	 * writable-pool draw that avoid_shared_buffer_out() moved to an
	 * address that is no longer provably mapped -- e.g. a sibling
	 * munmap between allocation and now -- does not SIGSEGV the
	 * sanitiser inside poison_output_struct's byte-walk.  On skip,
	 * poison_seed stays 0 and the post handler no-ops the poison check
	 * while the field-diff oracle still runs against snap->info.  Done
	 * after avoid_shared_buffer_out() so the poison lands on the final
	 * buffer the kernel will see.
	 */
	buf = (void *)(unsigned long) rec->a1;
	if (range_readable_user(buf, sizeof(struct sysinfo)))
		snap->poison_seed = poison_output_struct(buf,
							 sizeof(struct sysinfo),
							 0);

	post_state_install(rec, snap);
}

/*
 * Oracle: sys_sysinfo fills a struct sysinfo from si_meminfo() / si_swapinfo()
 * and a snapshot of avenrun[].  Two independent post checks run against
 * the same success return:
 *
 *   1. Untouched-buffer poison check.  Sanitise stamped a per-call poison
 *      pattern into the output buffer; a byte-identical poison after a
 *      0-retval means the kernel skipped copy_to_user() entirely or
 *      short-copied and left an uninitialised tail readable in user
 *      memory (a kernel->user infoleak).  Runs on every success -- the
 *      check is a ~64-byte memcmp with no re-issue, so it stays cheap
 *      enough to fire every time -- and bumps the shared
 *      post_handler_untouched_out_buf slot.
 *
 *   2. Field-divergence re-read oracle.  Most fields fluctuate every
 *      second (uptime, loads, freeram, sharedram, bufferram, freeswap,
 *      freehigh, procs) and are not useful for re-read comparison.  Four
 *      fields are boot-stable in the absence of memory hot-add or
 *      swapon/swapoff:
 *
 *        totalram  -- fixed at boot, only changes on memory hotplug
 *        totalswap -- only changes on swapon/swapoff
 *        totalhigh -- boot-fixed; 0 on x86_64 (LPAE off)
 *        mem_unit  -- set once at boot; on 64-bit always 1; on 32-bit
 *                     can be scaled by si_swapinfo to fit values in
 *                     unsigned long
 *
 *      Re-issue sysinfo() ourselves and compare only those four fields.
 *      Any mismatch points at one of:
 *        - copy_to_user mis-write: kernel wrote the full struct but the
 *          destination address was wrong / partially mapped, leaving
 *          torn fields in the user buffer.
 *        - mem_unit truncation on the 32-bit-on-64-bit compat path: a
 *          regression in the compat scaler could leave mem_unit==0 or
 *          totalram/totalswap truncated when scaled down to unsigned
 *          long.
 *        - struct layout mismatch between 32-bit user and 64-bit kernel:
 *          adjacent fields shifted, e.g. totalhigh appearing in the
 *          totalram slot.
 *        - memory hotplug torn write: rare but real -- totalram changes
 *          mid-flight while the kernel is still copying.
 *
 *      Sample one in a hundred.  Known benign false-positive sources:
 *        - genuine memory hotplug between the two reads (totalram
 *          changes legitimately).
 *        - swapon/swapoff in another trinity child between the two
 *          reads (totalswap changes legitimately).
 *      At ONE_IN(100) sampling x the ~zero background rate of these
 *      events on a fuzzing host, the counter stays signal-bearing.
 *      Do not early-return on the first mismatch -- log all four
 *      fields' divergences in a single sample so multi-field
 *      corruption is captured.
 *
 * TOCTOU defeat: the one input arg (info) and the poison seed are
 * snapshotted at sanitise time into a heap struct in rec->post_state, so
 * a sibling that scribbles rec->a1 between syscall return and post entry
 * cannot redirect the source memcpy at a foreign user buffer or smear
 * the poison check against an unrelated heap page that happens to still
 * carry a residual pattern.  The user-buffer payload at info is then
 * snapshotted into a stack-local via post_snapshot_or_skip before both
 * the poison check and the field re-read, so a sibling munmap of the
 * writable-pool page between syscall return and our reads degrades to a
 * skipped sample instead of a SIGSEGV.
 */
static void post_sysinfo(struct syscallrecord *rec)
{
	struct sysinfo_post_state *snap;
	struct sysinfo user_view, kernel_view;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, SYSINFO_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	if (snap->info == 0)
		goto out_release;

	if (!post_snapshot_or_skip(&user_view,
				   (const void *)(unsigned long) snap->info,
				   sizeof(user_view)))
		goto out_release;

	/*
	 * Untouched-buffer poison check runs on every success sample the
	 * buffer snapshot succeeded on.  poison_seed of 0 means sanitise
	 * chose not to stamp poison (unwritable pointer) -- skip the check
	 * so "we couldn't poison" is not confused with "kernel didn't
	 * write".  On a match, bump the shared counter; the field-diff
	 * arm below will also flag every field as diverged (first is all
	 * poison, recheck is real), but the shared slot is the cheaper,
	 * no-re-issue signal.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct(&user_view, sizeof(user_view),
				snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_release;

	if (sysinfo(&kernel_view) != 0)
		goto out_release;

	if (user_view.totalram != kernel_view.totalram) {
		output(0, "sysinfo oracle: totalram user=%lu kernel=%lu\n",
		       user_view.totalram, kernel_view.totalram);
		__atomic_add_fetch(&shm->stats.oracle.sysinfo_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
	if (user_view.totalswap != kernel_view.totalswap) {
		output(0, "sysinfo oracle: totalswap user=%lu kernel=%lu\n",
		       user_view.totalswap, kernel_view.totalswap);
		__atomic_add_fetch(&shm->stats.oracle.sysinfo_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
	if (user_view.totalhigh != kernel_view.totalhigh) {
		output(0, "sysinfo oracle: totalhigh user=%lu kernel=%lu\n",
		       user_view.totalhigh, kernel_view.totalhigh);
		__atomic_add_fetch(&shm->stats.oracle.sysinfo_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
	if (user_view.mem_unit != kernel_view.mem_unit) {
		output(0, "sysinfo oracle: mem_unit user=%lu kernel=%lu\n",
		       (unsigned long) user_view.mem_unit,
		       (unsigned long) kernel_view.mem_unit);
		__atomic_add_fetch(&shm->stats.oracle.sysinfo_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_sysinfo = {
	.name = "sysinfo",
	.num_args = 1,
	.argtype = { [0] = ARG_STRUCT_PTR_OUT },
	.argname = { [0] = "info" },
	.sanitise = sanitise_sysinfo,
	.post = post_sysinfo,
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
