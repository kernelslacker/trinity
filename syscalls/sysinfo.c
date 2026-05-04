/*
 * SYSCALL_DEFINE1(sysinfo, struct sysinfo __user *, info)
 */
#include <string.h>
#include <sys/sysinfo.h>
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the one sysinfo input arg read by the post oracle, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the source memcpy at a foreign user
 * buffer.
 */
struct sysinfo_post_state {
	unsigned long info;
};

static void sanitise_sysinfo(struct syscallrecord *rec)
{
	struct sysinfo_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer(&rec->a1, sizeof(struct sysinfo));

	/*
	 * Snapshot the one input arg for the post oracle.  Without this
	 * the post handler reads rec->a1 at post-time, when a sibling
	 * syscall may have scribbled the slot: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original info
	 * user-buffer pointer, so the source memcpy would touch a foreign
	 * allocation.  post_state is private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->info = rec->a1;
	rec->post_state = (unsigned long) snap;
}

/*
 * Oracle: sys_sysinfo fills a struct sysinfo from si_meminfo() / si_swapinfo()
 * and a snapshot of avenrun[].  Most fields fluctuate every second
 * (uptime, loads, freeram, sharedram, bufferram, freeswap, freehigh, procs)
 * and are not useful for re-read comparison.  Four fields are boot-stable
 * in the absence of memory hot-add or swapon/swapoff:
 *
 *   totalram  -- fixed at boot, only changes on memory hotplug
 *   totalswap -- only changes on swapon/swapoff
 *   totalhigh -- boot-fixed; 0 on x86_64 (LPAE off)
 *   mem_unit  -- set once at boot; on 64-bit always 1; on 32-bit can be
 *                scaled by si_swapinfo to fit values in unsigned long
 *
 * Re-issue sysinfo() ourselves and compare only those four fields.  Any
 * mismatch points at one of:
 *   - copy_to_user mis-write: kernel wrote the full struct but the
 *     destination address was wrong / partially mapped, leaving torn
 *     fields in the user buffer.
 *   - mem_unit truncation on the 32-bit-on-64-bit compat path: a
 *     regression in the compat scaler could leave mem_unit==0 or
 *     totalram/totalswap truncated when scaled down to unsigned long.
 *   - struct layout mismatch between 32-bit user and 64-bit kernel:
 *     adjacent fields shifted, e.g. totalhigh appearing in the totalram
 *     slot.
 *   - memory hotplug torn write: rare but real -- totalram changes
 *     mid-flight while the kernel is still copying.
 *
 * TOCTOU defeat: the one input arg (info) is snapshotted at sanitise time
 * into a heap struct in rec->post_state, so a sibling that scribbles
 * rec->a1 between syscall return and post entry cannot redirect the
 * source memcpy at a foreign user buffer.  The user-buffer payload at
 * info is then snapshotted into a stack-local before the re-call so a
 * sibling thread cannot scribble it between the original syscall return
 * and our compare.
 *
 * Sample one in a hundred.  Known benign false-positive sources:
 *   - genuine memory hotplug between the two reads (totalram changes
 *     legitimately).
 *   - swapon/swapoff in another trinity child between the two reads
 *     (totalswap changes legitimately).
 * At ONE_IN(100) sampling x the ~zero background rate of these events
 * on a fuzzing host, the counter stays signal-bearing.
 *
 * Do not early-return on the first mismatch -- log all four fields'
 * divergences in a single sample so multi-field corruption is captured.
 */
static void post_sysinfo(struct syscallrecord *rec)
{
	struct sysinfo_post_state *snap =
		(struct sysinfo_post_state *) rec->post_state;
	struct sysinfo user_view, kernel_view;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_sysinfo: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->info == 0)
		goto out_free;

	{
		void *info = (void *)(unsigned long) snap->info;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner info
		 * field.  Reject pid-scribbled info before deref.
		 */
		if (looks_like_corrupted_ptr(rec, info)) {
			outputerr("post_sysinfo: rejected suspicious info=%p (post_state-scribbled?)\n",
				  info);
			goto out_free;
		}
	}

	memcpy(&user_view, (void *)(unsigned long) snap->info,
	       sizeof(user_view));

	if (sysinfo(&kernel_view) != 0)
		goto out_free;

	if (user_view.totalram != kernel_view.totalram) {
		output(0, "sysinfo oracle: totalram user=%lu kernel=%lu\n",
		       user_view.totalram, kernel_view.totalram);
		__atomic_add_fetch(&shm->stats.sysinfo_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
	if (user_view.totalswap != kernel_view.totalswap) {
		output(0, "sysinfo oracle: totalswap user=%lu kernel=%lu\n",
		       user_view.totalswap, kernel_view.totalswap);
		__atomic_add_fetch(&shm->stats.sysinfo_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
	if (user_view.totalhigh != kernel_view.totalhigh) {
		output(0, "sysinfo oracle: totalhigh user=%lu kernel=%lu\n",
		       user_view.totalhigh, kernel_view.totalhigh);
		__atomic_add_fetch(&shm->stats.sysinfo_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
	if (user_view.mem_unit != kernel_view.mem_unit) {
		output(0, "sysinfo oracle: mem_unit user=%lu kernel=%lu\n",
		       (unsigned long) user_view.mem_unit,
		       (unsigned long) kernel_view.mem_unit);
		__atomic_add_fetch(&shm->stats.sysinfo_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_sysinfo = {
	.name = "sysinfo",
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "info" },
	.sanitise = sanitise_sysinfo,
	.post = post_sysinfo,
	.group = GROUP_PROCESS,
};
