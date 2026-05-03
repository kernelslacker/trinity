/*
 * SYSCALL_DEFINE1(sysinfo, struct sysinfo __user *, info)
 */
#include <string.h>
#include <sys/sysinfo.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_sysinfo(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(struct sysinfo));
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
 * TOCTOU defeat: snapshot the user buffer to a stack-local before the
 * re-call so a sibling thread cannot scribble on rec->a1 between the
 * syscall return and our compare.
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
	struct sysinfo user_view, kernel_view;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval != 0)
		return;

	if (rec->a1 == 0)
		return;

	{
		void *info = (void *)(unsigned long) rec->a1;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a1. */
		if (looks_like_corrupted_ptr(info)) {
			outputerr("post_sysinfo: rejected suspicious info=%p (pid-scribbled?)\n",
				  info);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	memcpy(&user_view, (void *)(unsigned long) rec->a1,
	       sizeof(user_view));

	if (sysinfo(&kernel_view) != 0)
		return;

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
