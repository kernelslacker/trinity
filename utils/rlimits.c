/*
 * Startup rlimit caps.  Defense-in-depth bound on trinity's
 * process-wide resource use so a runaway fuzzer-side bug cannot
 * walk the host into a global OOM cascade before any kernel-side
 * limit kicks in.
 *
 * Apply soft = min(current_soft, our_target); leave the hard limit
 * alone unless we are still root (in which case we set hard =
 * our_target so a subsequent unprivileged drop cannot raise back
 * over the cap).  Any setrlimit failure logs a warning and
 * continues -- the kernel may have stricter limits already, which
 * is the better outcome.
 */

#include <errno.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "params.h"
#include "rlimits.h"
#include "trinity.h"

#define NOFILE_TARGET	262144UL
#define AS_TARGET	(8UL * 1024 * 1024 * 1024)
#define NPROC_BASE	128UL
#define NPROC_PER_CHILD	8UL

/*
 * Raise RLIMIT_MEMLOCK to infinity for the trinity process tree.
 * Children inherit rlimits across fork, so a single parent-side raise
 * gives every fuzz child enough headroom for mlockall(MCL_CURRENT |
 * MCL_FUTURE) under ASAN.  Without this, libasan's TB-scale shadow
 * extension mmap -EAGAINs once the per-process MEMLOCK cap is hit
 * while MCL_FUTURE is set, and the child aborts.
 *
 * Raising the hard limit needs CAP_SYS_RESOURCE; the trinity binary
 * gets it via `make setcap`.  Best-effort: if the cap is absent the
 * setrlimit fails EPERM, we log once and continue with the inherited
 * limit.  Trinity must still run without setcap (the mlock_pressure
 * childop's existing ASAN gate keeps coverage workable on the inherited
 * limit).
 *
 * Co-located with the soft-cap helpers below despite being a *raise*:
 * this is the single point where the process-tree's MEMLOCK limit is
 * set before fork, and the raise reuses CAP_SYS_RESOURCE that the
 * sibling caps don't need.  The cap is dropped along with everything
 * else by the capset()-to-empty in init_child_setup_sandbox().
 */
static void raise_memlock_unlimited(void)
{
	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };

	if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
		output(0, "rlimit: setrlimit(MEMLOCK, unlimited) failed: %s "
			  "(CAP_SYS_RESOURCE missing? run `make setcap`); "
			  "continuing with inherited limit\n",
			  strerror(errno));
		return;
	}

	output(0, "rlimit: MEMLOCK=unlimited\n");
}

static void cap_one(int resource, const char *name, rlim_t target)
{
	struct rlimit rl;

	if (getrlimit(resource, &rl) != 0) {
		output(0, "rlimit: getrlimit(%s) failed: %s\n",
			name, strerror(errno));
		return;
	}

	if (rl.rlim_cur == RLIM_INFINITY || rl.rlim_cur > target)
		rl.rlim_cur = target;

	if (geteuid() == 0)
		rl.rlim_max = target;

	if (rl.rlim_max != RLIM_INFINITY && rl.rlim_cur > rl.rlim_max)
		rl.rlim_cur = rl.rlim_max;

	if (setrlimit(resource, &rl) != 0) {
		output(0, "rlimit: setrlimit(%s, cur=%lu max=%lu) failed: %s\n",
			name, (unsigned long) rl.rlim_cur,
			(unsigned long) rl.rlim_max, strerror(errno));
		return;
	}

	output(0, "rlimit: %s=%lu\n", name, (unsigned long) rl.rlim_cur);
}

void init_rlimits(unsigned int nr_children)
{
	rlim_t nproc_target = (rlim_t) nr_children * NPROC_PER_CHILD + NPROC_BASE;

	raise_memlock_unlimited();

	cap_one(RLIMIT_NOFILE, "NOFILE", (rlim_t) NOFILE_TARGET);

	/*
	 * RLIMIT_NPROC is per-UID -- it counts every process the invoking
	 * user already owns, not just trinity's.  The absolute target here is
	 * sized for a dedicated host; on a shared box where the user already
	 * runs more than nproc_target processes the cap strangles trinity the
	 * instant it spawns a thread or forks a child (EAGAIN).  The cap is
	 * here to bound the fork-storm / pidfd-storm childops -- and --dry-run
	 * gates every childop off and executes no fuzzed clone/fork, so the
	 * child count is already bounded by the fixed worker pool and the cap
	 * is pure downside.  Skip it under --dry-run.
	 */
	if (dry_run)
		output(0, "rlimit: NPROC=skipped (--dry-run gates fork-storm childops)\n");
	else
		cap_one(RLIMIT_NPROC, "NPROC", nproc_target);

	/* ASAN reserves TB-scale virtual address space for its shadow
	 * tables.  An RLIMIT_AS cap of a few GB starves ASAN's mmap and
	 * trinity aborts at init before the first fuzz iteration.  Skip
	 * the AS cap on sanitizer builds; the cgroup self-cap still bounds
	 * RSS+swap on the production build. */
#ifdef __SANITIZE_ADDRESS__
	output(0, "rlimit: AS=skipped (ASAN build needs unlimited VA)\n");
#else
	cap_one(RLIMIT_AS, "AS", (rlim_t) AS_TARGET);
#endif
}
