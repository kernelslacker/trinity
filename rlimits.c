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

#include "rlimits.h"
#include "trinity.h"

#define NOFILE_TARGET	262144UL
#define AS_TARGET	(8UL * 1024 * 1024 * 1024)
#define NPROC_BASE	128UL
#define NPROC_PER_CHILD	8UL

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

	cap_one(RLIMIT_NOFILE, "NOFILE", (rlim_t) NOFILE_TARGET);
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
