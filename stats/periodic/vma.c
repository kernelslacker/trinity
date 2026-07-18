
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "arch.h"
#include "arg-len-semantics.h"
#include "breadcrumb_ring.h"
#include "child-api.h"
#include "cmp_hints.h"
#include "cred_throttle.h"
#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "reach-band.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "version.h"

/*
 * Count newline-terminated lines in @path.  Returns -1 on open failure
 * (caller skips the slot) and the line count otherwise.  Each completed
 * /proc/<pid>/maps line is one VMA in the target's address space, so the
 * line count is the VMA count without the cost of parsing the address /
 * permission / pathname columns we don't care about here.  Anchoring on
 * '\n' avoids over-counting when a single maps line exceeds the read
 * buffer (rare but possible -- there's no kernel-side cap on the trailing
 * pathname column) and fgets returns the tail in a follow-up call.
 */
static long count_proc_maps_lines(const char *path)
{
	FILE *f;
	char buf[1024];
	long lines = 0;

	f = fopen(path, "r");
	if (f == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), f) != NULL) {
		if (strchr(buf, '\n') != NULL)
			lines++;
	}

	fclose(f);
	return lines;
}

/*
 * Per-tick scan paired with periodic_counter_rates_dump: every dump
 * window, snapshot the parent's VMA count and walk the live child pid
 * slots to sum, max, and min the children's VMA counts.  The point is
 * post-mortem visibility for the cgroup-OOM class where one of trinity's
 * thaw/freeze paths leaks a VMA per cycle (a failed mprotect that gets
 * retried can split a VMA without merging back, and the leak only
 * manifests when the host kills the parent for memory exhaustion).
 * children_max is the diagnostic of interest: if a single slot grows
 * its VMA count an order of magnitude faster than the others, that's
 * the leak signature.  /proc reads that fail (process died between the
 * pid snapshot and the open) are silently skipped rather than panicked.
 */
void __cold vma_count_periodic_dump(void)
{
	static struct timespec last_dump;
	struct timespec now;
	long elapsed;
	long parent_vmas;
	unsigned long total = 0;
	unsigned long max_vmas = 0;
	unsigned long min_vmas = 0;
	bool min_set = false;
	unsigned int i;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/* First call: arm the window so the first emission lands at the
	 * same cadence as the rest of the periodic dumps. */
	if (last_dump.tv_sec == 0) {
		last_dump = now;
		return;
	}

	elapsed = now.tv_sec - last_dump.tv_sec;
	if (elapsed < DEFENSE_DUMP_INTERVAL_SEC)
		return;

	parent_vmas = count_proc_maps_lines("/proc/self/maps");

	for_each_child(i) {
		char path[32];
		pid_t pid;
		long n;

		pid = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);
		if (pid == EMPTY_PIDSLOT)
			continue;

		snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
		n = count_proc_maps_lines(path);
		if (n < 0)
			continue;

		total += (unsigned long)n;
		if ((unsigned long)n > max_vmas)
			max_vmas = (unsigned long)n;
		if (!min_set || (unsigned long)n < min_vmas) {
			min_vmas = (unsigned long)n;
			min_set = true;
		}
	}

	/*
	 * Coalesce identical VMAs lines.  In steady-state runs all four
	 * counts (parent, total, max, min) are unchanged window after
	 * window.  Suppress repeats but force a print every 30 windows so
	 * the stats log still carries a periodic state anchor.
	 */
	unsigned long parent = (parent_vmas < 0) ? 0UL : (unsigned long)parent_vmas;
	static unsigned long last_vma_parent;
	static unsigned long last_vma_total;
	static unsigned long last_vma_max;
	static unsigned long last_vma_min;
	static unsigned int vma_suppress = 30; /* force first print */
	if (vma_suppress >= 30 ||
	    parent != last_vma_parent ||
	    total != last_vma_total ||
	    max_vmas != last_vma_max ||
	    min_vmas != last_vma_min) {
		stats_log_write("[main] VMAs: parent=%lu children_total=%lu children_max=%lu children_min=%lu\n",
				parent, total, max_vmas, min_vmas);
		last_vma_parent = parent;
		last_vma_total = total;
		last_vma_max = max_vmas;
		last_vma_min = min_vmas;
		vma_suppress = 0;
	} else {
		vma_suppress++;
	}

	last_dump = now;
}
