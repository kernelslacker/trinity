/*
 * Load balancer: monitor /proc/meminfo and /proc/loadavg, and dynamically
 * adjust max_children so Trinity backs off when system resources are tight.
 *
 * Called periodically from the main loop via lb_tick().  All reads and
 * writes to max_children happen in the main process only, so no locking
 * is needed.
 */

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "child.h"
#include "loadbalancer.h"
#include "shm.h"
#include "trinity.h"

/* How often (in seconds) to re-evaluate. */
#define LB_INTERVAL_SECS    5

/* MemAvailable thresholds in kB. */
#define LB_MEM_LOW_KB       (128UL * 1024)  /* 128 MiB: start stepping down */
#define LB_MEM_CRITICAL_KB  (32UL * 1024)   /* 32 MiB: halve child count   */

/*
 * Load-average thresholds, expressed as (loadavg × 100) per online CPU.
 * E.g. LB_LOAD_HIGH_PCT = 150 means load > 1.5 × num_online_cpus.
 */
#define LB_LOAD_HIGH_PCT     150
#define LB_LOAD_CRITICAL_PCT 200

/* Never drop below this many children. */
#define LB_MIN_CHILDREN 1

/* Original max_children ceiling, set once at lb_init(). */
static unsigned int lb_max_ceiling;

/* Monotonic time of the last adjustment. */
static time_t lb_last_check;

/*
 * Returns MemAvailable in kB as reported by /proc/meminfo.
 * Returns ULONG_MAX on any read or parse error so that callers treat
 * errors as "plenty of memory" and don't trigger unnecessary scale-down.
 */
static unsigned long read_memavail_kb(void)
{
	FILE *fp;
	char line[128];
	unsigned long val = ULONG_MAX;

	fp = fopen("/proc/meminfo", "r");
	if (!fp)
		return ULONG_MAX;

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "MemAvailable:", 13) == 0) {
			if (sscanf(line, "MemAvailable: %lu kB", &val) != 1)
				val = ULONG_MAX;
			break;
		}
	}

	fclose(fp);
	return val;
}

/*
 * Returns the 1-minute load average × 100 (e.g., 1.50 → 150).
 * Returns 0 on any read or parse error so callers don't scale down.
 */
static unsigned int read_loadavg_100(void)
{
	FILE *fp;
	unsigned int whole, frac;

	fp = fopen("/proc/loadavg", "r");
	if (!fp)
		return 0;

	if (fscanf(fp, "%u.%u", &whole, &frac) != 2)
		whole = frac = 0;

	fclose(fp);
	return whole * 100 + frac;
}

/*
 * Record the initial max_children ceiling.  Must be called after
 * max_children has been set from command-line args (i.e., after parse_args)
 * but before fork_children().
 */
void lb_init(void)
{
	lb_max_ceiling = max_children;
	lb_last_check = 0;
}

/*
 * Re-read system metrics and adjust max_children if needed.
 * A no-op when called more frequently than LB_INTERVAL_SECS.
 *
 * Scale-down policy (applied in priority order):
 *   1. MemAvailable < LB_MEM_CRITICAL_KB: halve children.
 *   2. load > LB_LOAD_CRITICAL_PCT × ncpus: halve children.
 *   3. MemAvailable < LB_MEM_LOW_KB or load > LB_LOAD_HIGH_PCT × ncpus:
 *      decrement by one.
 *
 * Scale-up policy (only when conditions are healthy):
 *   - MemAvailable >= LB_MEM_LOW_KB and load < LB_LOAD_HIGH_PCT × ncpus:
 *     increment by one, up to lb_max_ceiling.
 *
 * Reducing max_children stops the main loop from spawning new children;
 * existing children above the new limit drain away naturally as they die
 * and replace_child() declines to re-spawn them.
 */
void lb_tick(void)
{
	struct timespec now;
	unsigned long memavail;
	unsigned int load100, load_hi, load_crit;
	unsigned int cur, target;

	if (__atomic_load_n(&shm->spawn_no_more, __ATOMIC_ACQUIRE))
		return;

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (now.tv_sec - lb_last_check < LB_INTERVAL_SECS)
		return;
	lb_last_check = now.tv_sec;

	memavail = read_memavail_kb();
	load100  = read_loadavg_100();

	load_hi   = num_online_cpus * LB_LOAD_HIGH_PCT;
	load_crit = num_online_cpus * LB_LOAD_CRITICAL_PCT;

	cur    = max_children;
	target = cur;

	/* Memory-driven adjustments. */
	if (memavail < LB_MEM_CRITICAL_KB) {
		target = cur / 2;
	} else if (memavail < LB_MEM_LOW_KB) {
		if (target > LB_MIN_CHILDREN)
			target--;
	} else if (load100 < load_hi && target < lb_max_ceiling) {
		/* System has headroom — grow back toward the ceiling. */
		target++;
	}

	/* Load-driven adjustments (can only reduce further). */
	if (load100 >= load_crit) {
		unsigned int load_target = cur / 2;

		if (load_target < target)
			target = load_target;
	} else if (load100 >= load_hi) {
		if (cur > LB_MIN_CHILDREN) {
			unsigned int load_target = cur - 1;

			if (load_target < target)
				target = load_target;
		}
	}

	/* Clamp to [LB_MIN_CHILDREN, lb_max_ceiling]. */
	if (target < LB_MIN_CHILDREN)
		target = LB_MIN_CHILDREN;
	if (target > lb_max_ceiling)
		target = lb_max_ceiling;

	if (target == cur)
		return;

	output(1, "load balancer: children %u -> %u "
	       "(memavail=%lu kB, load=%u.%02u)\n",
	       cur, target, memavail, load100 / 100, load100 % 100);

	max_children = target;
}
