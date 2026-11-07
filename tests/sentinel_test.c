/*
 * Self-check for the divergence sentinel (child/child-sentinel.c): a
 * totalram or totalswap change the kernel makes on its own (a balloon
 * inflate, memory hotplug, swapon) counts as expected drift, while a
 * field nothing legitimately moves still counts as an anomaly, and the
 * pre-crash ring records both.  uname() and sysinfo() go to a model
 * through fake_syscall.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <linux/utsname.h>

#include "child.h"
#include "child-api.h"		/* divergence_sentinel_tick */
#include "debug.h"		/* BUG */
#include "pre_crash_ring.h"
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */

extern bool (*fake_syscall)(long number, const unsigned long a[6],
			    long *ret);	/* landlock_test.c */

static struct sysinfo model_si;
static unsigned int ring_records;

/* Owned by health/pre_crash_ring.c in production. */
void pre_crash_ring_record(struct childdata *child,
			   const struct syscallrecord *rec,
			   const struct timespec *now)
{
	(void)child;
	(void)rec;
	(void)now;
	ring_records++;
}

static bool model_sentinel_calls(long number, const unsigned long a[6],
				 long *ret)
{
	if (number == __NR_uname) {
		struct new_utsname *uts = (void *) a[0];

		memset(uts, 0, sizeof(*uts));
		strcpy(uts->sysname, "Linux");
		strcpy(uts->release, "6.13.0");
		*ret = 0;
		return true;
	}
	if (number == __NR_sysinfo) {
		memcpy((void *) a[0], &model_si, sizeof(model_si));
		*ret = 0;
		return true;
	}
	return false;
}

/* One uname tick, then one sysinfo tick. */
static void tick_both(struct childdata *child)
{
	divergence_sentinel_tick(child);
	divergence_sentinel_tick(child);
}

void sentinel_self_check(void);
void sentinel_self_check(void)
{
	struct divergence_sentinel_stats *stats = &shm->stats.divergence_sentinel;
	struct childdata *child = calloc(1, sizeof(*child));

	if (child == NULL)
		BUG("sentinel: calloc failed");
	memset(stats, 0, sizeof(*stats));
	fake_syscall = model_sentinel_calls;

	model_si.totalram = 1UL << 20;
	model_si.totalswap = 1UL << 18;
	model_si.mem_unit = 4096;
	divergence_sentinel_tick(child);	/* seeds both halves */

	model_si.totalram -= 256;		/* a balloon inflate */
	model_si.totalswap += 1UL << 16;	/* a swapon */
	tick_both(child);
	if (stats->anomalies[SF_SYSINFO_TOTALRAM] != 0 ||
	    stats->anomalies[SF_SYSINFO_TOTALSWAP] != 0)
		BUG("sentinel: a totalram or totalswap change counted as an anomaly");
	if (stats->expected_drift != 2)
		BUG("sentinel: a totalram or totalswap change went uncounted");

	model_si.mem_unit = 1;
	tick_both(child);
	if (stats->anomalies[SF_SYSINFO_MEM_UNIT] != 1)
		BUG("sentinel: a mem_unit change did not count as an anomaly");
	if (ring_records != 3)
		BUG("sentinel: the pre-crash ring missed a divergence");

	fake_syscall = NULL;
	memset(stats, 0, sizeof(*stats));
	free(child);
}
