/*
 * Per-resource safe-limit dictionaries for the rlimit family.  See
 * include/rlimit-safe.h for rationale.
 *
 * The table is sized so each resource carries 3-5 (cur, max) pairs that
 * satisfy the per-resource legality constraints described next to each
 * entry.  All pairs respect the universal "rlim_max >= rlim_cur"
 * invariant the kernel enforces via the bare cmp in do_prlimit() before
 * the resource-specific handler runs.
 */

#include <stddef.h>
#include <sys/resource.h>
#include "rlimit-safe.h"
#include "rnd.h"
#include "utils.h"

#include "kernel/resource.h"
#include "kernel/sched.h"
#ifndef RLIM_INFINITY
#define RLIM_INFINITY (~0ULL)
#endif

/*
 * RLIMIT_NICE on the kernel side is encoded as `20 - nice`, with the
 * legal nice range being [-20, 19] -> encoded as [40, 1].  An rlim_cur
 * of 0 means "no autogroup nice override" and is also accepted.
 *
 * RLIMIT_RTPRIO is the maximum real-time scheduling priority a task may
 * acquire via sched_setscheduler() in SCHED_FIFO/RR -- legal 0..99.
 *
 * Everything else is byte/count/seconds without per-resource legality
 * bounds beyond the universal cur<=max invariant; pick a smattering of
 * 0 / page / MB / GB / INFINITY shaped pairs that exercise both the
 * "tight cap" and "unlimited" paths.
 */

struct rlimit_safe_pair {
	unsigned long long cur;
	unsigned long long max;
};

/* Per-resource pair lists.  Keep each short (3-5 entries). */

static const struct rlimit_safe_pair cpu_pairs[] = {
	{ 0, 0 },
	{ 1, 1 },
	{ 60, 3600 },
	{ RLIM_INFINITY, RLIM_INFINITY },
};

static const struct rlimit_safe_pair fsize_pairs[] = {
	{ 0, 0 },
	{ 4096, 4096 },
	{ 1ULL << 20, 1ULL << 20 },
	{ 1ULL << 30, 1ULL << 30 },
	{ RLIM_INFINITY, RLIM_INFINITY },
};

static const struct rlimit_safe_pair data_pairs[] = {
	{ 0, 0 },
	{ 1ULL << 20, 1ULL << 20 },
	{ 1ULL << 30, 1ULL << 30 },
	{ RLIM_INFINITY, RLIM_INFINITY },
};

static const struct rlimit_safe_pair stack_pairs[] = {
	{ 8192, 8192 },
	{ 1ULL << 20, 1ULL << 23 },
	{ 8ULL << 20, 8ULL << 20 },
	{ RLIM_INFINITY, RLIM_INFINITY },
};

static const struct rlimit_safe_pair core_pairs[] = {
	{ 0, 0 },
	{ 1ULL << 20, 1ULL << 20 },
	{ 1ULL << 30, 1ULL << 30 },
	{ RLIM_INFINITY, RLIM_INFINITY },
};

static const struct rlimit_safe_pair rss_pairs[] = {
	{ 0, 0 },
	{ 1ULL << 20, 1ULL << 20 },
	{ 1ULL << 30, 1ULL << 30 },
	{ RLIM_INFINITY, RLIM_INFINITY },
};

static const struct rlimit_safe_pair nproc_pairs[] = {
	{ 0, 0 },
	{ 64, 1024 },
	{ 16384, 16384 },
	{ RLIM_INFINITY, RLIM_INFINITY },
};

/*
 * RLIMIT_NOFILE rlim_max is bounded by sysctl_nr_open (default 1<<20).
 * Stay below that ceiling so the kernel does not reject before reaching
 * the per-fd handler.
 */
static const struct rlimit_safe_pair nofile_pairs[] = {
	{ 0, 0 },
	{ 256, 1024 },
	{ 4096, 4096 },
	{ 1ULL << 16, 1ULL << 16 },
};

static const struct rlimit_safe_pair memlock_pairs[] = {
	{ 0, 0 },
	{ 64ULL << 10, 64ULL << 10 },
	{ 1ULL << 20, 1ULL << 20 },
	{ RLIM_INFINITY, RLIM_INFINITY },
};

static const struct rlimit_safe_pair as_pairs[] = {
	{ 0, 0 },
	{ 1ULL << 30, 1ULL << 30 },
	{ 1ULL << 40, 1ULL << 40 },
	{ RLIM_INFINITY, RLIM_INFINITY },
};

static const struct rlimit_safe_pair locks_pairs[] = {
	{ 0, 0 },
	{ 8, 1024 },
	{ 65536, 65536 },
	{ RLIM_INFINITY, RLIM_INFINITY },
};

static const struct rlimit_safe_pair sigpending_pairs[] = {
	{ 0, 0 },
	{ 16, 1024 },
	{ 4096, 4096 },
	{ RLIM_INFINITY, RLIM_INFINITY },
};

static const struct rlimit_safe_pair msgqueue_pairs[] = {
	{ 0, 0 },
	{ 1ULL << 16, 1ULL << 20 },
	{ 1ULL << 20, 1ULL << 20 },
	{ RLIM_INFINITY, RLIM_INFINITY },
};

/* RLIMIT_NICE: legal encoded values 1..40 (cur 0 also accepted). */
static const struct rlimit_safe_pair nice_pairs[] = {
	{ 1, 1 },
	{ 20, 20 },
	{ 20, 40 },
	{ 40, 40 },
};

/* RLIMIT_RTPRIO: legal 0..99. */
static const struct rlimit_safe_pair rtprio_pairs[] = {
	{ 0, 0 },
	{ 1, 50 },
	{ 50, 99 },
	{ 99, 99 },
};

#ifdef RLIMIT_RTTIME
static const struct rlimit_safe_pair rttime_pairs[] = {
	{ 0, 0 },
	{ 200000, 200000 },
	{ 1000000, 1000000 },
	{ RLIM_INFINITY, RLIM_INFINITY },
};
#endif

#define PAIR_LIST(arr) { (arr), sizeof(arr) / sizeof((arr)[0]) }

static const struct {
	const struct rlimit_safe_pair *pairs;
	unsigned int n;
} rlimit_safe_table[] = {
	[RLIMIT_CPU]		= PAIR_LIST(cpu_pairs),
	[RLIMIT_FSIZE]		= PAIR_LIST(fsize_pairs),
	[RLIMIT_DATA]		= PAIR_LIST(data_pairs),
	[RLIMIT_STACK]		= PAIR_LIST(stack_pairs),
	[RLIMIT_CORE]		= PAIR_LIST(core_pairs),
	[RLIMIT_RSS]		= PAIR_LIST(rss_pairs),
	[RLIMIT_NPROC]		= PAIR_LIST(nproc_pairs),
	[RLIMIT_NOFILE]		= PAIR_LIST(nofile_pairs),
	[RLIMIT_MEMLOCK]	= PAIR_LIST(memlock_pairs),
	[RLIMIT_AS]		= PAIR_LIST(as_pairs),
	[RLIMIT_LOCKS]		= PAIR_LIST(locks_pairs),
	[RLIMIT_SIGPENDING]	= PAIR_LIST(sigpending_pairs),
	[RLIMIT_MSGQUEUE]	= PAIR_LIST(msgqueue_pairs),
	[RLIMIT_NICE]		= PAIR_LIST(nice_pairs),
	[RLIMIT_RTPRIO]		= PAIR_LIST(rtprio_pairs),
#ifdef RLIMIT_RTTIME
	[RLIMIT_RTTIME]		= PAIR_LIST(rttime_pairs),
#endif
};

static const unsigned long rlimit_fragile_resources[] = {
	RLIMIT_CPU, RLIMIT_NOFILE, RLIMIT_AS, RLIMIT_DATA,
	RLIMIT_STACK, RLIMIT_RSS, RLIMIT_MEMLOCK,
};

bool resource_is_fragile(unsigned long resource)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(rlimit_fragile_resources); i++)
		if (rlimit_fragile_resources[i] == resource)
			return true;
	return false;
}

unsigned long pick_nonfragile_rlimit_resource(const unsigned long *table,
					      unsigned int count)
{
	unsigned int start;
	unsigned int i;

	if (count == 0)
		return RLIMIT_CORE;

	start = rnd_modulo_u32(count);
	for (i = 0; i < count; i++) {
		unsigned long r = table[(start + i) % count];

		if (!resource_is_fragile(r))
			return r;
	}
	return RLIMIT_CORE;
}

int rlimit_pick_safe_pair(unsigned int resource,
			  unsigned long long *cur_out,
			  unsigned long long *max_out)
{
	const struct rlimit_safe_pair *p;
	unsigned int n;

	if (resource >= sizeof(rlimit_safe_table) / sizeof(rlimit_safe_table[0]))
		return -1;

	p = rlimit_safe_table[resource].pairs;
	n = rlimit_safe_table[resource].n;
	if (p == NULL || n == 0)
		return -1;

	p += rnd_modulo_u32(n);
	*cur_out = p->cur;
	*max_out = p->max;
	return 0;
}
