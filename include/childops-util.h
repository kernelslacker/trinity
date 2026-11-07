#pragma once

#include <stdbool.h>
#include <time.h>

/*
 * Wall-clock budget check used by long-running childops to bound their
 * inner loops.  Returns true once `budget_ns` has elapsed since `start`
 * on CLOCK_MONOTONIC.  Each op picks its own ceiling (commonly 200-300 ms)
 * and passes it in; the helper just does the timespec arithmetic, in
 * long long because a 32-bit long wraps at ~2.1 s of nanoseconds.
 */
static inline bool budget_elapsed_ns(const struct timespec *start, long budget_ns)
{
	struct timespec now;
	long long elapsed_ns;

	clock_gettime(CLOCK_MONOTONIC, &now);
	elapsed_ns = (long long)(now.tv_sec - start->tv_sec) * 1000000000LL
		   + (now.tv_nsec - start->tv_nsec);
	return elapsed_ns >= budget_ns;
}
