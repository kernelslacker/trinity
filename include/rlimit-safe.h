#pragma once
/*
 * Per-resource safe-limit dictionaries for the rlimit family
 * (prlimit64, getrlimit, setrlimit).
 *
 * Why: the kernel validates each RLIMIT_* against its own per-resource
 * legality rules -- RLIMIT_NICE is encoded as (20 - nice) and only legal
 * in 1..40, RLIMIT_RTPRIO is bounded 0..99, RLIMIT_NOFILE is capped at
 * sysctl_nr_open, and every resource enforces rlim_max >= rlim_cur.
 * Random rlim_cur/rlim_max pairs almost always trip "rlim_max < rlim_cur"
 * or "exceeds privileged max" before the kernel ever reaches the
 * resource-specific handlers (do_prlimit -> __ksys_setrlimit calls back
 * through security_task_setrlimit and the bare cmp before the per-resource
 * path).  This file ships a small dictionary of safe (cur, max) pairs
 * keyed by RLIMIT_*, designed so the validation gate accepts them and
 * the deeper resource-specific code path actually runs.
 *
 * Callers use:
 *   rlimit_pick_safe_pair(resource, &cur, &max)  -- fill a known-good pair
 *
 * Returns 0 on success, -1 if the resource has no dictionary entries
 * (in which case the caller should fall back to random values).
 */

#include <stdint.h>

int rlimit_pick_safe_pair(unsigned int resource,
			  unsigned long long *cur_out,
			  unsigned long long *max_out);
