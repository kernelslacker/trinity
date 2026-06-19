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

#include <stdbool.h>
#include <stdint.h>

#include "rnd.h"

int rlimit_pick_safe_pair(unsigned int resource,
			  unsigned long long *cur_out,
			  unsigned long long *max_out);

/*
 * Uniform draw from a caller-supplied table of RLIMIT_* values.  The
 * three rlimit syscall sites each keep their own resources[] for the
 * .arg_params[].list = ARGLIST(...) registration; this shared helper
 * gives all three the same uniform pick without copy-pasted bodies.
 */
static inline unsigned int random_rlimit_resource(const unsigned long *table,
						  unsigned int count)
{
	return (unsigned int) table[rnd_modulo_u32(count)];
}

/*
 * Harness-fragile rlimit set: lowering any of these on a trinity-owned
 * pid breaks the fuzz child's own runtime.  RLIMIT_NOFILE {0,0} caps
 * fds so heap_bounds_init's /proc/self/maps open hits EMFILE and the
 * child runs the rest of its life with broken bounds tracking.
 * RLIMIT_AS / RLIMIT_DATA / RLIMIT_STACK / RLIMIT_RSS / RLIMIT_MEMLOCK
 * cap address-space or pinned pages so deferred_free's mprotect-RW
 * step ENOMEMs and the alloc-tracker quietly leaks every freed slot.
 * The safe-dictionary entries for these resources include {0,0} and
 * single-page sizes -- legal to the kernel (cur<=max, per-resource
 * bounds satisfied), lethal to us.  prlimit64 and setrlimit both draw
 * from the same dictionary, so the guard is shared.
 */
bool resource_is_fragile(unsigned long resource);

/*
 * Pick a non-fragile RLIMIT_* from a caller-supplied table.  Used
 * when the target is harness-owned (prlimit64) or unconditionally
 * (setrlimit, whose target is always self): walks the table from a
 * random start so the chosen non-fragile resource is still uniform,
 * and is guaranteed to terminate as long as the table contains at
 * least one non-fragile entry (callers register tables that always
 * include CPU/FSIZE/CORE/NPROC/LOCKS/SIGPENDING/MSGQUEUE/NICE/
 * RTPRIO/RTTIME alongside the fragile set).
 */
unsigned long pick_nonfragile_rlimit_resource(const unsigned long *table,
					      unsigned int count);
