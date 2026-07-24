/*
 * Generic close-fd hook, post-state / rettype bound validators, and
 * ENOSYS deactivation, carved out of dispatch/syscall.c.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "params.h"
#include "shm.h"
#include "syscall.h"
#include "syscall-internal.h"
#include "syscall_record.h"
#include "tables.h"
#include "utils.h"

void generic_post_close_fd(struct syscallrecord *rec)
{
	long ret = (long)rec->retval;
	if (ret >= 0 && ret < (1 << 20))
		close((int)ret);
}

/*
 * Blanket count-bound validator for syscalls whose retval semantics are
 * exactly "bytes/items processed in [0, aN] || -1", driven by the
 * .bound_arg annotation on syscallentry.  Single dispatcher chokepoint
 * means we don't have to sprinkle the same per-syscall .post bound check
 * across every read/write/recv/send-class handler individually -- one
 * gate covers the entire helper-eligible set, and adding a new entry to
 * the set is a one-line .bound_arg = N annotation.
 *
 * Read the count from rec->aN at validator entry rather than from a
 * post_state snapshot: the validator runs before entry->post, so the
 * snap-stash pattern that defends per-syscall post handlers against
 * sibling-stomps of rec->aN is not yet in scope.  Per-syscall .post
 * handlers that already keep a snap-bounded copy (write/listmount/
 * readlink/getcwd etc.) remain in place as a defense-in-depth second
 * layer; this helper catches the symmetric set that has no .post today
 * (read/pread64/recv/sendto/...) for the same logical bug class.
 *
 * Informational only -- do NOT coerce rec->retval.  Unlike the RET_FD
 * blanket validator, an over-large count-bound retval does not seed a
 * downstream wild-write hazard: nobody passes the retval back to the
 * kernel as a buffer length or fd.  The cost of a mis-coerced retval
 * (silently dropping a legitimate large read on a machine whose ulimit
 * raises the bound past the helper's expectation) outweighs the value
 * for a Phase 2 detector.  Coercion is reserved for a follow-up phase
 * once the helper has accumulated quiet-week telemetry.
 *
 * Skip rec->retval == -1UL: failure is the legitimate error path and
 * carries no count semantics.
 */
void enforce_count_bound(const struct syscallentry *entry,
			 struct syscallrecord *rec)
{
	int idx = entry->bound_arg;
	unsigned long count;
	unsigned long ret;

	if (idx == 0)
		return;

	if (rec->retval == -1UL)
		return;

	if (idx < 1 || idx > 6)
		return;

	/* Read via get_arg_snapshot() so a bound_arg slot that opted into
	 * the arg_shadow mask is compared against the dispatch-time value
	 * the kernel actually saw -- a sibling stomping rec->aN between
	 * syscall return and this check would otherwise either fabricate a
	 * spurious "retval exceeds count" warning or hide a real one by
	 * inflating the bound.  Unopted slots fall through the accessor's
	 * mask gate to the live rec->aN, matching the pre-change behaviour. */
	count = get_arg_snapshot(rec, (unsigned int) idx);

	ret = rec->retval;
	if (ret > count) {
		outputerr("count-bound: %s retval=%lu exceeds %s=%lu\n",
			  entry->name, ret,
			  entry->argname[idx - 1] ? entry->argname[idx - 1] : "count",
			  count);
		post_handler_corrupt_ptr_bump_at(rec, NULL,
						 CORRUPT_PTR_SITE_ENFORCE_COUNT_BOUND);
	}
}

/*
 * Table-driven generic return-bound validator.  Complementary to the
 * bespoke rettype gates above (rzs_blanket_reject, reject_corrupt_retfd,
 * enforce_count_bound), this catches the residual RET_* classes whose
 * value range is well-defined by kernel ABI but had no dispatcher-level
 * check.  Entries left .active = false (RET_FD, RET_ADDRESS, the
 * unlisted indices) are skipped: RET_FD is already coerced to -1UL by
 * reject_corrupt_retfd before this runs, so an entry here would be dead;
 * RET_ADDRESS spans the full address space and has no useful generic
 * bound.  RET_ZERO_SUCCESS IS included even though rzs_blanket_reject
 * already bumps a stat counter for it -- the counter is silent, and
 * adding the entry surfaces the per-syscall offender at -v.
 *
 * Informational only -- does not coerce rec->retval.  Skips the universal
 * -1UL error path and any rettype outside [RET_ZERO_SUCCESS, RET_LAST].
 * Logged via output(1, ...) so it stays quiet at the default verbosity
 * and only fires for an operator running with -v.
 */
struct ret_bound {
	long min, max;
	bool active;
};

static const struct ret_bound ret_bounds[RET_LAST + 1] = {
	[RET_ZERO_SUCCESS] = { 0,         0,         true },
	[RET_KEY_SERIAL_T] = { 1,         INT32_MAX, true },
	[RET_PID_T]        = { 0,         4194304,   true },  /* PID_MAX_LIMIT */
	[RET_PATH]         = { 0,         PATH_MAX,  true },
	[RET_NUM_BYTES]    = { 0,         LONG_MAX,  true },  /* ssize_t domain */
	[RET_GID_T]        = { 0,         INT32_MAX, true },
	[RET_UID_T]        = { 0,         INT32_MAX, true },
};

void validate_ret_bound(const struct syscallentry *entry,
			struct syscallrecord *rec)
{
	const struct ret_bound *b;
	int rt = effective_rettype(entry, rec);
	long s;

	if (rt <= RET_NONE || rt > RET_LAST)
		return;
	b = &ret_bounds[rt];
	if (!b->active)
		return;
	if (rec->retval == -1UL)
		return;

	s = (long) rec->retval;
	if (s < b->min || s > b->max)
		output(1, "ret-bound: %s rettype=%d retval=%ld outside [%ld, %ld]\n",
		       entry->name, rt, s, b->min, b->max);
}

/*
 * If the syscall doesn't exist don't bother calling it next time.
 * Some syscalls return ENOSYS depending on their arguments, we mark
 * those as IGNORE_ENOSYS and keep calling them.
 */
void deactivate_enosys(struct syscallrecord *rec, struct syscallentry *entry, unsigned int call)
{
	bool did_deactivate = false;

	/* some syscalls return ENOSYS instead of EINVAL etc (futex for eg) */
	if (entry->flags & IGNORE_ENOSYS)
		return;

	lock(&shm->syscalltable_lock);

	/* check another thread didn't already do this. */
	if (syscall_rt(entry)->active_number != 0) {
		deactivate_syscall_nolock(call, rec->do32bit);
		did_deactivate = true;
	}

	unlock(&shm->syscalltable_lock);

	if (did_deactivate) {
		output(0, "%s (%d%s) returned ENOSYS, marking as inactive.\n",
			entry->name,
			call + SYSCALL_OFFSET,
			rec->do32bit == true ? ":[32BIT]" : "");
		if ((do_specific_syscall || random_selection ||
		     desired_group != GROUP_NONE) &&
		    no_syscalls_enabled() == true)
			outputerr("%s was the last syscall in the targeted "
				  "set; depleted via ENOSYS self-disable\n",
				  entry->name);
	}
}
