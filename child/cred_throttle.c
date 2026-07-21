/*
 * Credential-syscall observability oracle + flag-gated throttle.
 *
 * Companion to random-syscall.c.  Splitting the implementation out keeps
 * the cred-class enum, the name -> nr cache, and the dump-side counters
 * in a single self-contained TU so a later "expand the class set" or
 * "tune the throttle thresholds" change touches one file instead of the
 * picker hot path.  See include/cred_throttle.h for the design contract.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "cred_throttle.h"
#include "kcov.h"		/* ERRNO_BUCKET_* */
#include "params.h"		/* cred_throttle */
#include "rnd.h"
#include "shm.h"
#include "stats.h"
#include "syscall.h"
#include "tables.h"		/* get_syscall_entry */

const char *const cred_class_name[CRED_CLASS_NR] = {
	[CRED_CLASS_SETREGID]  = "setregid",
	[CRED_CLASS_SETREUID]  = "setreuid",
	[CRED_CLASS_SETRESUID] = "setresuid",
	[CRED_CLASS_SETRESGID] = "setresgid",
	[CRED_CLASS_SETGID]    = "setgid",
	[CRED_CLASS_SETUID]    = "setuid",
	[CRED_CLASS_SETFSUID]  = "setfsuid",
	[CRED_CLASS_SETFSGID]  = "setfsgid",
	[CRED_CLASS_SETGROUPS] = "setgroups",
};

int cred_class_for_entry(const struct syscallentry *entry)
{
	int i;

	if (entry == NULL || entry->name == NULL)
		return CRED_CLASS_NR;

	for (i = 0; i < CRED_CLASS_NR; i++) {
		if (strcmp(entry->name, cred_class_name[i]) == 0)
			return i;
	}
	return CRED_CLASS_NR;
}

/*
 * Per-(nr, do32) cache.  Sentinel -1 == not yet resolved; 0..CRED_CLASS_NR-1
 * == the resolved cred class; CRED_CLASS_NR == resolved as not-a-credential.
 * Writes are RELAXED and idempotent (entry->name is fixed at table-init
 * time, and cred_class_for_entry() is a pure function of that name), so
 * concurrent racing initialisers from different children always store the
 * same value into the same slot -- a torn read sees either the sentinel or
 * the final value, never a foreign half.
 *
 * The two-arch dimension matches biarch: the same syscall nr can resolve
 * to a different entry on the 32-bit and 64-bit tables (e.g. setreuid vs
 * setreuid32), so caching per (nr, do32) preserves the picker's per-arch
 * decision.
 */
static int8_t cred_class_by_nr[MAX_NR_SYSCALL][2] = {
	[0 ... MAX_NR_SYSCALL - 1] = { -1, -1 },
};

int cred_class_for_nr(unsigned int nr, bool do32)
{
	int8_t cached;
	struct syscallentry *entry;
	int cls;
	unsigned int arch = do32 ? 1U : 0U;

	if (nr >= MAX_NR_SYSCALL)
		return CRED_CLASS_NR;

	cached = __atomic_load_n(&cred_class_by_nr[nr][arch], __ATOMIC_RELAXED);
	if (cached >= 0)
		return (int)cached;

	entry = get_syscall_entry(nr, do32);
	cls = cred_class_for_entry(entry);
	__atomic_store_n(&cred_class_by_nr[nr][arch], (int8_t)cls,
			 __ATOMIC_RELAXED);
	return cls;
}

void cred_oracle_record(const struct syscallentry *entry,
			unsigned int errno_bucket)
{
	int cls = cred_class_for_entry(entry);

	if (cls >= CRED_CLASS_NR)
		return;

	__atomic_add_fetch(&shm->stats.cred_class.calls[cls], 1UL,
			   __ATOMIC_RELAXED);

	switch (errno_bucket) {
	case ERRNO_BUCKET_SUCCESS:
		__atomic_add_fetch(&shm->stats.cred_class.success[cls], 1UL,
				   __ATOMIC_RELAXED);
		break;
	case ERRNO_BUCKET_EPERM:
		__atomic_add_fetch(&shm->stats.cred_class.eperm[cls], 1UL,
				   __ATOMIC_RELAXED);
		break;
	case ERRNO_BUCKET_EINVAL:
		__atomic_add_fetch(&shm->stats.cred_class.einval[cls], 1UL,
				   __ATOMIC_RELAXED);
		break;
	default:
		break;
	}
}

bool cred_throttle_should_reject(unsigned int nr, bool do32)
{
	int cls;
	unsigned long calls, success, eperm, einval, hard_fails;

	/* Flag short-circuit FIRST: this is the load-bearing guarantee that
	 * --cred-throttle off makes the gate a single relaxed load with no
	 * other side effects.  A RELAXED bool load is the same cost as the
	 * existing group_bias gate at the top of set_syscall_nr_heuristic. */
	if (!__atomic_load_n(&cred_throttle, __ATOMIC_RELAXED))
		return false;

	cls = cred_class_for_nr(nr, do32);
	if (cls >= CRED_CLASS_NR)
		return false;

	calls = __atomic_load_n(&shm->stats.cred_class.calls[cls],
				__ATOMIC_RELAXED);
	if (calls < CRED_THROTTLE_MIN_CALLS)
		return false;

	/* Any observed success retires the throttle until the run restarts:
	 * if the class CAN succeed in this environment we want full sampling
	 * to drive its coverage. */
	success = __atomic_load_n(&shm->stats.cred_class.success[cls],
				  __ATOMIC_RELAXED);
	if (success > 0)
		return false;

	/* EPERM + EINVAL must dominate.  A class that's failing on EAGAIN
	 * or EFAULT is not "provably impossible" -- it's hitting a different
	 * shape of bug or kernel rejection that the picker should keep
	 * sampling.  100 * hard_fails >= CRED_THROTTLE_HARD_FAIL_PCT * calls
	 * is the percent check rearranged to integer-safe form. */
	eperm = __atomic_load_n(&shm->stats.cred_class.eperm[cls],
				__ATOMIC_RELAXED);
	einval = __atomic_load_n(&shm->stats.cred_class.einval[cls],
				 __ATOMIC_RELAXED);
	hard_fails = eperm + einval;
	if (hard_fails * 100UL < (unsigned long)CRED_THROTTLE_HARD_FAIL_PCT *
				 calls)
		return false;

	/* Sharply downweight.  rnd_modulo_u32(REJECT_DENOM) == 0 with
	 * probability 1/REJECT_DENOM keeps the class sampled at ~3% so a
	 * late environment change (capability grant, userns map landing) can
	 * still produce a success that retires the throttle on its next
	 * oracle re-check. */
	if (rnd_modulo_u32(CRED_THROTTLE_REJECT_DENOM) != 0) {
		__atomic_add_fetch(&shm->stats.cred_class.throttled[cls], 1UL,
				   __ATOMIC_RELAXED);
		return true;
	}
	return false;
}
