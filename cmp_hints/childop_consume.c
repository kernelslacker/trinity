/*
 * SHADOW consume-side resolver for the childop CMP path.
 *
 * childop_cmp_value() is the consumer half of the childop CMP
 * integration -- the producer half (trinity_cmp_syscall wrapper +
 * childop_cmp_reset / _collect helpers) already lives on master
 * behind --childop-cmp-harvest.  This resolver reads the durable
 * per-nr pool that the harvest side (and warm-start / non-childop
 * inserts) populates and shadow-scores what a live consume would
 * return at each childop field site, but always returns the
 * caller's rng fallback so no arg changes and no downstream
 * behaviour differs.  Sized purely to measure the opportunity
 * before the C3/C4 live-consume slice earns its own re-nod.
 *
 * See include/childop-cmp.h for the per-mode contract, and
 * include/kcov.h childop_cmp_consume_* for the counter shape.
 */

#include <stdbool.h>

#include "childop-cmp.h"
#include "cmp_hints.h"
#include "kcov.h"
#include "syscall.h"

unsigned long childop_cmp_value(unsigned int nr, enum cmp_hint_use use,
				unsigned long old, unsigned long fallback)
{
	unsigned long resolved;
	bool got;

	/* OFF default: byte-for-byte identical to a direct rng draw.
	 * No cmp_hints_try_get_ex call, no counter bump, no shm
	 * access -- the field-site pick stream is preserved bit-for-
	 * bit against a build without the knob for a given seed. */
	if (__atomic_load_n(&childop_cmp_consume_mode, __ATOMIC_RELAXED) ==
	    CHILDOP_CMP_CONSUME_OFF)
		return fallback;

	/* Degrade-safe: kcov_shm-less / out-of-range nr short-circuits
	 * before any counter access, matching the harvest-side
	 * childop_cmp_collect() convention. */
	if (kcov_shm == NULL || nr >= MAX_NR_SYSCALL)
		return fallback;

	/* SHADOW probe.  do32=false (childops issue native 64-bit
	 * syscalls only); allow_hyp_inject=false (never route through
	 * the LIVE typed-hypothesis inject arm from a shadow-only
	 * resolver -- keeps the pick stream identical to OFF); accept=
	 * NULL (accept-all -- accept range plumbing is a per-field
	 * follow-up); arg_idx=0 + callsite=CMP_HINT_CALLSITE_OTHER
	 * (nr-only keying; pilot single-semantic per the design). */
	resolved = 0;
	got = cmp_hints_try_get_ex(nr, false, use, old, false, NULL, 0,
				   CMP_HINT_CALLSITE_OTHER, &resolved);

	if (got) {
		__atomic_fetch_add(
			&kcov_shm->childop_cmp_consume.childop_cmp_consume_would_pick[nr], 1UL,
			__ATOMIC_RELAXED);
		if (resolved != fallback)
			__atomic_fetch_add(
			    &kcov_shm->childop_cmp_consume.childop_cmp_consume_would_value_differs[nr],
			    1UL, __ATOMIC_RELAXED);
	} else {
		__atomic_fetch_add(
			&kcov_shm->childop_cmp_consume.childop_cmp_consume_would_miss[nr], 1UL,
			__ATOMIC_RELAXED);
	}

	/* SHADOW contract: the resolved hint is OBSERVED, never used
	 * to change an arg.  Return the rng fallback unconditionally
	 * so the syscall receives byte-for-byte the same value it
	 * would have under --childop-cmp-consume=off. */
	return fallback;
}
