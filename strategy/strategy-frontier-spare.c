/*
 * Spare-lane classifier shared by the coverage-frontier cooldown
 * helpers.  Split from strategy-frontier.c.
 */

#include <stdbool.h>

#include "kcov.h"
#include "shm.h"
#include "stats.h"
#include "strategy.h"
#include "syscall.h"		/* MAX_NR_SYSCALL */

#include "strategy-frontier-internal.h"

/*
 * Spare-lane decision shared by the silent-regime satcool helper
 * (frontier_satcool_spare below) and the LIVE-regime cooldown helper
 * (frontier_live_cool_spare further below).  Returns the FIRST matching
 * spare reason, or FRONTIER_SPARE_NONE when no lane fires -- the caller
 * applies its own outer mode gate, magnitude floor, and counter-bump
 * cascade, so this routine is the bare predicate body the two siblings
 * share.  Extracting it keeps the lane logic from drifting between the
 * silent and LIVE call sites (one predicate body, two callers, zero
 * duplication).
 *
 * Lane order encodes precedence -- the bpf-backstop windowed-edges
 * spare wins over arggen, and arggen wins over the ret_objtype
 * producer spare (the more specific signal beats the broader catch).
 * Windowed-edges first: a syscall whose K-window ring is nonzero is
 * recently productive regardless of every other signal, so the
 * predicate stops there and the caller never reads cmp / errno
 * baselines on the windowed-nonzero path -- the recent-count check
 * returns FRONTIER_SPARE_WINDOWED_EDGES directly, skipping the four
 * RELAXED atomic loads that follow.
 *
 * All loads RELAXED: a mixed snapshot taken across non-atomic
 * instants at most causes one rotation of mis-classification, the
 * same one-window attribution lag the rotation loop already documents.
 * The cmp_now / cmp_base / errno_now / errno_base comparisons are
 * equality / ordering tests, never arithmetic, so a stale or torn
 * read cannot drive an unsigned subtraction or latch permanent state.
 * The producer-observer lookup is a single bit-test against the
 * immutable-after-init bitmap, published release-acquire by
 * ensure_producer_observer_built() above; the rotation-hot caller
 * (frontier_live_cool_spare on every LIVE-regime miss) pays one
 * lookup per call, no get_syscall_entry indirection.
 */
/* enum frontier_spare_reason lives in include/strategy.h so the shadow
 * attribution-confidence dump in stats/dump.c can bucket per-syscall
 * clean/noisy readings by the same spare-cascade classification the
 * silent- and LIVE-regime cooldown helpers here consume. */

enum frontier_spare_reason
frontier_spare_lane_decide(unsigned int syscallnr, bool do32)
{
	unsigned long cmp_now, cmp_base;
	unsigned long errno_now, errno_base;

	if (frontier_recent_count(syscallnr) != 0)
		return FRONTIER_SPARE_WINDOWED_EDGES;

	cmp_now = __atomic_load_n(
		&kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts[syscallnr],
		__ATOMIC_RELAXED);
	cmp_base = __atomic_load_n(
		&shm->stats.frontier.per_syscall.silent_cmp_baseline[syscallnr],
		__ATOMIC_RELAXED);
	errno_now = __atomic_load_n(
		&kcov_shm->errno_state.per_syscall_errno[syscallnr][ERRNO_BUCKET_SUCCESS],
		__ATOMIC_RELAXED);
	errno_base = __atomic_load_n(
		&shm->stats.frontier.per_syscall.silent_errno_success_baseline[syscallnr],
		__ATOMIC_RELAXED);

	/*
	 * CRITICAL: first-success TRANSITION, NOT raw success-count delta.
	 * A syscall that succeeds on every call (syncfs) has errno_base > 0
	 * at every baseline snapshot and so CANNOT spare itself by raw
	 * success accumulation; the spare fires only when the syscall
	 * transitions from never-having-succeeded (errno_base == 0) to
	 * producing its first success in the current window.  Distinct
	 * CMP-inserts use the existing baseline machinery (refreshed at
	 * every productive-event reset in frontier_record_new_edge() /
	 * frontier_record_transition_edge()), which already counts only
	 * first-inserts / evict-replaces in per_syscall_cmp_inserts -- the
	 * "distinct hint additions" the design names.
	 */
	if ((cmp_now != cmp_base) || (errno_base == 0 && errno_now > 0))
		return FRONTIER_SPARE_ARGGEN;

	/*
	 * Object-producer spare: ret_objtype != OBJ_NONE exempts the
	 * producers whose payoff is delayed and credited downstream to the
	 * consumer of the produced object.  Lookup is against the
	 * precomputed producer-observer bitmap above -- the per-pick
	 * get_syscall_entry() table indirection (and the biarch branch
	 * inside it) the original inline shape paid for is collapsed to a
	 * single bit-test.  Build is lazy with release/acquire publish so a
	 * partially-built bitmap is NEVER visible to a concurrent reader.
	 */
	ensure_producer_observer_built();
	if (producer_observer_lookup(syscallnr, do32))
		return FRONTIER_SPARE_OBJPRODUCER;

	return FRONTIER_SPARE_NONE;
}
