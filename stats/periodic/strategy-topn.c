
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "arch.h"
#include "arg-len-semantics.h"
#include "breadcrumb_ring.h"
#include "child-api.h"
#include "cmp_hints.h"
#include "cred_throttle.h"
#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "reach-band.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "version.h"


/*
 * Top-N per-syscall distribution dump for the shadow-only saturation
 * cooldown.  Walks frontier_satcool_would_skip_per_syscall[] and emits
 * the highest-bumping syscalls in descending order followed by a trailing
 * total.  Called from dump_stats_strategy_summary() alongside the
 * aggregate frontier_satcool_* rows so the operator can confirm the
 * projected demote mass concentrates on the saturated-rich syscalls and
 * stays near zero on the under-explored struct-arg backlog before any
 * tuning of the magnitude threshold or promotion to a live reject.
 *
 * Render-only: never read by the silent-regime accept site or the
 * predicate it gates.  Mode-OFF runs return before any output so the
 * default-off behaviour stays byte-identical to today; under shadow-only
 * or combined the header + total are always printed (even when the array
 * is empty) so an operator running a short or under-populated session
 * can confirm the wiring fired without having to grep for absence.
 */
#define SATCOOL_TOPN 30

void dump_satcool_would_skip_per_syscall_top(void)
{
	struct {
		unsigned int nr;
		unsigned long count;
	} top[SATCOOL_TOPN];
	unsigned int top_count = 0;
	unsigned long total = 0;
	unsigned int nr_to_scan;
	unsigned int i;
	int j;
	enum frontier_saturation_cooldown_mode mode =
		__atomic_load_n(&frontier_saturation_cooldown_mode,
				__ATOMIC_RELAXED);

	/* Mode == OFF: byte-identical to pre-shadow behaviour.  The writer
	 * does not bump the array on OFF runs, so it would render an empty
	 * block, but skip outright to keep the OFF stats output unchanged. */
	if (mode == FRONTIER_SATURATION_COOLDOWN_MODE_OFF)
		return;

	/* Match the same biarch table-scan choice the existing per-syscall
	 * top-N path in dump_stats uses: under biarch only the 64-bit table
	 * is walked, since the silent-regime accept site writes the index
	 * raw and the 32/64 slot alias is the established shape for the
	 * sibling per-syscall counters. */
	nr_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	if (nr_to_scan > MAX_NR_SYSCALL)
		nr_to_scan = MAX_NR_SYSCALL;

	memset(top, 0, sizeof(top));

	for (i = 0; i < nr_to_scan; i++) {
		unsigned long c =
			shm->stats.frontier.satcool_would_skip_per_syscall[i];

		if (c == 0)
			continue;

		total += c;

		/* Insertion sort, descending by count, capped at SATCOOL_TOPN. */
		for (j = (int)top_count; j > 0 && c > top[j - 1].count; j--) {
			if (j < SATCOOL_TOPN)
				top[j] = top[j - 1];
		}
		if (j < SATCOOL_TOPN) {
			top[j].nr = i;
			top[j].count = c;
			if (top_count < SATCOOL_TOPN)
				top_count++;
		}
	}

	output(0, "frontier_satcool_would_skip per-syscall top %u:\n",
	       top_count);
	for (j = 0; j < (int)top_count; j++) {
		const char *sname = print_syscall_name(top[j].nr, false);

		output(0, "  %s=%lu\n", sname, top[j].count);
	}
	output(0, "frontier_satcool_would_skip per-syscall total: %lu\n",
	       total);
}

/*
 * Top-N per-syscall distribution dump for the SHADOW floored-barren
 * sub-floor demote.  Walks frontier_barren_would_skip_per_syscall[]
 * and emits the highest-bumping syscalls in descending order followed
 * by a trailing total.  Called from dump_stats_strategy_summary()
 * alongside the aggregate frontier_barren_* rows so the operator can
 * confirm the projected demote mass concentrates on the pure zero-arg
 * getter cohort and stays near zero on the object-producer / state-
 * mutator / heuristic-arm-spike sets the vetted skeleton is supposed
 * to exclude.
 *
 * Render-only: never read by the silent-regime accept site or the
 * predicate it gates.  Mode-OFF runs return before any output so the
 * default-off behaviour stays byte-identical to today; under shadow-
 * only or combined the header + total are always printed (even when
 * the array is empty) so an operator running a short or under-
 * populated session can confirm the wiring fired without having to
 * grep for absence, matching the satcool sibling's discipline.
 */
#define BARREN_TOPN 30

void dump_barren_would_skip_per_syscall_top(void)
{
	struct {
		unsigned int nr;
		unsigned long count;
	} top[BARREN_TOPN];
	unsigned int top_count = 0;
	unsigned long total = 0;
	unsigned int nr_to_scan;
	unsigned int i;
	int j;
	enum frontier_barren_demote_mode mode =
		__atomic_load_n(&frontier_barren_demote_mode,
				__ATOMIC_RELAXED);

	if (mode == FRONTIER_BARREN_DEMOTE_MODE_OFF)
		return;

	nr_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	if (nr_to_scan > MAX_NR_SYSCALL)
		nr_to_scan = MAX_NR_SYSCALL;

	memset(top, 0, sizeof(top));

	for (i = 0; i < nr_to_scan; i++) {
		unsigned long c =
			shm->stats.frontier.barren_would_skip_per_syscall[i];

		if (c == 0)
			continue;

		total += c;

		for (j = (int)top_count; j > 0 && c > top[j - 1].count; j--) {
			if (j < BARREN_TOPN)
				top[j] = top[j - 1];
		}
		if (j < BARREN_TOPN) {
			top[j].nr = i;
			top[j].count = c;
			if (top_count < BARREN_TOPN)
				top_count++;
		}
	}

	output(0, "frontier_barren_would_skip per-syscall top %u:\n",
	       top_count);
	for (j = 0; j < (int)top_count; j++) {
		const char *sname = print_syscall_name(top[j].nr, false);

		output(0, "  %s=%lu\n", sname, top[j].count);
	}
	output(0, "frontier_barren_would_skip per-syscall total: %lu\n",
	       total);
}

/*
 * Top-N per-syscall distribution dump for the SHADOW LIVE-regime
 * cooldown.  Walks frontier_live_would_skip_per_syscall[] and emits
 * the highest-bumping syscalls in descending order followed by a
 * trailing total.  Called from dump_stats_strategy_summary() alongside
 * the aggregate frontier_live_cooldown_candidates / frontier_live_
 * would_skip rows so the operator can see which syscalls drive the
 * LIVE-regime projection -- the bigger reclaim lever, since the LIVE
 * frontier regime carries far more pick volume than the silent regime
 * the satcool sibling above attributes.
 *
 * Render-only: never read by the LIVE accept site or the picker.
 * Unlike the satcool sibling there is no mode flag to gate on -- the
 * writer at the LIVE-regime miss attribution path bumps the per-
 * syscall counter (and the scalar it mirrors) unconditionally, so the
 * dump emits on every run; the header + total are always printed even
 * when the array is empty so an operator running a short or under-
 * populated session can confirm the wiring fired without having to
 * grep for absence, matching the satcool sibling's discipline.
 *
 * The biarch table-scan choice mirrors the satcool sibling and the
 * other per-syscall top-N emitters: under biarch only the 64-bit
 * table is walked, matching the slot-alias shape the LIVE-regime
 * miss writer site uses.
 */
#define LIVE_COOLDOWN_TOPN 30

void dump_live_cooldown_would_skip_per_syscall_top(void)
{
	struct {
		unsigned int nr;
		unsigned long count;
	} top[LIVE_COOLDOWN_TOPN];
	unsigned int top_count = 0;
	unsigned long total = 0;
	unsigned int nr_to_scan;
	unsigned int i;
	int j;

	nr_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	if (nr_to_scan > MAX_NR_SYSCALL)
		nr_to_scan = MAX_NR_SYSCALL;

	memset(top, 0, sizeof(top));

	for (i = 0; i < nr_to_scan; i++) {
		unsigned long c =
			shm->stats.frontier.live_would_skip_per_syscall[i];

		if (c == 0)
			continue;

		total += c;

		/* Insertion sort, descending by count, capped at LIVE_COOLDOWN_TOPN. */
		for (j = (int)top_count; j > 0 && c > top[j - 1].count; j--) {
			if (j < LIVE_COOLDOWN_TOPN)
				top[j] = top[j - 1];
		}
		if (j < LIVE_COOLDOWN_TOPN) {
			top[j].nr = i;
			top[j].count = c;
			if (top_count < LIVE_COOLDOWN_TOPN)
				top_count++;
		}
	}

	output(0, "frontier_live_would_skip per-syscall top %u:\n",
	       top_count);
	for (j = 0; j < (int)top_count; j++) {
		const char *sname = print_syscall_name(top[j].nr, false);

		output(0, "  %s=%lu\n", sname, top[j].count);
	}
	output(0, "frontier_live_would_skip per-syscall total: %lu\n",
	       total);
}

/*
 * Top-N per-syscall distribution dumps for the SHADOW LIVE-regime
 * cooldown discriminator.  Walks frontier_live_cool_would_skip_per_
 * syscall[] and frontier_live_cool_would_spare_per_syscall[]
 * separately so the operator can see, per-nr, both the projected
 * demote mass the discriminator would produce AND the projected
 * spare mass the discriminator is keeping out of the demote set.
 * The headline SHADOW_ONLY ramp gate: would_skip top must
 * concentrate on the legitimately-barren getter set (gettid /
 * sched_get_priority_max) and would_spare top must concentrate on
 * the productive set the over-cool was demoting (bpf /
 * io_uring_setup / openat / io_setup / futex / setxattrat); if
 * either distribution lands on the wrong axis COMBINED MUST NOT be
 * promoted.
 *
 * Called from dump_stats_strategy_summary() alongside the aggregate
 * frontier_live_cool_* scalar rows.  Render-only: never read by the
 * LIVE accept site or the picker.  Mode == OFF returns before any
 * output so the default-off behaviour stays byte-identical to today;
 * the writer at the LIVE-regime miss attribution path also early-
 * returns on OFF so the array stays empty there too.  Header +
 * total are printed even when the array is empty so an operator
 * running a short session can confirm the wiring fired without
 * having to grep for absence, matching the satcool / live cooldown
 * sibling discipline.
 *
 * The biarch table-scan choice mirrors the satcool / live cooldown
 * siblings: under biarch only the 64-bit table is walked, matching
 * the slot-alias shape the LIVE-regime miss writer site uses.
 */
#define LIVE_COOL_TOPN 30

void dump_live_cool_per_syscall_top(const unsigned long *arr,
					   const char *label)
{
	struct {
		unsigned int nr;
		unsigned long count;
	} top[LIVE_COOL_TOPN];
	unsigned int top_count = 0;
	unsigned long total = 0;
	unsigned int nr_to_scan;
	unsigned int i;
	int j;
	enum frontier_live_cooldown_mode mode =
		__atomic_load_n(&frontier_live_cooldown_mode,
				__ATOMIC_RELAXED);

	if (mode == FRONTIER_LIVE_COOLDOWN_MODE_OFF)
		return;

	nr_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	if (nr_to_scan > MAX_NR_SYSCALL)
		nr_to_scan = MAX_NR_SYSCALL;

	memset(top, 0, sizeof(top));

	for (i = 0; i < nr_to_scan; i++) {
		unsigned long c = arr[i];

		if (c == 0)
			continue;

		total += c;

		for (j = (int)top_count; j > 0 && c > top[j - 1].count; j--) {
			if (j < LIVE_COOL_TOPN)
				top[j] = top[j - 1];
		}
		if (j < LIVE_COOL_TOPN) {
			top[j].nr = i;
			top[j].count = c;
			if (top_count < LIVE_COOL_TOPN)
				top_count++;
		}
	}

	output(0, "%s per-syscall top %u:\n", label, top_count);
	for (j = 0; j < (int)top_count; j++) {
		const char *sname = print_syscall_name(top[j].nr, false);

		output(0, "  %s=%lu\n", sname, top[j].count);
	}
	output(0, "%s per-syscall total: %lu\n", label, total);
}

/*
 * Top-N per-syscall distribution dump for the SHADOW Path-A
 * regular_suppressed context-axis projection.  Walks context_regular_
 * suppressed_would_skip_per_syscall[] and emits the highest-bumping
 * syscalls in descending order followed by a trailing total.  Called
 * from dump_stats_strategy_summary() alongside the aggregate context_
 * regular_suppressed_* scalar rows so the operator can confirm the
 * projected demote mass concentrates on the measured EPERM hogs (fchown
 * / chown / lchown / fchownat + the cred family as seen at uid 1026)
 * and stays near zero on syscalls with unprivileged regular value
 * before any tuning of the classifier thresholds or promotion to a
 * live regular-pool deactivation.
 *
 * Render-only: never read by the pick-finalise site or the picker.
 * Mode == OFF returns before any output so the default-off behaviour
 * stays byte-identical to today; the writer at the pick-finalise site
 * also early-returns on OFF so the array stays empty there too.
 * Header + total are printed even when the array is empty so an
 * operator running a short or under-populated session can confirm the
 * wiring fired without having to grep for absence, matching the
 * satcool / live cooldown sibling discipline.
 *
 * The biarch table-scan choice mirrors the satcool / live cooldown
 * siblings: under biarch only the 64-bit table is walked, matching
 * the slot-alias shape the pick-finalise writer site uses.
 */
#define CONTEXT_REGULAR_SUPPRESSED_TOPN 30

void dump_context_regular_suppressed_per_syscall_top(void)
{
	struct {
		unsigned int nr;
		unsigned long count;
	} top[CONTEXT_REGULAR_SUPPRESSED_TOPN];
	unsigned int top_count = 0;
	unsigned long total = 0;
	unsigned int nr_to_scan;
	unsigned int i;
	int j;
	enum context_pool_mode mode =
		__atomic_load_n(&context_pool_mode, __ATOMIC_RELAXED);

	if (mode == CONTEXT_POOL_MODE_OFF)
		return;

	nr_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	if (nr_to_scan > MAX_NR_SYSCALL)
		nr_to_scan = MAX_NR_SYSCALL;

	memset(top, 0, sizeof(top));

	for (i = 0; i < nr_to_scan; i++) {
		unsigned long c =
			shm->stats.context_regular_suppressed_would_skip_per_syscall[i];

		if (c == 0)
			continue;

		total += c;

		for (j = (int)top_count;
		     j > 0 && c > top[j - 1].count;
		     j--) {
			if (j < CONTEXT_REGULAR_SUPPRESSED_TOPN)
				top[j] = top[j - 1];
		}
		if (j < CONTEXT_REGULAR_SUPPRESSED_TOPN) {
			top[j].nr = i;
			top[j].count = c;
			if (top_count < CONTEXT_REGULAR_SUPPRESSED_TOPN)
				top_count++;
		}
	}

	output(0, "context_regular_suppressed_would_skip per-syscall top %u:\n",
	       top_count);
	for (j = 0; j < (int)top_count; j++) {
		const char *sname = print_syscall_name(top[j].nr, false);

		output(0, "  %s=%lu\n", sname, top[j].count);
	}
	output(0, "context_regular_suppressed_would_skip per-syscall total: %lu\n",
	       total);
}
