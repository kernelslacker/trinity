/*
 * Periodic + per-syscall dump helpers.
 *
 * Carved verbatim out of stats.c.  Contains the dumps called from
 * the parent's periodic tick (defense_counters_periodic_dump,
 * cost_pool_periodic_dump, top_syscalls_periodic_dump,
 * vma_count_periodic_dump), the childop_split_dump shutdown +
 * per-tick emitter, the shadow-only per-syscall top-N helpers used
 * by the strategy summary (dump_satcool_would_skip_per_syscall_top,
 * dump_live_cooldown_would_skip_per_syscall_top,
 * dump_live_cool_per_syscall_top), and the descriptor-driven
 * defense_counters[] table with its defense_counter_load reader.
 *
 * The pct_thousandths permille helper moves with this cluster --
 * childop_split_dump is its only caller so co-locating keeps the
 * accompanying design comment intact (the extern prototype in
 * stats-internal.h from the earlier header commit stays in place,
 * cost-free until a second caller ever appears).
 *
 * defense_counters[] and defense_counter_load also live here: both
 * are read only from defense_counters_periodic_dump so file-static
 * scope is the tightest home for them.  The static top_syscalls_
 * emit_pool / _emit_frontier_yield helpers plus count_proc_maps_
 * lines are internal to this TU and stay static.
 */

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


/*
 * Periodic surface of the defense-counter family that dump_stats() only
 * emits at end-of-run.  Called once per main_loop tick from the parent;
 * every DEFENSE_DUMP_INTERVAL_SEC the diff between the current counter
 * value and the value cached at the prior dump is divided by the elapsed
 * window and emitted as a per-second rate, so an operator watching a
 * long fuzz run can see which guards are catching real wild writes vs
 * sitting at noise without waiting for the run to end.  Counters with a
 * zero delta are skipped so the per-window line stays short on a quiet
 * fleet; the whole block is suppressed entirely on a window where every
 * counter held flat.  Listed once in defense_counters[] so adding a new
 * defense counter only needs one edit to get periodic visibility.
 *
 * DEFENSE_DUMP_INTERVAL_SEC lives in stats-internal.h so the sibling
 * periodic rate dumps (cost_pool, top_syscalls) and the kcov_cmp
 * cluster all share one cadence value.
 */

static const struct {
	const char *name;
	size_t off;
	bool    from_aggregate;	/* true: read from parent_stats; false: shm->stats */
} defense_counters[] = {
	{ "shared_buffer_redirected",
	  offsetof(struct stats_aggregate, shared_buffer_redirected), true },
	{ "range_overlaps_shared_rejects",
	  offsetof(struct stats_aggregate, range_overlaps_shared_rejects), true },
	{ "libc_heap_redirected",
	  offsetof(struct stats_aggregate, libc_heap_redirected), true },
	{ "libc_heap_embedded_redirected",
	  offsetof(struct stats_aggregate, libc_heap_embedded_redirected), true },
	{ "asb_relocate_readable_skip",
	  offsetof(struct stats_aggregate, asb_relocate_readable_skip), true },
	{ "asb_relocate_copy_fault",
	  offsetof(struct stats_aggregate, asb_relocate_copy_fault), true },
	{ "heap_pointer_outside_cache",
	  offsetof(struct stats_aggregate, heap_pointer_outside_cache), true },
	{ "heap_brk_stale_window_hit",
	  offsetof(struct stats_aggregate, heap_brk_stale_window_hit), true },
	{ "mm_gate_post_slip",
	  offsetof(struct stats_aggregate, mm_gate_post_slip), true },
	{ "post_handler_corrupt_ptr",
	  offsetof(struct stats_aggregate, post_handler_corrupt_ptr), true },
	{ "validator_rejected",
	  offsetof(struct stats_aggregate, validator_rejected), true },
	{ "arg_constraint_repaired",
	  offsetof(struct stats_aggregate, arg_constraint_repaired), true },
	{ "arg_constraint_kept_incoherent",
	  offsetof(struct stats_aggregate, arg_constraint_kept_incoherent), true },
	{ "epoll_wait_null_events_alloc_fail",
	  offsetof(struct stats_s, epoll_wait_null_events_alloc_fail) },
	{ "epoll_wait_null_events_shared_reject",
	  offsetof(struct stats_s, epoll_wait_null_events_shared_reject) },
	{ "deferred_free_reject",
	  offsetof(struct stats_aggregate, deferred_free_reject), true },
	{ "deferred_free_reject_pathname",
	  offsetof(struct stats_aggregate, deferred_free_reject_pathname), true },
	{ "deferred_free_reject_iovec",
	  offsetof(struct stats_aggregate, deferred_free_reject_iovec), true },
	{ "deferred_free_reject_sockaddr",
	  offsetof(struct stats_aggregate, deferred_free_reject_sockaddr), true },
	{ "deferred_free_reject_other",
	  offsetof(struct stats_aggregate, deferred_free_reject_other), true },
	{ "snapshot_non_heap_reject",
	  offsetof(struct stats_aggregate, snapshot_non_heap_reject), true },
	{ "deferred_free_corrupt_ptr",
	  offsetof(struct stats_aggregate, deferred_free_corrupt_ptr), true },
	{ "arg_shadow_stomp",
	  offsetof(struct stats_aggregate, arg_shadow_stomp), true },
	{ "lock_word_scribbled",
	  offsetof(struct stats_aggregate, lock_word_scribbled), true },
	{ "lock_held_scribble",
	  offsetof(struct stats_s, lock_held_scribble) },
	{ "rec_canary_stomped",
	  offsetof(struct stats_s, rec_canary_stomped) },
	{ "rzs_blanket_reject",
	  offsetof(struct stats_s, rzs_blanket_reject) },
	{ "retfd_blanket_reject",
	  offsetof(struct stats_s, retfd_blanket_reject) },
	{ "arena_ptr_stale_caught_arg",
	  offsetof(struct stats_s, arena_ptr_stale_caught_arg) },
	{ "arena_ptr_stale_caught_post_state",
	  offsetof(struct stats_s, arena_ptr_stale_caught_post_state) },
	{ "execve_self_exec_blocked",
	  offsetof(struct stats_s, execve_self_exec_blocked) },
	{ "corpus_count_overcap_caught",
	  offsetof(struct stats_s, corpus_count_overcap_caught) },
	{ "sibling_mprotect_failed",
	  offsetof(struct stats_s, sibling_mprotect_failed) },
	{ "sibling_refreeze_count",
	  offsetof(struct stats_s, sibling_refreeze_count) },
	/* divergence-sentinel anomaly counter, sharded by enum
	 * sentinel_field.  One row per active field id so the periodic
	 * rate dump shows which monitored field is drifting rather than
	 * a lumped headline number.  Gaps in the enum (5..9) are simply
	 * not listed here — their array slots stay zero.
	 */
	{ "divergence_sentinel_anomalies_sysname",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_UNAME_SYSNAME]) },
	{ "divergence_sentinel_anomalies_release",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_UNAME_RELEASE]) },
	{ "divergence_sentinel_anomalies_version",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_UNAME_VERSION]) },
	{ "divergence_sentinel_anomalies_machine",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_UNAME_MACHINE]) },
	{ "divergence_sentinel_anomalies_totalram",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_SYSINFO_TOTALRAM]) },
	{ "divergence_sentinel_anomalies_totalswap",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_SYSINFO_TOTALSWAP]) },
	{ "divergence_sentinel_anomalies_totalhigh",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_SYSINFO_TOTALHIGH]) },
	{ "divergence_sentinel_anomalies_mem_unit",
	  offsetof(struct stats_s, divergence_sentinel_anomalies[SF_SYSINFO_MEM_UNIT]) },
	/* SF_UNAME_RELEASE / SF_UNAME_MACHINE bumps land here instead of
	 * on the per-field anomaly shards above — personality()-driven
	 * legitimate drift, kept separate so the corruption histogram
	 * stays a real signal. */
	{ "divergence_sentinel_expected_drift",
	  offsetof(struct stats_s, divergence_sentinel_expected_drift) },
	{ "iouring_enter_mask_corrupt",
	  offsetof(struct stats_s, iouring_enter_mask_corrupt) },
	{ "watchdog_sigalrm_clobbered",
	  offsetof(struct stats_s, watchdog_sigalrm_clobbered) },
	{ "watchdog_sigxcpu_clobbered",
	  offsetof(struct stats_s, watchdog_sigxcpu_clobbered) },
	{ "watchdog_sigalrm_reinstalled",
	  offsetof(struct stats_s, watchdog_sigalrm_reinstalled) },
	{ "watchdog_sigxcpu_reinstalled",
	  offsetof(struct stats_s, watchdog_sigxcpu_reinstalled) },
	{ "fd_event_ring_corrupted",
	  offsetof(struct stats_s, fd_event_ring_corrupted) },
	{ "fd_event_ring_overwritten",
	  offsetof(struct stats_s, fd_event_ring_overwritten) },
	{ "stats_ring_corrupted",
	  offsetof(struct stats_s, stats_ring_corrupted) },
	{ "stats_ring_overwritten",
	  offsetof(struct stats_s, stats_ring_overwritten) },
	{ "fd_event_payload_corrupt",
	  offsetof(struct stats_s, fd_event_payload_corrupt) },
	{ "destroy_object_idx_corrupt",
	  offsetof(struct stats_s, destroy_object_idx_corrupt) },
	{ "global_obj_uaf_caught",
	  offsetof(struct stats_s, global_obj_uaf_caught) },
	{ "maps_pool_draw_exhausted",
	  offsetof(struct stats_s, maps.pool_draw_exhausted) },
	{ "maps_reject_pool_empty",
	  offsetof(struct stats_s, maps.reject_pool_empty) },
	{ "maps_reject_bogus_obj_ptr",
	  offsetof(struct stats_s, maps.reject_bogus_obj_ptr) },
	{ "maps_reject_alloc_track_miss",
	  offsetof(struct stats_s, maps.reject_alloc_track_miss) },
	{ "maps_reject_alloc_track_miss_anon",
	  offsetof(struct stats_s, maps.reject_alloc_track_miss_anon) },
	{ "maps_reject_alloc_track_miss_file",
	  offsetof(struct stats_s, maps.reject_alloc_track_miss_file) },
	{ "maps_reject_alloc_track_miss_testfile",
	  offsetof(struct stats_s, maps.reject_alloc_track_miss_testfile) },
	{ "maps_reject_size_zero",
	  offsetof(struct stats_s, maps.reject_size_zero) },
	{ "maps_reject_size_too_large",
	  offsetof(struct stats_s, maps.reject_size_too_large) },
	/* Map selection / pick-cost rows.  Per-second
	 * rates here let the periodic dump answer "is the
	 * 1000-iter retry budget actually contended" and "which
	 * pool / prot-mask is paying the rejection cost", the
	 * questions the side-index TIER-2/3 rows are gated on. */
	{ "maps_pool_chosen_anon",
	  offsetof(struct stats_s, maps.pool_chosen_anon) },
	{ "maps_pool_chosen_file",
	  offsetof(struct stats_s, maps.pool_chosen_file) },
	{ "maps_pool_chosen_testfile",
	  offsetof(struct stats_s, maps.pool_chosen_testfile) },
	{ "maps_reject_pool_empty_anon",
	  offsetof(struct stats_s, maps.reject_pool_empty_anon) },
	{ "maps_reject_pool_empty_file",
	  offsetof(struct stats_s, maps.reject_pool_empty_file) },
	{ "maps_reject_pool_empty_testfile",
	  offsetof(struct stats_s, maps.reject_pool_empty_testfile) },
	{ "maps_prot_reject_mask_0",
	  offsetof(struct stats_s, maps.prot_reject_by_mask[0]) },
	{ "maps_prot_reject_mask_R",
	  offsetof(struct stats_s, maps.prot_reject_by_mask[1]) },
	{ "maps_prot_reject_mask_W",
	  offsetof(struct stats_s, maps.prot_reject_by_mask[2]) },
	{ "maps_prot_reject_mask_RW",
	  offsetof(struct stats_s, maps.prot_reject_by_mask[3]) },
	{ "maps_prot_reject_mask_X",
	  offsetof(struct stats_s, maps.prot_reject_by_mask[4]) },
	{ "maps_prot_reject_mask_RX",
	  offsetof(struct stats_s, maps.prot_reject_by_mask[5]) },
	{ "maps_prot_reject_mask_WX",
	  offsetof(struct stats_s, maps.prot_reject_by_mask[6]) },
	{ "maps_prot_reject_mask_RWX",
	  offsetof(struct stats_s, maps.prot_reject_by_mask[7]) },
	{ "maps_pick_attempts_sum",
	  offsetof(struct stats_s, maps.pick_attempts_sum) },
	{ "maps_pick_successes",
	  offsetof(struct stats_s, maps.pick_successes) },
	{ "maps_pick_with_prot_attempts_sum",
	  offsetof(struct stats_s, maps.pick_with_prot_attempts_sum) },
	{ "maps_pick_with_prot_successes",
	  offsetof(struct stats_s, maps.pick_with_prot_successes) },
	/* SAMPLED get_map_handle() reject-loop cost.  cycles_sum
	 * accumulates the total rdtsc delta across the loop body on
	 * gated 1/N calls; cycles_count is the sample denominator.
	 * See include/stats.h and mm/maps.c for the sampling gate. */
	{ "maps_pick_cycles_sampled_sum",
	  offsetof(struct stats_s, maps.pick_cycles_sampled_sum) },
	{ "maps_pick_cycles_sampled_count",
	  offsetof(struct stats_s, maps.pick_cycles_sampled_count) },
	/* Log2 histogram of the get_map_handle() retry-loop exit
	 * index, bumped on both success and exhaustion paths.  Mirrors
	 * fd_live_remove_scan_histogram bucket layout: hist_0 is
	 * first-iteration hits, hist_ge64 is the saturating tail. */
	{ "maps_pick_scan_hist_0",
	  offsetof(struct stats_s, maps.pick_scan_histogram[0]) },
	{ "maps_pick_scan_hist_1",
	  offsetof(struct stats_s, maps.pick_scan_histogram[1]) },
	{ "maps_pick_scan_hist_2_3",
	  offsetof(struct stats_s, maps.pick_scan_histogram[2]) },
	{ "maps_pick_scan_hist_4_7",
	  offsetof(struct stats_s, maps.pick_scan_histogram[3]) },
	{ "maps_pick_scan_hist_8_15",
	  offsetof(struct stats_s, maps.pick_scan_histogram[4]) },
	{ "maps_pick_scan_hist_16_31",
	  offsetof(struct stats_s, maps.pick_scan_histogram[5]) },
	{ "maps_pick_scan_hist_32_63",
	  offsetof(struct stats_s, maps.pick_scan_histogram[6]) },
	{ "maps_pick_scan_hist_ge64",
	  offsetof(struct stats_s, maps.pick_scan_histogram[7]) },
	{ "maps_type_resolution_calls",
	  offsetof(struct stats_s, maps.type_resolution_calls) },
	{ "maps_type_resolution_scan_length_sum",
	  offsetof(struct stats_s, maps.type_resolution_scan_length_sum) },
	{ "maps_type_resolution_hits",
	  offsetof(struct stats_s, maps.type_resolution_hits) },
	/* FD bookkeeping rows.  fd_live_remove
	 * histogram surfaces whether the linear scan
	 * an fd live-list index would replace is actually expensive;
	 * fd_event_full_* says which producer drove a ring
	 * overflow; close_range_* surfaces the compression ratio
	 * the range opcode buys vs the per-fd path. */
	{ "fd_live_remove_calls",
	  offsetof(struct stats_s, fd_live_remove_calls) },
	{ "fd_live_remove_miss",
	  offsetof(struct stats_s, fd_live_remove_miss) },
	{ "fd_live_remove_scan_hist_0",
	  offsetof(struct stats_s, fd_live_remove_scan_histogram[0]) },
	{ "fd_live_remove_scan_hist_1",
	  offsetof(struct stats_s, fd_live_remove_scan_histogram[1]) },
	{ "fd_live_remove_scan_hist_2_3",
	  offsetof(struct stats_s, fd_live_remove_scan_histogram[2]) },
	{ "fd_live_remove_scan_hist_4_7",
	  offsetof(struct stats_s, fd_live_remove_scan_histogram[3]) },
	{ "fd_live_remove_scan_hist_8_15",
	  offsetof(struct stats_s, fd_live_remove_scan_histogram[4]) },
	{ "fd_live_remove_scan_hist_16_31",
	  offsetof(struct stats_s, fd_live_remove_scan_histogram[5]) },
	{ "fd_live_remove_scan_hist_32_63",
	  offsetof(struct stats_s, fd_live_remove_scan_histogram[6]) },
	{ "fd_live_remove_scan_hist_ge64",
	  offsetof(struct stats_s, fd_live_remove_scan_histogram[7]) },
	{ "fd_event_full_close",
	  offsetof(struct stats_s, fd_event_full_close) },
	{ "fd_event_full_evict",
	  offsetof(struct stats_s, fd_event_full_evict) },
	{ "fd_event_full_close_range",
	  offsetof(struct stats_s, fd_event_full_close_range) },
	{ "fd_event_close_range_enqueued",
	  offsetof(struct stats_s, fd_event_close_range_enqueued) },
	{ "fd_event_close_range_length_sum",
	  offsetof(struct stats_s, fd_event_close_range_length_sum) },
	/* Chain-corpus duplicate-shape rate.  Dup
	 * vs unique count over the K=8 most-recent slots; rate
	 * dup/(dup+unique) gates a per-shape chain quota. */
	{ "chain_corpus_save_dup_shape",
	  offsetof(struct stats_s, chain_corpus_save_dup_shape) },
	{ "chain_corpus_save_unique_shape",
	  offsetof(struct stats_s, chain_corpus_save_unique_shape) },
	/* Per-resource-kind chain-generation telemetry
	 * (--chain-resource-typing).  One row per (kind, counter);
	 * per-kind naming so the JSON emitter and check-stats-reachable
	 * audit both see distinct symbols and rate-of-change
	 * dashboards can plot each resource family independently.
	 * Kind ordering MUST match enum chain_resource_kind in
	 * include/sequence.h. */
	{ "chain_restype_produced_epoll_fd",
	  offsetof(struct stats_s, chain_restype_produced[CHAIN_RESTYPE_EPOLL_FD]) },
	{ "chain_restype_produced_timerfd",
	  offsetof(struct stats_s, chain_restype_produced[CHAIN_RESTYPE_TIMERFD]) },
	{ "chain_restype_produced_eventfd",
	  offsetof(struct stats_s, chain_restype_produced[CHAIN_RESTYPE_EVENTFD]) },
	{ "chain_restype_produced_io_uring_fd",
	  offsetof(struct stats_s, chain_restype_produced[CHAIN_RESTYPE_IO_URING_FD]) },
	{ "chain_restype_produced_pidfd",
	  offsetof(struct stats_s, chain_restype_produced[CHAIN_RESTYPE_PIDFD]) },
	{ "chain_restype_produced_socket_tcp",
	  offsetof(struct stats_s, chain_restype_produced[CHAIN_RESTYPE_SOCKET_TCP]) },
	{ "chain_restype_produced_bpf_map_fd",
	  offsetof(struct stats_s, chain_restype_produced[CHAIN_RESTYPE_BPF_MAP_FD]) },
	{ "chain_restype_would_bias_epoll_fd",
	  offsetof(struct stats_s, chain_restype_would_bias[CHAIN_RESTYPE_EPOLL_FD]) },
	{ "chain_restype_would_bias_timerfd",
	  offsetof(struct stats_s, chain_restype_would_bias[CHAIN_RESTYPE_TIMERFD]) },
	{ "chain_restype_would_bias_eventfd",
	  offsetof(struct stats_s, chain_restype_would_bias[CHAIN_RESTYPE_EVENTFD]) },
	{ "chain_restype_would_bias_io_uring_fd",
	  offsetof(struct stats_s, chain_restype_would_bias[CHAIN_RESTYPE_IO_URING_FD]) },
	{ "chain_restype_would_bias_pidfd",
	  offsetof(struct stats_s, chain_restype_would_bias[CHAIN_RESTYPE_PIDFD]) },
	{ "chain_restype_would_bias_socket_tcp",
	  offsetof(struct stats_s, chain_restype_would_bias[CHAIN_RESTYPE_SOCKET_TCP]) },
	{ "chain_restype_would_bias_bpf_map_fd",
	  offsetof(struct stats_s, chain_restype_would_bias[CHAIN_RESTYPE_BPF_MAP_FD]) },
	{ "chain_restype_biased_epoll_fd",
	  offsetof(struct stats_s, chain_restype_biased[CHAIN_RESTYPE_EPOLL_FD]) },
	{ "chain_restype_biased_timerfd",
	  offsetof(struct stats_s, chain_restype_biased[CHAIN_RESTYPE_TIMERFD]) },
	{ "chain_restype_biased_eventfd",
	  offsetof(struct stats_s, chain_restype_biased[CHAIN_RESTYPE_EVENTFD]) },
	{ "chain_restype_biased_io_uring_fd",
	  offsetof(struct stats_s, chain_restype_biased[CHAIN_RESTYPE_IO_URING_FD]) },
	{ "chain_restype_biased_pidfd",
	  offsetof(struct stats_s, chain_restype_biased[CHAIN_RESTYPE_PIDFD]) },
	{ "chain_restype_biased_socket_tcp",
	  offsetof(struct stats_s, chain_restype_biased[CHAIN_RESTYPE_SOCKET_TCP]) },
	{ "chain_restype_biased_bpf_map_fd",
	  offsetof(struct stats_s, chain_restype_biased[CHAIN_RESTYPE_BPF_MAP_FD]) },
	{ "chain_restype_save_epoll_fd",
	  offsetof(struct stats_s, chain_restype_save[CHAIN_RESTYPE_EPOLL_FD]) },
	{ "chain_restype_save_timerfd",
	  offsetof(struct stats_s, chain_restype_save[CHAIN_RESTYPE_TIMERFD]) },
	{ "chain_restype_save_eventfd",
	  offsetof(struct stats_s, chain_restype_save[CHAIN_RESTYPE_EVENTFD]) },
	{ "chain_restype_save_io_uring_fd",
	  offsetof(struct stats_s, chain_restype_save[CHAIN_RESTYPE_IO_URING_FD]) },
	{ "chain_restype_save_pidfd",
	  offsetof(struct stats_s, chain_restype_save[CHAIN_RESTYPE_PIDFD]) },
	{ "chain_restype_save_socket_tcp",
	  offsetof(struct stats_s, chain_restype_save[CHAIN_RESTYPE_SOCKET_TCP]) },
	{ "chain_restype_save_bpf_map_fd",
	  offsetof(struct stats_s, chain_restype_save[CHAIN_RESTYPE_BPF_MAP_FD]) },
	{ "chain_restype_replay_win_epoll_fd",
	  offsetof(struct stats_s, chain_restype_replay_win[CHAIN_RESTYPE_EPOLL_FD]) },
	{ "chain_restype_replay_win_timerfd",
	  offsetof(struct stats_s, chain_restype_replay_win[CHAIN_RESTYPE_TIMERFD]) },
	{ "chain_restype_replay_win_eventfd",
	  offsetof(struct stats_s, chain_restype_replay_win[CHAIN_RESTYPE_EVENTFD]) },
	{ "chain_restype_replay_win_io_uring_fd",
	  offsetof(struct stats_s, chain_restype_replay_win[CHAIN_RESTYPE_IO_URING_FD]) },
	{ "chain_restype_replay_win_pidfd",
	  offsetof(struct stats_s, chain_restype_replay_win[CHAIN_RESTYPE_PIDFD]) },
	{ "chain_restype_replay_win_socket_tcp",
	  offsetof(struct stats_s, chain_restype_replay_win[CHAIN_RESTYPE_SOCKET_TCP]) },
	{ "chain_restype_replay_win_bpf_map_fd",
	  offsetof(struct stats_s, chain_restype_replay_win[CHAIN_RESTYPE_BPF_MAP_FD]) },
	{ "deferred_free_reject_misaligned",
	  offsetof(struct stats_s, deferred_free_reject_misaligned) },
	{ "deferred_free_reject_corrupt_shape",
	  offsetof(struct stats_s, deferred_free_reject_corrupt_shape) },
	{ "deferred_free_reject_non_heap",
	  offsetof(struct stats_s, deferred_free_reject_non_heap) },
	{ "deferred_free_reject_untracked",
	  offsetof(struct stats_s, deferred_free_reject_untracked) },
	{ "nested_scrub_reject_untracked",
	  offsetof(struct stats_s, nested_scrub_reject_untracked) },
	{ "deferred_free_reject_shared_region",
	  offsetof(struct stats_s, deferred_free_reject_shared_region) },
	{ "deferred_free_outstanding_vmas",
	  offsetof(struct stats_s, deferred_free_outstanding_vmas) },
	{ "deferred_free_vma_fallback_immediate",
	  offsetof(struct stats_s, deferred_free_vma_fallback_immediate) },
	{ "deferred_free_enomem_drain",
	  offsetof(struct stats_s, deferred_free_enomem_drain) },
	{ "deferred_free_rw_restore_enomem",
	  offsetof(struct stats_s, deferred_free_rw_restore_enomem) },
	{ "deferred_free_pre_dispatch_leaked",
	  offsetof(struct stats_s, deferred_free_pre_dispatch_leaked) },
	{ "ring_evict_leaked",
	  offsetof(struct stats_s, ring_evict_leaked) },
	{ "deferred_free_ring_owned_skip",
	  offsetof(struct stats_s, deferred_free_ring_owned_skip) },
	{ "deferred_free_double_admit_skip",
	  offsetof(struct stats_s, deferred_free_double_admit_skip) },
	{ "alloc_track_refresh_ring_owned_skip",
	  offsetof(struct stats_s, alloc_track_refresh_ring_owned_skip) },
	{ "alloc_track_refresh_unverified_skip",
	  offsetof(struct stats_s, alloc_track_refresh_unverified_skip) },
	{ "alloc_track_refresh_consume_miss",
	  offsetof(struct stats_s, alloc_track_refresh_consume_miss) },
	{ "pagecache_canary_corrupt_caught",
	  offsetof(struct stats_s, pagecache_canary_corrupt_caught) },
	{ "objpool_array_stale_caught",
	  offsetof(struct stats_s, objpool_array_stale_caught) },
	/* genetlink registry per-family dispatch counters; rate-of-change
	 * surfaces the live family selection mix without waiting for the
	 * end-of-run summary.  A counter that stays at zero across an
	 * interval window with the others advancing flags either a missing
	 * registry entry or a family the controller never resolved. */
	{ "genl_family_calls_devlink",
	  offsetof(struct stats_s, genl_family_calls_devlink) },
	{ "genl_family_calls_nl80211",
	  offsetof(struct stats_s, genl_family_calls_nl80211) },
	{ "genl_family_calls_taskstats",
	  offsetof(struct stats_s, genl_family_calls_taskstats) },
	{ "genl_family_calls_ethtool",
	  offsetof(struct stats_s, genl_family_calls_ethtool) },
	{ "genl_family_calls_mptcp_pm",
	  offsetof(struct stats_s, genl_family_calls_mptcp_pm) },
	{ "genl_family_calls_tipc",
	  offsetof(struct stats_s, genl_family_calls_tipc) },
	{ "genl_family_calls_wireguard",
	  offsetof(struct stats_s, genl_family_calls_wireguard) },
	{ "genl_family_calls_l2tp",
	  offsetof(struct stats_s, genl_family_calls_l2tp) },
	{ "genl_family_calls_gtp",
	  offsetof(struct stats_s, genl_family_calls_gtp) },
	{ "genl_family_calls_macsec",
	  offsetof(struct stats_s, genl_family_calls_macsec) },
	{ "genl_family_calls_netlabel",
	  offsetof(struct stats_s, genl_family_calls_netlabel) },
	{ "genl_family_calls_team",
	  offsetof(struct stats_s, genl_family_calls_team) },
	{ "genl_family_calls_hsr",
	  offsetof(struct stats_s, genl_family_calls_hsr) },
	{ "genl_family_calls_fou",
	  offsetof(struct stats_s, genl_family_calls_fou) },
	{ "genl_family_calls_psample",
	  offsetof(struct stats_s, genl_family_calls_psample) },
	{ "genl_family_calls_nfsd",
	  offsetof(struct stats_s, genl_family_calls_nfsd) },
	{ "genl_family_calls_ila",
	  offsetof(struct stats_s, genl_family_calls_ila) },
	{ "genl_family_calls_ioam6",
	  offsetof(struct stats_s, genl_family_calls_ioam6) },
	{ "genl_family_calls_seg6",
	  offsetof(struct stats_s, genl_family_calls_seg6) },
	{ "genl_family_calls_thermal",
	  offsetof(struct stats_s, genl_family_calls_thermal) },
	{ "genl_family_calls_ipvs",
	  offsetof(struct stats_s, genl_family_calls_ipvs) },
	/* nfnetlink registry per-subsys dispatch counters; same diagnostic
	 * value as the genl ones above but for NETLINK_NETFILTER subsystems.
	 * Lets an operator see the live ctnetlink/nftables/ipset traffic
	 * split at 10-minute granularity without waiting for run end. */
	{ "nfnl_subsys_calls_ctnetlink",
	  offsetof(struct stats_s, nfnl_subsys_calls_ctnetlink) },
	{ "nfnl_subsys_calls_ctnetlink_exp",
	  offsetof(struct stats_s, nfnl_subsys_calls_ctnetlink_exp) },
	{ "nfnl_subsys_calls_nftables",
	  offsetof(struct stats_s, nfnl_subsys_calls_nftables) },
	{ "nfnl_subsys_calls_ipset",
	  offsetof(struct stats_s, nfnl_subsys_calls_ipset) },
	/* UCB1 bandit CMP-novelty reward firings: bumped from
	 * maybe_rotate_strategy() each time the just-finished window had
	 * enough novel comparison constants to clear the integer reward
	 * weight.  Surfaces whether the CMP feedback is meaningfully
	 * contributing to arm selection. */
	{ "bandit_cmp_reward_added",
	  offsetof(struct stats_s, bandit_cmp_reward_added) },
	/* Sibling of bandit_cmp_reward_added for the edge-count secondary
	 * reward.  Fires on windows where pc_edge_count /
	 * EDGE_COUNT_BANDIT_REWARD_WEIGHT_RECIPROCAL was non-zero under
	 * either SHADOW_ONLY or COMBINED; zero on default runs (mode OFF).
	 * Periodic firing rate is the gate the operator watches before
	 * promoting the mode to COMBINED. */
	{ "bandit_edge_count_reward_added",
	  offsetof(struct stats_s, bandit_edge_count_reward_added) },
	/* Picks accepted by STRATEGY_COVERAGE_FRONTIER's frontier-weighted
	 * roulette wheel.  Rate-of-change tracks the arm's actual share of
	 * the fleet's syscall throughput when the bandit picker selects it. */
	{ "frontier_strategy_picks",
	  offsetof(struct stats_s, frontier.strategy_picks) },
	/* Saturating-subtract clamps fired during frontier ring rotation --
	 * see comment on struct field.  Non-zero is a correctness flag, not
	 * tuning data. */
	{ "frontier_underflow_prevented",
	  offsetof(struct stats_s, frontier.underflow_prevented) },
	/* Plateau-intervention rotations that selected the frontier arm.
	 * Held side-channel so the learner-facing bandit_pulls[] stays
	 * clean; the snapshot path folds this back in for the plateau
	 * classifier's frontier_cold rule. */
	{ "frontier_intervention_pulls",
	  offsetof(struct stats_s, frontier.intervention_pulls) },
	/* Accept-regime split of frontier_strategy_picks.  Sum equals
	 * frontier_strategy_picks; the periodic ratio surfaces whether the
	 * picker is steering on the K-window ring (live) or has collapsed
	 * to the lifetime cold-weight fallback (silent). */
	{ "frontier_live_picks",
	  offsetof(struct stats_s, frontier.live_picks) },
	{ "frontier_silent_picks",
	  offsetof(struct stats_s, frontier.silent_picks) },
	/* SHADOW-ONLY decay accounting under the tightened no-novelty
	 * predicate (consecutive silent picks past threshold AND no CMP
	 * insert AND no SUCCESS-bucket errno shift since the streak's
	 * most recent reset).  Sibling of frontier_shadow_decay_candidates;
	 * see the struct-field comment in include/stats.h for the per-
	 * counter semantics. */
	{ "frontier_decay_candidates",
	  offsetof(struct stats_s, frontier.decay_candidates) },
	{ "frontier_decay_would_skip",
	  offsetof(struct stats_s, frontier.decay_would_skip) },
	{ "frontier_silent_decay_live_rejects",
	  offsetof(struct stats_s, frontier.silent_decay_live_rejects) },
	/* SHADOW-ONLY saturation-cooldown predicate accounting (gated by
	 * --frontier-saturation-cooldown != off).  Sibling block of the
	 * silent-streak decay scalars above; this one targets the same
	 * wasteful-silent-pick shape but uses the windowed frontier-edge
	 * ring for plateau and the first-success-TRANSITION + distinct-CMP
	 * spare lanes for the struct-arg backlog.  See the struct-field
	 * comment in include/stats.h for per-counter semantics. */
	{ "frontier_satcool_candidates",
	  offsetof(struct stats_s, frontier.satcool_candidates) },
	{ "frontier_satcool_would_skip",
	  offsetof(struct stats_s, frontier.satcool_would_skip) },
	{ "frontier_satcool_spared_arggen",
	  offsetof(struct stats_s, frontier.satcool_spared_arggen) },
	{ "frontier_satcool_spared_objproducer",
	  offsetof(struct stats_s, frontier.satcool_spared_objproducer) },
	/* SHADOW-ONLY floored-barren sub-floor demote scalars (gated by
	 * --frontier-barren-demote != off).  Sibling of the frontier_
	 * satcool_* scalars above; targets the pure zero-arg getter set
	 * whose lifetime PC-edge yield has plateaued to a hard floor.
	 * See the struct-field comment in include/stats.h for the
	 * per-counter contract. */
	{ "frontier_barren_candidates",
	  offsetof(struct stats_s, frontier.barren_candidates) },
	{ "frontier_barren_would_skip",
	  offsetof(struct stats_s, frontier.barren_would_skip) },
	/* SHADOW-ONLY LIVE-regime cooldown discriminator scalars (gated
	 * by --frontier-live-cooldown-mode != off).  Sibling of the
	 * frontier_satcool_* scalars above; this row projects the
	 * DISCRIMINATED LIVE-regime cooldown demote mass (miss-streak
	 * AND magnitude floor AND no spare lane fires).  Compare against
	 * the undiscriminated frontier_live_would_skip projection for
	 * the over-cool the discriminator removes -- the SHADOW_ONLY
	 * ramp gate. */
	{ "frontier_live_cool_candidates",
	  offsetof(struct stats_s, frontier.live_cool_candidates) },
	{ "frontier_live_cool_would_skip",
	  offsetof(struct stats_s, frontier.live_cool_would_skip) },
	{ "frontier_live_cool_spared_windowed",
	  offsetof(struct stats_s, frontier.live_cool_spared_windowed) },
	{ "frontier_live_cool_spared_arggen",
	  offsetof(struct stats_s, frontier.live_cool_spared_arggen) },
	{ "frontier_live_cool_spared_objproducer",
	  offsetof(struct stats_s, frontier.live_cool_spared_objproducer) },
	/* SHADOW-ONLY Path-A "regular_suppressed" context-axis projection
	 * (gated by --context-pool != off).  See the struct-field comment
	 * in include/stats.h for the per-counter semantics and the enum
	 * context_pool_mode comment in include/strategy.h for the mode
	 * contract.  The (would_skip / candidates) ratio is the projected
	 * regular-pool pick share a live Path-A deactivation would
	 * reclaim; the spared_* triple partitions the spare cascade. */
	{ "context_regular_suppressed_candidates",
	  offsetof(struct stats_s, context_regular_suppressed_candidates) },
	{ "context_regular_suppressed_would_skip",
	  offsetof(struct stats_s, context_regular_suppressed_would_skip) },
	{ "context_regular_suppressed_spared_windowed",
	  offsetof(struct stats_s, context_regular_suppressed_spared_windowed) },
	{ "context_regular_suppressed_spared_arggen",
	  offsetof(struct stats_s, context_regular_suppressed_spared_arggen) },
	{ "context_regular_suppressed_spared_objproducer",
	  offsetof(struct stats_s, context_regular_suppressed_spared_objproducer) },
	/* SHADOW-ONLY LIVE-regime cooldown projections, paired with
	 * frontier_live_miss_streak_per_syscall[].  Candidates is edge-
	 * triggered at FRONTIER_LIVE_MISS_COOLDOWN crossings; would_skip is
	 * cumulative across every LIVE-regime miss past the threshold.  See
	 * the struct-field comments in include/stats.h and the
	 * FRONTIER_LIVE_MISS_COOLDOWN comment in include/strategy.h for the
	 * predicate contract. */
	{ "frontier_live_cooldown_candidates",
	  offsetof(struct stats_s, frontier.live_cooldown_candidates) },
	{ "frontier_live_would_skip",
	  offsetof(struct stats_s, frontier.live_would_skip) },
	/* Did-decay counter for the LIVE-regime early ring-decay path.
	 * Bumped per (nr, rotation) where the early ring-decay in
	 * frontier_window_advance actually halved a non-zero cached sum. */
	{ "frontier_live_cooldown_decays",
	  offsetof(struct stats_s, frontier.live_cooldown_decays) },
	/* Live reject count for the blanket LIVE-regime probabilistic
	 * pick-reject gate.  See the struct-field comment in
	 * include/stats.h and the FRONTIER_LIVE_DECAY_REJECT_DENOM comment
	 * in include/strategy.h for the probabilistic-reject contract. */
	{ "frontier_live_decay_live_rejects",
	  offsetof(struct stats_s, frontier.live_decay_live_rejects) },
	/* SHADOW-ONLY wall-lever accounting.  Eligible_total is
	 * the denominator (every plateau-active pick the lever saw); would_
	 * suppress_total is the projected reclaim count a live variant would
	 * produce.  See the struct-field comment in include/stats.h for the
	 * predicate contract. */
	{ "wall_lever_eligible_total",
	  offsetof(struct stats_s, wall_lever_eligible_total) },
	{ "wall_lever_would_suppress_total",
	  offsetof(struct stats_s, wall_lever_would_suppress_total) },
	/* SHADOW + per-child A/B accounting for the errno-plateau decay at
	 * the coverage-frontier picker's silent-regime accept site.  See the
	 * struct-field comments in include/stats.h and the FRONTIER_ERRNO_
	 * PLATEAU_* contract in include/strategy.h for the per-counter
	 * semantics and the would_skip vs live_rejects vs overlap_silent
	 * triple. */
	{ "frontier_errno_decay_would_skip",
	  offsetof(struct stats_s, frontier.errno_decay_would_skip) },
	{ "frontier_errno_decay_live_rejects",
	  offsetof(struct stats_s, frontier.errno_decay_live_rejects) },
	{ "frontier_errno_decay_overlap_silent",
	  offsetof(struct stats_s, frontier.errno_decay_overlap_silent) },
	/* SHADOW-ONLY A/B scoring for the frontier-blend cold-weight
	 * blend.  The picker still consumes the OLD weight; these counters
	 * expose how often the blended formula would have steered
	 * differently and by how much.  See the struct-field comment in
	 * include/stats.h for the per-counter semantics. */
	{ "frontier_blend_samples",
	  offsetof(struct stats_s, frontier.blend_samples) },
	{ "frontier_blend_new_lower",
	  offsetof(struct stats_s, frontier.blend_new_lower) },
	{ "frontier_blend_new_higher",
	  offsetof(struct stats_s, frontier.blend_new_higher) },
	{ "frontier_blend_new_equal",
	  offsetof(struct stats_s, frontier.blend_new_equal) },
	{ "frontier_blend_old_weight_sum",
	  offsetof(struct stats_s, frontier.blend_old_weight_sum) },
	{ "frontier_blend_new_weight_sum",
	  offsetof(struct stats_s, frontier.blend_new_weight_sum) },
	/* Shadow per-band counters for --reach-band.  All zero on default
	 * (OFF) runs -- the gate in frontier_cold_weight() early-outs
	 * before the bumps.  See the reach_band_* field-comment block in
	 * include/stats.h for SHADOW_ONLY vs COMBINED reading and the
	 * REACH_BAND_IDX_LOW/_MID/_HIGH band semantics. */
	{ "reach_band_picks_low",
	  offsetof(struct stats_s,
		   reach_band_picks_per_band[REACH_BAND_IDX_LOW]) },
	{ "reach_band_picks_mid",
	  offsetof(struct stats_s,
		   reach_band_picks_per_band[REACH_BAND_IDX_MID]) },
	{ "reach_band_picks_high",
	  offsetof(struct stats_s,
		   reach_band_picks_per_band[REACH_BAND_IDX_HIGH]) },
	{ "reach_band_would_demote_mid",
	  offsetof(struct stats_s, reach_band_would_demote_mid) },
	{ "reach_band_would_boost_high",
	  offsetof(struct stats_s, reach_band_would_boost_high) },
	/* Observability for the adaptive expensive-syscall accept gate.
	 * See the expensive_adaptive_* field-comment block in include/
	 * stats.h and the expensive_accept() helper in random-syscall.c
	 * for the OFF / SHADOW_ONLY / COMBINED mode contract. */
	{ "expensive_adaptive_samples",
	  offsetof(struct stats_s, expensive_adaptive_samples) },
	{ "expensive_adaptive_extra_accepts",
	  offsetof(struct stats_s, expensive_adaptive_extra_accepts) },
	{ "expensive_adaptive_demotes",
	  offsetof(struct stats_s, expensive_adaptive_demotes) },
	/* Object-size-relative ARG_LEN draw observability.  All zero while
	 * --arg-len-semantics is off (the default).  See the struct-field
	 * comment block in include/stats.h for per-counter semantics. */
	{ "arg_len_semantics_draws",
	  offsetof(struct stats_s, arg.len_semantics_draws) },
	{ "arg_len_objrelative_used",
	  offsetof(struct stats_s, arg.len_objrelative_used) },
	{ "arg_len_objrelative_nosize",
	  offsetof(struct stats_s, arg.len_objrelative_nosize) },
	{ "arg_len_objrel_blend_getlen",
	  offsetof(struct stats_s, arg.len_objrel_blend_getlen) },
	{ "arg_len_objrel_zero",
	  offsetof(struct stats_s, arg.len_objrel_zero) },
	{ "arg_len_objrel_one",
	  offsetof(struct stats_s, arg.len_objrel_one) },
	{ "arg_len_objrel_objsize",
	  offsetof(struct stats_s, arg.len_objrel_objsize) },
	{ "arg_len_objrel_objsize_minus_1",
	  offsetof(struct stats_s, arg.len_objrel_objsize_minus_1) },
	{ "arg_len_objrel_objsize_half",
	  offsetof(struct stats_s, arg.len_objrel_objsize_half) },
	{ "arg_len_objrel_pagesize",
	  offsetof(struct stats_s, arg.len_objrel_pagesize) },
	{ "arg_len_objrel_pagesize_plus_1",
	  offsetof(struct stats_s, arg.len_objrel_pagesize_plus_1) },
	{ "arg_len_objrel_pagesize_minus_1",
	  offsetof(struct stats_s, arg.len_objrel_pagesize_minus_1) },
	/* Adaptive remote-KCOV mode A/B disposition counters.  Bumped in
	 * lock-step from BOTH arms in remote_adaptive_decide(); the live
	 * remote_mode diverges only on Arm B.  See the struct-field
	 * comments in include/stats.h for per-counter semantics. */
	{ "remote_adaptive_samples",
	  offsetof(struct stats_s, remote_adaptive_samples) },
	{ "remote_adaptive_would_demote",
	  offsetof(struct stats_s, remote_adaptive_would_demote) },
	{ "remote_adaptive_would_promote",
	  offsetof(struct stats_s, remote_adaptive_would_promote) },
	{ "remote_adaptive_would_force",
	  offsetof(struct stats_s, remote_adaptive_would_force) },
	{ "remote_adaptive_would_gate_promote",
	  offsetof(struct stats_s, remote_adaptive_would_gate_promote) },
	{ "remote_adaptive_agree",
	  offsetof(struct stats_s, remote_adaptive_agree) },
	/* Picks the explorer pool forced to STRATEGY_RANDOM.  Rate-of-change
	 * over the run divided by explorer_children gives the per-explorer
	 * picker throughput; deviation from the bandit-pool throughput
	 * highlights either picker overhead or per-strategy work skew. */
	{ "strategy_explorer_picks",
	  offsetof(struct stats_s, strategy_explorer_picks) },
	/* Per-pool new-edge counters: ratio
	 *   explorer_pool_edges_discovered / bandit_pool_edges_discovered
	 * compared against
	 *   explorer_children / (max_children - explorer_children)
	 * tells the operator whether the explorer pool is finding edges
	 * disproportionately to its fleet share -- the trigger condition
	 * for considering per-child bandit (Option C). */
	{ "explorer_pool_edges_discovered",
	  offsetof(struct stats_s, explorer_pool_edges_discovered) },
	{ "bandit_pool_edges_discovered",
	  offsetof(struct stats_s, bandit_pool_edges_discovered) },
	/* Epoll lazy-arm wins: rate-of-change tracks fresh epfds reaching
	 * children after the deferred-arm refactor.  A flat counter while
	 * children are issuing epoll_wait suggests the consumer wireup
	 * regressed. */
	{ "epoll_lazy_armed",
	  offsetof(struct stats_s, epoll_lazy_armed) },
	/* Watch-set populations refused because the candidate fd belonged
	 * to a poll_can_block-tagged fd_provider (FUSE / userfaultfd / KVM
	 * vCPU / io_uring / pidfd).  Sustained growth confirms the filter
	 * is intercepting the fds that would otherwise wedge children in
	 * ep_item_poll → fops->poll on the per-fd waitqueue. */
	{ "epoll_blocking_poll_skipped",
	  offsetof(struct stats_s, epoll_blocking_poll_skipped) },
	/* Per-vCPU ioctl dispatches into kvm_vcpu_grp.  Rate-of-change at the
	 * 10-minute window granularity confirms the OBJ_FD_KVM_VCPU fd_test
	 * path is keeping up with vCPU pool churn -- a flat counter while the
	 * vcpu pool is non-empty would mean the new ioctl group isn't winning
	 * find_ioctl_group() arbitration, or the sanitiser is being bypassed
	 * by a fd that doesn't satisfy kvm_vcpu_fd_test. */
	{ "kvm_vcpu_ioctls_dispatched",
	  offsetof(struct stats_s, kvm_vcpu_ioctls_dispatched) },
	{ "kvm_vm_ioctls_dispatched",
	  offsetof(struct stats_s, kvm_vm_ioctls_dispatched) },
	/* nl80211_churn invocation rate.  Periodic visibility lets an operator
	 * confirm the cfg80211 state-machine fuzzer is making progress under the
	 * mac80211_hwsim radio without waiting for the end-of-run summary; a
	 * flat counter while other network childops advance is the signal that
	 * the hwsim probe latched ns_unsupported_nl80211 and the op went
	 * noop_forever for the rest of the run. */
	{ "nl80211_runs",
	  offsetof(struct stats_s, nl80211_runs) },
	/* SHADOW-ONLY cumulative count of "deep but warm" calls -- no PC-edge
	 * novelty and no CMP-bloom novelty, yet either a per-call PC walk
	 * meaningfully deeper than the syscall's lifetime mean or a trace
	 * that approached the KCOV_TRACE_SIZE buffer cap.  Periodic stats
	 * dump only; the per-syscall warm_reserve_candidates[] breakdown
	 * surfaces via top_syscalls_periodic_dump()'s warm-reserve row. */
	{ "warm_reserve_candidates_total",
	  offsetof(struct stats_s, warm_reserve_candidates_total) },
	/* SHADOW-ONLY intersection of the deep-but-warm predicate above
	 * with the CMP_RISING_PC_FLAT plateau hypothesis -- the would-
	 * replay-demand signal a STAGE B capped-reserve experiment would
	 * size its ring + dispatch path against.  Periodic stats dump
	 * only; the per-syscall warm_reserve_during_plateau[] breakdown
	 * surfaces via top_syscalls_periodic_dump()'s warm-reserve-plateau
	 * row. */
	{ "warm_reserve_during_plateau_total",
	  offsetof(struct stats_s, warm_reserve_during_plateau_total) },
};

static unsigned long defense_counter_load(unsigned int i)
{
	const char *base = defense_counters[i].from_aggregate
			   ? (const char *)&parent_stats
			   : (const char *)&shm->stats;
	unsigned long *p = (unsigned long *)(base + defense_counters[i].off);

	return __atomic_load_n(p, __ATOMIC_RELAXED);
}



/*
 * Childop vs random-syscall effort split.
 *
 * Three independent splits between CHILD_OP_SYSCALL (the random-syscall
 * fast path) and all other child_op_types (childop recipes):
 *
 *   walltime   -- cumulative ns spent inside op_fn for each side.
 *                 Source-of-truth for "where is the child loop
 *                 actually spending time".
 *   syscalls   -- random_syscall-mediated syscalls dispatched while
 *                 the per-child in_childop flag was set vs clear.
 *                 Childops that call libc/raw syscall() directly do
 *                 not flow through the call-complete enqueue and are
 *                 not counted here; the walltime metric covers them.
 *   iterations -- per-op_fn dispatch counts: childop_invocations[]
 *                 summed over op != CHILD_OP_SYSCALL vs the parallel
 *                 random_syscall_dispatches counter for the
 *                 CHILD_OP_SYSCALL path.
 *
 * Emitted as one human stat_row line and a single childop_split JSON
 * object so a grep-and-jq reader can audit raw numerators + denominators
 * alongside the rendered percentages.  Cumulative since the run started
 * -- the surrounding defense_counters_periodic_dump already supplies a
 * windowed view via per-dump deltas if the operator wants rate-of-rate
 * trends later.
 *
 * A pct_thousandths helper avoids dragging floating point into the parent
 * stats-dump path while preserving one decimal place of resolution; both
 * sides round to the same scale so the two percentages always sum to
 * 100.0% (within rounding) when the denominator is non-zero.
 */
static unsigned long pct_thousandths(unsigned long num, unsigned long denom)
{
	if (denom == 0)
		return 0;
	/* num * 100000 overflows unsigned long once num approaches ~1.8e14,
	 * which the cumulative childop_walltime_ns numerator reaches on a
	 * sustained run.  Shed low bits from both operands until the multiply
	 * (plus the denom/2 rounding term) can no longer overflow; the ratio
	 * is preserved and the helper only needs 0.1% resolution, so the
	 * dropped bits are immaterial.  num <= denom here, so gating on
	 * ULONG_MAX / 100001 leaves headroom for the rounding add. */
	while (denom > ULONG_MAX / 100001UL) {
		num >>= 1;
		denom >>= 1;
	}
	return (num * 100000UL + denom / 2) / denom;
}

void childop_split_dump(void)
{
	unsigned long wt_childop = __atomic_load_n(
		&shm->stats.childop_walltime_ns, __ATOMIC_RELAXED);
	unsigned long wt_syscall = __atomic_load_n(
		&shm->stats.syscall_walltime_ns, __ATOMIC_RELAXED);
	unsigned long sc_childop = __atomic_load_n(
		&shm->stats.syscalls_in_childops, __ATOMIC_RELAXED);
	unsigned long sc_random = __atomic_load_n(
		&shm->stats.syscalls_random, __ATOMIC_RELAXED);
	unsigned long it_random = __atomic_load_n(
		&shm->stats.random_syscall_dispatches, __ATOMIC_RELAXED);
	unsigned long it_childop = 0;
	unsigned long wt_total, sc_total, it_total;
	unsigned long wt_pct, sc_pct, it_pct;
	unsigned int op;

	/* Iteration denominator for the childop side: sum the existing
	 * childop_invocations[] over op != CHILD_OP_SYSCALL.  CHILD_OP_SYSCALL
	 * is gated out of that array by child_process()'s is_alt_op check,
	 * so the random_syscall_dispatches counter above is its separate
	 * parallel denominator. */
	for (op = 1; op < NR_CHILD_OP_TYPES; op++) {
		it_childop += __atomic_load_n(
			&shm->stats.childop_invocations[op],
			__ATOMIC_RELAXED);
	}

	wt_total = wt_childop + wt_syscall;
	sc_total = sc_childop + sc_random;
	it_total = it_childop + it_random;

	/* Silently skip the block if no dispatch has happened yet so a
	 * fresh-start dump doesn't print three "0/0 = 0.0%" rows. */
	if (wt_total == 0 && sc_total == 0 && it_total == 0)
		return;

	wt_pct = pct_thousandths(wt_childop, wt_total);
	sc_pct = pct_thousandths(sc_childop, sc_total);
	it_pct = pct_thousandths(it_childop, it_total);

	stats_log_write(
		"childop_split: walltime childop=%lu.%01lu%% (%lu/%lu ns)  "
		"syscalls childop=%lu.%01lu%% (%lu/%lu)  "
		"iterations childop=%lu.%01lu%% (%lu/%lu)\n",
		wt_pct / 1000, (wt_pct / 100) % 10, wt_childop, wt_total,
		sc_pct / 1000, (sc_pct / 100) % 10, sc_childop, sc_total,
		it_pct / 1000, (it_pct / 100) % 10, it_childop, it_total);

	stats_log_write(
		"childop_split_json: {"
		"\"walltime_ns\":{\"childop\":%lu,\"syscall\":%lu,\"pct_childop_x10\":%lu},"
		"\"syscalls\":{\"childop\":%lu,\"random\":%lu,\"pct_childop_x10\":%lu},"
		"\"iterations\":{\"childop\":%lu,\"random\":%lu,\"pct_childop_x10\":%lu}"
		"}\n",
		wt_childop, wt_syscall, wt_pct / 100,
		sc_childop, sc_random, sc_pct / 100,
		it_childop, it_random, it_pct / 100);
}

void __cold defense_counters_periodic_dump(void)
{
	static unsigned long prev[ARRAY_SIZE(defense_counters)];
	static struct timespec last_dump;
	struct timespec now;
	unsigned int i;
	long elapsed;
	int header_emitted = 0;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/* First call: arm the window so any pre-existing counts carried
	 * over from earlier in the run are not mis-attributed to the
	 * first window, mirroring corrupt_ptr_spike_check(). */
	if (last_dump.tv_sec == 0) {
		last_dump = now;
		for (i = 0; i < ARRAY_SIZE(defense_counters); i++)
			prev[i] = defense_counter_load(i);
		return;
	}

	elapsed = now.tv_sec - last_dump.tv_sec;
	if (elapsed < DEFENSE_DUMP_INTERVAL_SEC)
		return;

	for (i = 0; i < ARRAY_SIZE(defense_counters); i++) {
		unsigned long cur = defense_counter_load(i);
		unsigned long delta = sat_sub_ul(cur, prev[i]);
		unsigned long rate_milli;

		prev[i] = cur;
		if (delta == 0)
			continue;

		if (header_emitted == 0) {
			stats_log_write("Defense counter rates over last %lds:\n",
					elapsed);
			header_emitted = 1;
		}

		/* Per-second rate scaled by 1000 to keep three decimals
		 * without dragging in floating point on the parent path. */
		rate_milli = (delta * 1000UL) / (unsigned long)elapsed;
		stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu)\n",
				defense_counters[i].name, delta,
				rate_milli / 1000, rate_milli % 1000, cur);
	}

	corrupt_ptr_attr_dump();
	deferred_free_reject_pc_dump();

	/* Per-fire breadcrumbs printed below the attribution rollup so a
	 * triage scan sees the headline rates, then which handlers, then
	 * the individual scribbled values that drove them.  Self-rate-
	 * limited inside the helper to the same 600 s cadence as the
	 * surrounding dump. */
	corrupt_ptr_breadcrumb_dump(10);

	childop_split_dump();

	/* Advance the per-childop decaying recency ring on the same tick
	 * that drives the other operator-visibility dumps so the recent-
	 * edge / recent-wall view ages out over a wall-clock horizon of
	 * roughly CHILDOP_DECAY_WINDOWS * DEFENSE_DUMP_INTERVAL_SEC.
	 * SHADOW: no picker / canary code reads the ring; rotation cadence
	 * only affects what the shutdown dump labels "recent". */
	childop_window_advance();

	last_dump = now;
}

/*
 * Per-pool active-count snapshot for the cost-pool selector foundation.
 *
 * The picker still draws from the flat shm->active_syscalls*[] arrays;
 * the cheap / expensive pools maintained beside them by the activate /
 * deactivate paths are storage-only in this phase.  This dump surfaces
 * the pool populations so the operator can watch the partition stay
 * consistent with the flat count (invariant: cheap + exp == flat) and
 * see the cheap / expensive split of the active set at run-end and at
 * every periodic tick.  RELAXED atomic reads: pool counts only shift
 * on -x auto-disable / validation-failure deactivation, which is
 * infrequent, and any torn read biases the surface by at most one
 * activation between the flat and pool halves.
 *
 * Self-rate-limited on DEFENSE_DUMP_INTERVAL_SEC so the 10-minute cadence
 * matches the surrounding periodic surfaces and long-fuzz logs stay
 * legible; the caller in run_periodic_surfaces() fires it every tick
 * and this gate absorbs the frequency.
 */
void __cold cost_pool_periodic_dump(void)
{
	static struct timespec last_dump;
	struct timespec now;
	long elapsed;

	clock_gettime(CLOCK_MONOTONIC, &now);

	if (last_dump.tv_sec == 0) {
		last_dump = now;
		return;
	}

	elapsed = now.tv_sec - last_dump.tv_sec;
	if (elapsed < DEFENSE_DUMP_INTERVAL_SEC)
		return;

	last_dump = now;

	if (biarch == true) {
		unsigned int flat32 = __atomic_load_n(&shm->nr_active_32bit_syscalls,
						      __ATOMIC_RELAXED);
		unsigned int flat64 = __atomic_load_n(&shm->nr_active_64bit_syscalls,
						      __ATOMIC_RELAXED);
		unsigned int c32 = __atomic_load_n(&shm->nr_active_cheap_32bit,
						   __ATOMIC_RELAXED);
		unsigned int e32 = __atomic_load_n(&shm->nr_active_exp_32bit,
						   __ATOMIC_RELAXED);
		unsigned int c64 = __atomic_load_n(&shm->nr_active_cheap_64bit,
						   __ATOMIC_RELAXED);
		unsigned int e64 = __atomic_load_n(&shm->nr_active_exp_64bit,
						   __ATOMIC_RELAXED);

		stats_log_write("cost-pool active: 32bit flat=%u cheap=%u exp=%u  "
				"64bit flat=%u cheap=%u exp=%u\n",
				flat32, c32, e32, flat64, c64, e64);
	} else {
		unsigned int flat = __atomic_load_n(&shm->nr_active_syscalls,
						    __ATOMIC_RELAXED);
		unsigned int cheap = __atomic_load_n(&shm->nr_active_cheap,
						     __ATOMIC_RELAXED);
		unsigned int exp = __atomic_load_n(&shm->nr_active_exp,
						   __ATOMIC_RELAXED);

		stats_log_write("cost-pool active: flat=%u cheap=%u exp=%u\n",
				flat, cheap, exp);
	}

	/* Cost-pool selector shadow / live counters -- emitted alongside
	 * the pool-active snapshot above so an operator can watch the
	 * closed-form section 4.1 identity hold empirically as the run
	 * progresses.  RELAXED atomic reads: each counter is an
	 * independent aggregate so no cross-counter tearing invariant
	 * matters here; the analytical (ppm-scaled) fraction can be
	 * off by at most one pick-worth-of-ppm relative to shadow_picks
	 * across a torn snapshot, which is well below the noise floor
	 * of a real run.  Rendered only when the observer engaged
	 * (mode != OFF) OR the live-attribution pair accumulated (which
	 * happens on every run regardless of mode) so a fixed-seed
	 * --dry-run under OFF still emits the live-actual fraction as a
	 * baseline reference. */
	{
		unsigned long shadow_picks = __atomic_load_n(
			&shm->stats.cost_pool_selector_shadow_picks,
			__ATOMIC_RELAXED);
		unsigned long shadow_ppm_sum = __atomic_load_n(
			&shm->stats.cost_pool_selector_shadow_expensive_ppm_sum,
			__ATOMIC_RELAXED);
		unsigned long live_cheap = __atomic_load_n(
			&shm->stats.cost_pool_selector_live_cheap_picks,
			__ATOMIC_RELAXED);
		unsigned long live_exp = __atomic_load_n(
			&shm->stats.cost_pool_selector_live_expensive_picks,
			__ATOMIC_RELAXED);
		unsigned long predraw_cheap = __atomic_load_n(
			&shm->stats.cost_pool_selector_predraw_cheap_picks,
			__ATOMIC_RELAXED);
		unsigned long predraw_exp = __atomic_load_n(
			&shm->stats.cost_pool_selector_predraw_expensive_picks,
			__ATOMIC_RELAXED);
		unsigned long live_total = live_cheap + live_exp;
		unsigned long predraw_total = predraw_cheap + predraw_exp;
		unsigned long shadow_exp_ppm = 0;
		unsigned long live_exp_ppm = 0;
		unsigned long predraw_exp_ppm = 0;
		const char *mode_name;

		if (shadow_picks > 0)
			shadow_exp_ppm = shadow_ppm_sum / shadow_picks;
		if (live_total > 0)
			live_exp_ppm = (1000000UL * live_exp) / live_total;
		if (predraw_total > 0)
			predraw_exp_ppm = (1000000UL * predraw_exp) / predraw_total;

		switch (cost_pool_selector_mode) {
		case COST_POOL_SELECTOR_MODE_OFF:
			mode_name = "off"; break;
		case COST_POOL_SELECTOR_MODE_SHADOW_ONLY:
			mode_name = "shadow-only"; break;
		case COST_POOL_SELECTOR_MODE_COMBINED:
			mode_name = "combined"; break;
		default:
			mode_name = "?"; break;
		}

		stats_log_write("cost-pool selector: mode=%s "
				"shadow picks=%lu exp_ppm=%lu  "
				"predraw cheap=%lu exp=%lu exp_ppm=%lu  "
				"live cheap=%lu exp=%lu exp_ppm=%lu\n",
				mode_name,
				shadow_picks, shadow_exp_ppm,
				predraw_cheap, predraw_exp, predraw_exp_ppm,
				live_cheap, live_exp, live_exp_ppm);
	}
}

/* Per-pool top-N entry for top_syscalls_periodic_dump's stack-resident
 * insertion sort.  Holds the syscall's table index and the per-window
 * delta of its strategy-attributed new-edge counter. */
struct top_syscall_entry {
	unsigned int nr;
	unsigned long delta;
};


static void top_syscalls_emit_pool(const char *pool_name,
				   const unsigned long *cur,
				   const unsigned long *prev,
				   unsigned int nr_to_scan,
				   const struct syscalltable *table,
				   bool is32bit)
{
	struct top_syscall_entry top[TOP_SYSCALLS_DUMP_TOPN];
	unsigned int top_count = 0;
	unsigned long total = 0, top_sum = 0, share_pct;
	unsigned int i;
	int j;

	for (i = 0; i < nr_to_scan; i++) {
		unsigned long delta = sat_sub_ul(cur[i], prev[i]);

		if (delta == 0)
			continue;

		total += delta;

		/* Insertion sort, descending by delta, capped at TOP_N. */
		for (j = (int)top_count;
		     j > 0 && delta > top[j - 1].delta;
		     j--) {
			if (j < TOP_SYSCALLS_DUMP_TOPN)
				top[j] = top[j - 1];
		}
		if (j < TOP_SYSCALLS_DUMP_TOPN) {
			top[j].nr = i;
			top[j].delta = delta;
			if (top_count < TOP_SYSCALLS_DUMP_TOPN)
				top_count++;
		}
	}

	/* Skip the strategy block entirely when the pool contributed no
	 * new edges this window -- a "(0 total, top 5 = 0%)" line is
	 * noise, not signal. */
	if (total == 0)
		return;

	for (j = 0; j < (int)top_count; j++)
		top_sum += top[j].delta;
	share_pct = (top_sum * 100UL) / total;

	stats_log_write("  %s (%lu total, top %u = %lu%%):\n",
			pool_name, total, top_count, share_pct);

	for (j = 0; j < (int)top_count; j++) {
		const char *name = table ? print_syscall_name(top[j].nr, is32bit)
					 : "???";
		stats_log_write("    %-24s +%lu\n", name, top[j].delta);
	}
}

/* Per-syscall frontier-yield kill-list row.  Carries the four delta-tracked
 * F1 counters plus the two absolute snapshots (recent_weight and the
 * last-productive-window stamp) so the emitter can render one combined
 * table row per top entry without re-reading shm. */
struct frontier_yield_entry {
	unsigned int nr;
	unsigned long live_picks_delta;
	unsigned long silent_picks_delta;
	unsigned long wins_delta;
	unsigned long misses_delta;
	uint32_t recent_weight;
	unsigned long last_productive_window;
};

/* Companion to top_syscalls_emit_pool() for the F1 per-syscall frontier-
 * yield arrays.  Sorts the top-N by live_misses delta -- the headline kill-
 * list signal -- and emits one row per entry with the live/silent pick split,
 * the productive-wins delta, the live_misses delta, the current recent-ring
 * weight, and the age (in bandit windows) since the last productive win.
 * Zero-total-misses windows skip the row, mirroring the sibling emitter. */
static void top_syscalls_emit_frontier_yield(
		const unsigned long *cur_live_picks,
		const unsigned long *prev_live_picks,
		const unsigned long *cur_silent_picks,
		const unsigned long *prev_silent_picks,
		const unsigned long *cur_wins,
		const unsigned long *prev_wins,
		const unsigned long *cur_misses,
		const unsigned long *prev_misses,
		const uint32_t *recent_weight,
		const unsigned long *last_productive_window,
		unsigned long bandit_window_now,
		unsigned int nr_to_scan,
		const struct syscalltable *table,
		bool is32bit)
{
	struct frontier_yield_entry top[TOP_SYSCALLS_DUMP_TOPN];
	unsigned int top_count = 0;
	unsigned long total_misses = 0;
	unsigned int i;
	int j;

	for (i = 0; i < nr_to_scan; i++) {
		unsigned long live_d = sat_sub_ul(cur_live_picks[i], prev_live_picks[i]);
		unsigned long silent_d = sat_sub_ul(cur_silent_picks[i], prev_silent_picks[i]);
		unsigned long wins_d = sat_sub_ul(cur_wins[i], prev_wins[i]);
		unsigned long misses_d = sat_sub_ul(cur_misses[i], prev_misses[i]);

		if (misses_d == 0)
			continue;

		total_misses += misses_d;

		for (j = (int)top_count;
		     j > 0 && misses_d > top[j - 1].misses_delta;
		     j--) {
			if (j < TOP_SYSCALLS_DUMP_TOPN)
				top[j] = top[j - 1];
		}
		if (j < TOP_SYSCALLS_DUMP_TOPN) {
			top[j].nr = i;
			top[j].live_picks_delta = live_d;
			top[j].silent_picks_delta = silent_d;
			top[j].wins_delta = wins_d;
			top[j].misses_delta = misses_d;
			top[j].recent_weight = recent_weight[i];
			top[j].last_productive_window =
				last_productive_window[i];
			if (top_count < TOP_SYSCALLS_DUMP_TOPN)
				top_count++;
		}
	}

	if (total_misses == 0)
		return;

	stats_log_write("  frontier-yield kill-list (top %u by live_misses, "
			"%lu total live_misses):\n",
			top_count, total_misses);
	stats_log_write("    %-24s %8s %8s %8s %8s %8s %10s\n",
			"syscall", "live", "silent", "wins", "misses",
			"recent", "last_age");
	for (j = 0; j < (int)top_count; j++) {
		const char *name = table ? print_syscall_name(top[j].nr, is32bit)
					 : "???";

		/* last_productive_window == 0 means no productive win has ever
		 * been attributed to this slot (F1 zero-inits the array via
		 * shm); rendering "bandit_window_now - 0" as a giant age would
		 * mis-read as a stale-but-once-productive entry.  "never" is
		 * the actionable signal: entry has eaten frontier picks under
		 * the live regime and converted zero of them since boot. */
		if (top[j].last_productive_window == 0) {
			stats_log_write("    %-24s %8lu %8lu %8lu %8lu %8u %10s\n",
					name,
					top[j].live_picks_delta,
					top[j].silent_picks_delta,
					top[j].wins_delta,
					top[j].misses_delta,
					top[j].recent_weight,
					"never");
		} else {
			/* Saturating subtract: the F1 stamp is RELAXED and the
			 * window counter we read here is a separate RELAXED
			 * load, so an interleaving where the stamp lands from
			 * a later window than the bandit_window_now snapshot
			 * is observable; clamp at 0 rather than wrap to
			 * ULONG_MAX (mirrors the delta clamps above). */
			unsigned long age = (bandit_window_now >
					     top[j].last_productive_window)
				? bandit_window_now -
					top[j].last_productive_window
				: 0;
			stats_log_write("    %-24s %8lu %8lu %8lu %8lu %8u %10lu\n",
					name,
					top[j].live_picks_delta,
					top[j].silent_picks_delta,
					top[j].wins_delta,
					top[j].misses_delta,
					top[j].recent_weight,
					age);
		}
	}
}

static void top_syscalls_render_frontier_picks(
		const unsigned long *cur, const unsigned long *prev,
		long elapsed, unsigned int nr_to_scan,
		const struct syscalltable *table)
{
	/* Frontier-picker accept distribution: which syscalls ate the
	 * coverage-frontier picks this window.  Same top-N emitter as the
	 * edge pools above; an empty distribution (frontier arm never
	 * selected, or selected but accepted nothing) skips the row via the
	 * helper's zero-total gate. */
	stats_log_write("Top %u syscalls by frontier picks in last %lds:\n",
			TOP_SYSCALLS_DUMP_TOPN, elapsed);
	top_syscalls_emit_pool("frontier", cur, prev, nr_to_scan, table, false);
}

static void top_syscalls_render_frontier_yield(
		const unsigned long *cur_live_picks,
		const unsigned long *prev_live_picks,
		const unsigned long *cur_silent_picks,
		const unsigned long *prev_silent_picks,
		const unsigned long *cur_wins,
		const unsigned long *prev_wins,
		const unsigned long *cur_live_misses,
		const unsigned long *prev_live_misses,
		const uint32_t *cur_recent_weight,
		const unsigned long *cur_last_productive,
		long elapsed, unsigned int nr_to_scan,
		const struct syscalltable *table)
{
	unsigned long bandit_window_now;

	/* Per-syscall frontier yield (kill-list feedstock).  Surfaces the
	 * regime split (live vs silent pick deltas), productive wins and
	 * live_misses deltas, the current recent-ring weight, and the age
	 * since the last productive win for the top-N syscalls by live_miss
	 * delta.  Render-only over F1's per-syscall counters; the helper
	 * gates on total_misses == 0 so a window where the live regime never
	 * wasted a pick collapses to no row. */
	bandit_window_now = __atomic_load_n(&shm->bandit_window_count,
					    __ATOMIC_RELAXED);
	stats_log_write("Per-syscall frontier yield in last %lds:\n", elapsed);
	top_syscalls_emit_frontier_yield(
			cur_live_picks, prev_live_picks,
			cur_silent_picks, prev_silent_picks,
			cur_wins, prev_wins,
			cur_live_misses, prev_live_misses,
			cur_recent_weight,
			cur_last_productive,
			bandit_window_now,
			nr_to_scan, table, false);
}

static void top_syscalls_render_rq(
		const unsigned long *cur_saves,
		const unsigned long *prev_saves,
		const unsigned long *cur_wins,
		const unsigned long *prev_wins,
		long elapsed, unsigned int nr_to_scan,
		const struct syscalltable *table)
{
	/* RedQueen-source corpus saves vs the PC-edge wins those saves
	 * later produce, per-syscall.  The two top-Ns answer the
	 * harvest->edge bottleneck question: which syscalls are RedQueen
	 * harvesting args for, and which of those convert downstream to
	 * new PC-bucket edges once a corpus replay picks them up.  The
	 * helper's zero-total gate skips each row when its pool is empty
	 * (re-exec disabled, or enabled but no corpus replay landed on an
	 * rq-sourced entry that flipped a new edge this window). */
	stats_log_write("Top %u syscalls by RedQueen-sourced saves "
			"in last %lds:\n",
			TOP_SYSCALLS_DUMP_TOPN, elapsed);
	top_syscalls_emit_pool("rq-saves", cur_saves, prev_saves,
			       nr_to_scan, table, false);
	stats_log_write("Top %u syscalls by PC-edge wins from "
			"RedQueen-sourced saves in last %lds:\n",
			TOP_SYSCALLS_DUMP_TOPN, elapsed);
	top_syscalls_emit_pool("rq-pcedge-wins", cur_wins, prev_wins,
			       nr_to_scan, table, false);
}

static void top_syscalls_render_warm_reserve(
		const unsigned long *cur, const unsigned long *prev,
		long elapsed, unsigned int nr_to_scan,
		const struct syscalltable *table)
{
	/* SHADOW deep-but-warm candidate accounting (see the warm_reserve_
	 * candidates* comment in include/stats.h for the predicate).  Same
	 * top-N shape and zero-total skip as the pools above; an empty
	 * distribution (no syscall fired the deep-but-warm predicate this
	 * window) collapses to no row via the emitter's gate. */
	stats_log_write("Top %u syscalls by deep-but-warm candidates "
			"in last %lds:\n",
			TOP_SYSCALLS_DUMP_TOPN, elapsed);
	top_syscalls_emit_pool("warm-reserve", cur, prev,
			       nr_to_scan, table, false);
}

static void top_syscalls_render_warm_reserve_plateau(
		const unsigned long *cur, const unsigned long *prev,
		long elapsed, unsigned int nr_to_scan,
		const struct syscalltable *table)
{
	/* SHADOW would-replay-demand accounting -- intersection of the
	 * deep-but-warm predicate with the CMP_RISING_PC_FLAT plateau
	 * window (see warm_reserve_during_plateau* in include/stats.h).
	 * Same top-N shape and zero-total skip as the warm-reserve row
	 * above; a window without a plateau, or a plateau window without
	 * any deep-but-warm fires, collapses to no row. */
	stats_log_write("Top %u syscalls by deep-but-warm candidates "
			"during plateau in last %lds:\n",
			TOP_SYSCALLS_DUMP_TOPN, elapsed);
	top_syscalls_emit_pool("warm-reserve-plateau", cur, prev,
			       nr_to_scan, table, false);
}

void __cold top_syscalls_periodic_dump(void)
{
	static unsigned long prev_bandit[MAX_NR_SYSCALL];
	static unsigned long prev_explorer[MAX_NR_SYSCALL];
	static unsigned long prev_frontier_picks[MAX_NR_SYSCALL];
	static unsigned long prev_frontier_live_picks[MAX_NR_SYSCALL];
	static unsigned long prev_frontier_silent_picks[MAX_NR_SYSCALL];
	static unsigned long prev_frontier_wins[MAX_NR_SYSCALL];
	static unsigned long prev_frontier_live_misses[MAX_NR_SYSCALL];
	static unsigned long prev_rq_saves[MAX_NR_SYSCALL];
	static unsigned long prev_rq_wins[MAX_NR_SYSCALL];
	static unsigned long prev_warm_reserve[MAX_NR_SYSCALL];
	static unsigned long prev_warm_reserve_plateau[MAX_NR_SYSCALL];
	static struct timespec last_dump;
	unsigned long cur_bandit[MAX_NR_SYSCALL];
	unsigned long cur_explorer[MAX_NR_SYSCALL];
	unsigned long cur_frontier_picks[MAX_NR_SYSCALL];
	unsigned long cur_frontier_live_picks[MAX_NR_SYSCALL];
	unsigned long cur_frontier_silent_picks[MAX_NR_SYSCALL];
	unsigned long cur_frontier_wins[MAX_NR_SYSCALL];
	unsigned long cur_frontier_live_misses[MAX_NR_SYSCALL];
	unsigned long cur_frontier_last_productive[MAX_NR_SYSCALL];
	uint32_t cur_frontier_recent_weight[MAX_NR_SYSCALL];
	unsigned long cur_rq_saves[MAX_NR_SYSCALL];
	unsigned long cur_rq_wins[MAX_NR_SYSCALL];
	unsigned long cur_warm_reserve[MAX_NR_SYSCALL];
	unsigned long cur_warm_reserve_plateau[MAX_NR_SYSCALL];
	struct timespec now;
	long elapsed;
	unsigned int nr_to_scan;
	const struct syscalltable *table;
	unsigned int i;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/* First call: arm the window so any pre-existing counts carried
	 * over from earlier in the run are not mis-attributed to the
	 * first window, mirroring defense_counters_periodic_dump. */
	if (last_dump.tv_sec == 0) {
		last_dump = now;
		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			prev_bandit[i]   = __atomic_load_n(
				&shm->stats.edges_per_syscall_bandit[i],
				__ATOMIC_RELAXED);
			prev_explorer[i] = __atomic_load_n(
				&shm->stats.edges_per_syscall_explorer[i],
				__ATOMIC_RELAXED);
			prev_frontier_picks[i] = __atomic_load_n(
				&shm->stats.frontier.picks_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_frontier_live_picks[i] = __atomic_load_n(
				&shm->stats.frontier.live_picks_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_frontier_silent_picks[i] = __atomic_load_n(
				&shm->stats.frontier.silent_picks_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_frontier_wins[i] = __atomic_load_n(
				&shm->stats.frontier.productive_wins_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_frontier_live_misses[i] = __atomic_load_n(
				&shm->stats.frontier.live_misses_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_rq_saves[i] = __atomic_load_n(
				&shm->stats.rq_sourced_saves_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_rq_wins[i] = __atomic_load_n(
				&shm->stats.rq_sourced_pcedge_wins_per_syscall[i],
				__ATOMIC_RELAXED);
			prev_warm_reserve[i] = __atomic_load_n(
				&shm->stats.warm_reserve_candidates[i],
				__ATOMIC_RELAXED);
			prev_warm_reserve_plateau[i] = __atomic_load_n(
				&shm->stats.warm_reserve_during_plateau[i],
				__ATOMIC_RELAXED);
		}
		return;
	}

	elapsed = now.tv_sec - last_dump.tv_sec;
	if (elapsed < DEFENSE_DUMP_INTERVAL_SEC)
		return;

	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		cur_bandit[i]   = __atomic_load_n(
			&shm->stats.edges_per_syscall_bandit[i],
			__ATOMIC_RELAXED);
		cur_explorer[i] = __atomic_load_n(
			&shm->stats.edges_per_syscall_explorer[i],
			__ATOMIC_RELAXED);
		cur_frontier_picks[i] = __atomic_load_n(
			&shm->stats.frontier.picks_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_live_picks[i] = __atomic_load_n(
			&shm->stats.frontier.live_picks_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_silent_picks[i] = __atomic_load_n(
			&shm->stats.frontier.silent_picks_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_wins[i] = __atomic_load_n(
			&shm->stats.frontier.productive_wins_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_live_misses[i] = __atomic_load_n(
			&shm->stats.frontier.live_misses_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_last_productive[i] = __atomic_load_n(
			&shm->stats.frontier.last_productive_window_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_frontier_recent_weight[i] = __atomic_load_n(
			&shm->frontier_recent_count_cached[i],
			__ATOMIC_RELAXED);
		cur_rq_saves[i] = __atomic_load_n(
			&shm->stats.rq_sourced_saves_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_rq_wins[i] = __atomic_load_n(
			&shm->stats.rq_sourced_pcedge_wins_per_syscall[i],
			__ATOMIC_RELAXED);
		cur_warm_reserve[i] = __atomic_load_n(
			&shm->stats.warm_reserve_candidates[i],
			__ATOMIC_RELAXED);
		cur_warm_reserve_plateau[i] = __atomic_load_n(
			&shm->stats.warm_reserve_during_plateau[i],
			__ATOMIC_RELAXED);
	}

	/* Match the same biarch table-scan choice the existing per-syscall
	 * top-N path in dump_stats uses: under biarch only the 64-bit table
	 * is iterated (32-bit nrs collide with 64-bit ones in the same
	 * index space and would shadow them in the display). */
	if (biarch) {
		nr_to_scan = max_nr_64bit_syscalls;
		table = syscalls_64bit;
	} else {
		nr_to_scan = max_nr_syscalls;
		table = syscalls;
	}
	if (nr_to_scan > MAX_NR_SYSCALL)
		nr_to_scan = MAX_NR_SYSCALL;

	stats_log_write("Top %u syscalls by new edges in last %lds:\n",
			TOP_SYSCALLS_DUMP_TOPN, elapsed);
	top_syscalls_emit_pool("bandit", cur_bandit, prev_bandit,
			       nr_to_scan, table, false);
	top_syscalls_emit_pool("explorer", cur_explorer, prev_explorer,
			       nr_to_scan, table, false);

	top_syscalls_render_frontier_picks(cur_frontier_picks,
					   prev_frontier_picks,
					   elapsed, nr_to_scan, table);

	top_syscalls_render_frontier_yield(
			cur_frontier_live_picks, prev_frontier_live_picks,
			cur_frontier_silent_picks, prev_frontier_silent_picks,
			cur_frontier_wins, prev_frontier_wins,
			cur_frontier_live_misses, prev_frontier_live_misses,
			cur_frontier_recent_weight,
			cur_frontier_last_productive,
			elapsed, nr_to_scan, table);

	top_syscalls_render_rq(cur_rq_saves, prev_rq_saves,
			       cur_rq_wins, prev_rq_wins,
			       elapsed, nr_to_scan, table);

	top_syscalls_render_warm_reserve(cur_warm_reserve, prev_warm_reserve,
					 elapsed, nr_to_scan, table);

	top_syscalls_render_warm_reserve_plateau(cur_warm_reserve_plateau,
						 prev_warm_reserve_plateau,
						 elapsed, nr_to_scan, table);

	memcpy(prev_bandit,   cur_bandit,   sizeof(prev_bandit));
	memcpy(prev_explorer, cur_explorer, sizeof(prev_explorer));
	memcpy(prev_frontier_picks, cur_frontier_picks,
	       sizeof(prev_frontier_picks));
	memcpy(prev_frontier_live_picks, cur_frontier_live_picks,
	       sizeof(prev_frontier_live_picks));
	memcpy(prev_frontier_silent_picks, cur_frontier_silent_picks,
	       sizeof(prev_frontier_silent_picks));
	memcpy(prev_frontier_wins, cur_frontier_wins,
	       sizeof(prev_frontier_wins));
	memcpy(prev_frontier_live_misses, cur_frontier_live_misses,
	       sizeof(prev_frontier_live_misses));
	memcpy(prev_rq_saves, cur_rq_saves, sizeof(prev_rq_saves));
	memcpy(prev_rq_wins,  cur_rq_wins,  sizeof(prev_rq_wins));
	memcpy(prev_warm_reserve, cur_warm_reserve,
	       sizeof(prev_warm_reserve));
	memcpy(prev_warm_reserve_plateau, cur_warm_reserve_plateau,
	       sizeof(prev_warm_reserve_plateau));

	last_dump = now;
}

/*
 * Count newline-terminated lines in @path.  Returns -1 on open failure
 * (caller skips the slot) and the line count otherwise.  Each completed
 * /proc/<pid>/maps line is one VMA in the target's address space, so the
 * line count is the VMA count without the cost of parsing the address /
 * permission / pathname columns we don't care about here.  Anchoring on
 * '\n' avoids over-counting when a single maps line exceeds the read
 * buffer (rare but possible -- there's no kernel-side cap on the trailing
 * pathname column) and fgets returns the tail in a follow-up call.
 */
static long count_proc_maps_lines(const char *path)
{
	FILE *f;
	char buf[1024];
	long lines = 0;

	f = fopen(path, "r");
	if (f == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), f) != NULL) {
		if (strchr(buf, '\n') != NULL)
			lines++;
	}

	fclose(f);
	return lines;
}

/*
 * Per-tick scan paired with defense_counters_periodic_dump: every dump
 * window, snapshot the parent's VMA count and walk the live child pid
 * slots to sum, max, and min the children's VMA counts.  The point is
 * post-mortem visibility for the cgroup-OOM class where one of trinity's
 * thaw/freeze paths leaks a VMA per cycle (a failed mprotect that gets
 * retried can split a VMA without merging back, and the leak only
 * manifests when the host kills the parent for memory exhaustion).
 * children_max is the diagnostic of interest: if a single slot grows
 * its VMA count an order of magnitude faster than the others, that's
 * the leak signature.  /proc reads that fail (process died between the
 * pid snapshot and the open) are silently skipped rather than panicked.
 */
void __cold vma_count_periodic_dump(void)
{
	static struct timespec last_dump;
	struct timespec now;
	long elapsed;
	long parent_vmas;
	unsigned long total = 0;
	unsigned long max_vmas = 0;
	unsigned long min_vmas = 0;
	bool min_set = false;
	unsigned int i;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/* First call: arm the window so the first emission lands at the
	 * same cadence as the rest of the periodic dumps. */
	if (last_dump.tv_sec == 0) {
		last_dump = now;
		return;
	}

	elapsed = now.tv_sec - last_dump.tv_sec;
	if (elapsed < DEFENSE_DUMP_INTERVAL_SEC)
		return;

	parent_vmas = count_proc_maps_lines("/proc/self/maps");

	for_each_child(i) {
		char path[32];
		pid_t pid;
		long n;

		pid = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);
		if (pid == EMPTY_PIDSLOT)
			continue;

		snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
		n = count_proc_maps_lines(path);
		if (n < 0)
			continue;

		total += (unsigned long)n;
		if ((unsigned long)n > max_vmas)
			max_vmas = (unsigned long)n;
		if (!min_set || (unsigned long)n < min_vmas) {
			min_vmas = (unsigned long)n;
			min_set = true;
		}
	}

	/*
	 * Coalesce identical VMAs lines.  In steady-state runs all four
	 * counts (parent, total, max, min) are unchanged window after
	 * window.  Suppress repeats but force a print every 30 windows so
	 * the stats log still carries a periodic state anchor.
	 */
	unsigned long parent = (parent_vmas < 0) ? 0UL : (unsigned long)parent_vmas;
	static unsigned long last_vma_parent;
	static unsigned long last_vma_total;
	static unsigned long last_vma_max;
	static unsigned long last_vma_min;
	static unsigned int vma_suppress = 30; /* force first print */
	if (vma_suppress >= 30 ||
	    parent != last_vma_parent ||
	    total != last_vma_total ||
	    max_vmas != last_vma_max ||
	    min_vmas != last_vma_min) {
		stats_log_write("[main] VMAs: parent=%lu children_total=%lu children_max=%lu children_min=%lu\n",
				parent, total, max_vmas, min_vmas);
		last_vma_parent = parent;
		last_vma_total = total;
		last_vma_max = max_vmas;
		last_vma_min = min_vmas;
		vma_suppress = 0;
	} else {
		vma_suppress++;
	}

	last_dump = now;
}
