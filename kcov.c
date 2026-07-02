/*
 * KCOV coverage collection for coverage-guided fuzzing.
 *
 * Each child tries to open /sys/kernel/debug/kcov at startup. If the
 * kernel supports KCOV, per-thread trace buffers are mmapped and PC
 * tracing is enabled around each syscall. Collected PCs are hashed
 * into a global shared bucket-seen table to track edge coverage with
 * AFL-style hit-count bucketing: a syscall that hits the same edge five
 * times is distinguishable from one that hits it two hundred times, so
 * mutations that nudge loop-trip counts past bucket boundaries register
 * as new coverage.
 *
 * When KCOV_REMOTE_ENABLE is available, a fraction of syscalls use
 * remote mode to also collect coverage from softirqs, threaded IRQ
 * handlers, and kthreads triggered by the syscall — deferred work
 * that per-thread KCOV_ENABLE would miss.
 *
 * If KCOV is not available, everything is silently skipped with no
 * runtime overhead beyond the initial open() attempt per child.
 */

#include <errno.h>
#include <limits.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef CONFIG_GUARD_SHARED
#include "signals.h"	/* kcov_protect_recover / kcov_protect_active */
#endif

#include "arch.h"
#include "child.h"
#include "cmp_hints.h"
#include "fd.h"
#include "kcov.h"
#include "kcov-internal.h"
#include "minicorpus.h"
#include "params.h"
#include "persist-util.h"
#include "pids.h"
#include "rnd.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "strategy.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

struct kcov_shared *kcov_shm = NULL;

/* The per-childop arrays in struct kcov_shared are sized off
 * KCOV_CHILDOP_NR_MAX because include/kcov.h cannot pull in child.h
 * for the real NR_CHILD_OP_TYPES (child.h includes kcov.h for struct
 * kcov_child).  Bump KCOV_CHILDOP_NR_MAX in include/kcov.h if a
 * childop slot beyond the bound is ever added. */
_Static_assert(NR_CHILD_OP_TYPES <= KCOV_CHILDOP_NR_MAX,
	"NR_CHILD_OP_TYPES exceeds KCOV_CHILDOP_NR_MAX; "
	"bump KCOV_CHILDOP_NR_MAX in include/kcov.h");

enum childop_kcov_attribution_mode childop_kcov_attr_mode =
	CHILDOP_KCOV_ATTR_DUAL;

/* Default is OFF: the childop CMP harvest path is dormant and the
 * childop dispatch surface is byte-identical to a build without the
 * --childop-cmp-harvest knob.  Flipping to ON opens the §3.2 bracket
 * on every CMP-mode child whose dispatch reaches the existing
 * op_uses_outer_bracket gate (see child.c) so childop syscalls routed
 * through trinity_cmp_syscall harvest their CMP operands into the
 * quarantined childop_recent_pools[nr][do32] lane.  See the
 * childop_cmp_harvest_mode enum in include/kcov.h for the per-mode
 * contract. */
enum childop_cmp_harvest_mode childop_cmp_harvest_mode =
	CHILDOP_CMP_HARVEST_OFF;

/* Default is SHADOW: collect into the transition map and surface it
 * through the stats dump, but do not feed deltas into any steering
 * consumer.  See the kcov_transition_coverage_mode enum in include/
 * kcov.h for the contract. */
enum kcov_transition_coverage_mode kcov_transition_coverage_mode =
	KCOV_TRANSITION_COVERAGE_SHADOW;

/* Default is COMBINED: feed the capped transition delta into
 * frontier_cold_weight()'s blend, bandit_record_pull()'s per-arm
 * reward total, and the frontier-edge ring via frontier_record_
 * transition_edge() so syscalls that produce only transitions (a new
 * ordering through warm-known code, no fresh PC bits) still earn live
 * frontier credit.  The shadow-mode A/B prior to this default flip
 * showed the blend weighting frontier-transition syscalls upward an
 * order of magnitude more often than downward (frontier_blend_new_
 * higher vs frontier_blend_new_lower in shm->stats), which is the
 * divergence gate justifying the live promotion.  --kcov-transition-
 * reward=shadow-only and =off remain as rollback paths.  See the
 * kcov_transition_reward_mode enum in include/kcov.h for the full
 * contract. */
enum kcov_transition_reward_mode kcov_transition_reward_mode =
	KCOV_TRANSITION_REWARD_COMBINED;

/*
 * Coverage-jump breadcrumb -- diagnostic only.
 *
 * Sampled at the tail of kcov_collect() so call_nr (the kcov_shm->
 * total_calls fetch_add return from earlier in this call) is in hand
 * without a second atomic read.  See the KCOV_COVJUMP_* block in
 * include/kcov.h for the detector contract.
 *
 * No runtime behaviour reads any output of this path: it writes one
 * stats.log line when the (distinct_edges) coverage delta over a
 * KCOV_COVJUMP_WINDOW_CALLS-sized window crosses KCOV_COVJUMP_DELTA_
 * THRESHOLD, rate-capped to one line per KCOV_COVJUMP_RATE_CAP_CALLS
 * total_calls.  All emitted facts (recent syscalls, top childop
 * deltas, plateau hypothesis + bandit arm name, corpus save/replay
 * deltas) are observability snapshots taken by the CAS winner -- no
 * fleet counter is written, no policy is consulted.
 *
 * The CAS on covjump_window_start_call_nr serialises window advances
 * across racing children so only one breadcrumb fires per window even
 * when many children cross the boundary in the same instant.
 */
static const enum child_op_type covjump_bridge_ops[] = {
	CHILD_OP_BRIDGE_FDB_STP,
	CHILD_OP_BRIDGE_VLAN_CHURN,
	CHILD_OP_BRIDGE_CT_CHURN,
};
static const enum child_op_type covjump_conntrack_ops[] = {
	CHILD_OP_NF_CONNTRACK_HELPER,
};
static const enum child_op_type covjump_mld_ops[] = {
	CHILD_OP_IGMP_MLD_SOURCE_CHURN,
};
static const enum child_op_type covjump_mempress_ops[] = {
	CHILD_OP_MEMORY_PRESSURE,
	CHILD_OP_MLOCK_PRESSURE,
};

static bool covjump_any_delta(const enum child_op_type *ops, unsigned int n,
			      const unsigned long *now,
			      const unsigned long *snap)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		unsigned int op = (unsigned int)ops[i];

		if (op >= KCOV_CHILDOP_NR_MAX)
			continue;
		if (now[op] > snap[op])
			return true;
	}
	return false;
}

static void covjump_seed_snapshot(unsigned long call_nr, unsigned long edges_now)
{
	unsigned int op;

	__atomic_store_n(&kcov_shm->covjump_window_start_call_nr, call_nr,
			 __ATOMIC_RELAXED);
	__atomic_store_n(&kcov_shm->covjump_window_start_distinct_edges,
			 edges_now, __ATOMIC_RELAXED);
	if (minicorpus_shm != NULL) {
		__atomic_store_n(&kcov_shm->covjump_snap_saves_pc,
			__atomic_load_n(&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_PC],
					__ATOMIC_RELAXED),
			__ATOMIC_RELAXED);
		__atomic_store_n(&kcov_shm->covjump_snap_saves_cmp,
			__atomic_load_n(&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_CMP],
					__ATOMIC_RELAXED),
			__ATOMIC_RELAXED);
	}
	if (chain_corpus_shm != NULL) {
		__atomic_store_n(&kcov_shm->covjump_snap_chain_saves,
			__atomic_load_n(&chain_corpus_shm->save_count,
					__ATOMIC_RELAXED),
			__ATOMIC_RELAXED);
		__atomic_store_n(&kcov_shm->covjump_snap_chain_replays,
			__atomic_load_n(&chain_corpus_shm->replay_count,
					__ATOMIC_RELAXED),
			__ATOMIC_RELAXED);
	}
	for (op = 0; op < KCOV_CHILDOP_NR_MAX; op++) {
		unsigned long v = 0;

		if (op < (unsigned int)NR_CHILD_OP_TYPES)
			v = __atomic_load_n(&shm->stats.childop_invocations[op],
					    __ATOMIC_RELAXED);
		__atomic_store_n(&kcov_shm->covjump_snap_childop_invocations[op],
				 v, __ATOMIC_RELAXED);
	}
}

void kcov_covjump_breadcrumb_maybe(unsigned long call_nr)
{
	unsigned long expected_start, edges_now, edges_prev, delta;
	unsigned long elapsed, last_emit, sample_calls;
	unsigned long now_childop[KCOV_CHILDOP_NR_MAX];
	unsigned long snap_childop[KCOV_CHILDOP_NR_MAX];
	unsigned long saves_pc_now = 0, saves_cmp_now = 0;
	unsigned long chain_saves_now = 0, chain_replays_now = 0;
	unsigned long saves_pc_snap, saves_cmp_snap;
	unsigned long chain_saves_snap, chain_replays_snap;
	unsigned int top_idx[KCOV_COVJUMP_RECENT_N];
	unsigned long top_delta[KCOV_COVJUMP_RECENT_N];
	char syscalls_buf[256];
	char childops_buf[256];
	char tag_buf[64];
	unsigned int top_n = 0;
	unsigned int op, i;
	struct childdata *cc;
	enum plateau_hypothesis hyp;
	int arm;
	bool bridge_hit, conntrack_hit, mld_hit, mempress_hit;

	if (kcov_shm == NULL)
		return;

	/* First-call arm.  RELEASE-store the gate after the companion
	 * fields are seeded so a peer that observes covjump_window_armed
	 * via the ACQUIRE pair below also sees the freshly seeded
	 * snapshot. */
	if (!__atomic_load_n(&kcov_shm->covjump_window_armed,
			     __ATOMIC_ACQUIRE)) {
		bool expected = false;

		edges_now = __atomic_load_n(&kcov_shm->distinct_edges,
					    __ATOMIC_RELAXED);
		covjump_seed_snapshot(call_nr, edges_now);
		__atomic_compare_exchange_n(&kcov_shm->covjump_window_armed,
			&expected, true, false,
			__ATOMIC_RELEASE, __ATOMIC_RELAXED);
		return;
	}

	expected_start = __atomic_load_n(&kcov_shm->covjump_window_start_call_nr,
					 __ATOMIC_RELAXED);
	if (call_nr <= expected_start)
		return;
	elapsed = call_nr - expected_start;
	if (elapsed < KCOV_COVJUMP_WINDOW_CALLS)
		return;

	/* CAS-elect a single window-advance winner.  Losers see the new
	 * start on a later call and re-evaluate. */
	if (!__atomic_compare_exchange_n(&kcov_shm->covjump_window_start_call_nr,
		&expected_start, call_nr, false,
		__ATOMIC_RELAXED, __ATOMIC_RELAXED))
		return;

	sample_calls = call_nr - expected_start;
	edges_now = __atomic_load_n(&kcov_shm->distinct_edges, __ATOMIC_RELAXED);
	edges_prev = __atomic_load_n(&kcov_shm->covjump_window_start_distinct_edges,
				     __ATOMIC_RELAXED);
	delta = (edges_now >= edges_prev) ? edges_now - edges_prev : 0;

	/* Refresh the edge snapshot every window even when the delta is
	 * sub-threshold so the NEXT window measures a contiguous interval. */
	__atomic_store_n(&kcov_shm->covjump_window_start_distinct_edges,
			 edges_now, __ATOMIC_RELAXED);

	if (delta < KCOV_COVJUMP_DELTA_THRESHOLD)
		goto refresh_snapshot;

	last_emit = __atomic_load_n(&kcov_shm->covjump_last_emit_call_nr,
				    __ATOMIC_RELAXED);
	if (last_emit != 0 && call_nr - last_emit < KCOV_COVJUMP_RATE_CAP_CALLS)
		goto refresh_snapshot;
	__atomic_store_n(&kcov_shm->covjump_last_emit_call_nr, call_nr,
			 __ATOMIC_RELAXED);

	/* Snapshot live + saved counters for the line. */
	if (minicorpus_shm != NULL) {
		saves_pc_now = __atomic_load_n(&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_PC],
					       __ATOMIC_RELAXED);
		saves_cmp_now = __atomic_load_n(&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_CMP],
						__ATOMIC_RELAXED);
	}
	if (chain_corpus_shm != NULL) {
		chain_saves_now = __atomic_load_n(&chain_corpus_shm->save_count,
						  __ATOMIC_RELAXED);
		chain_replays_now = __atomic_load_n(&chain_corpus_shm->replay_count,
						    __ATOMIC_RELAXED);
	}
	saves_pc_snap = __atomic_load_n(&kcov_shm->covjump_snap_saves_pc,
					__ATOMIC_RELAXED);
	saves_cmp_snap = __atomic_load_n(&kcov_shm->covjump_snap_saves_cmp,
					 __ATOMIC_RELAXED);
	chain_saves_snap = __atomic_load_n(&kcov_shm->covjump_snap_chain_saves,
					   __ATOMIC_RELAXED);
	chain_replays_snap = __atomic_load_n(&kcov_shm->covjump_snap_chain_replays,
					     __ATOMIC_RELAXED);
	for (op = 0; op < KCOV_CHILDOP_NR_MAX; op++) {
		now_childop[op] = 0;
		if (op < (unsigned int)NR_CHILD_OP_TYPES)
			now_childop[op] = __atomic_load_n(
				&shm->stats.childop_invocations[op],
				__ATOMIC_RELAXED);
		snap_childop[op] = __atomic_load_n(
			&kcov_shm->covjump_snap_childop_invocations[op],
			__ATOMIC_RELAXED);
	}

	/* Top-N childops by per-window invocation delta.  Trivial
	 * insertion sort over the small KCOV_COVJUMP_RECENT_N tail. */
	for (i = 0; i < KCOV_COVJUMP_RECENT_N; i++) {
		top_idx[i] = 0;
		top_delta[i] = 0;
	}
	for (op = 0; op < KCOV_CHILDOP_NR_MAX && op < (unsigned int)NR_CHILD_OP_TYPES; op++) {
		unsigned long d;

		if (now_childop[op] <= snap_childop[op])
			continue;
		d = now_childop[op] - snap_childop[op];
		for (i = 0; i < KCOV_COVJUMP_RECENT_N; i++) {
			if (d > top_delta[i]) {
				unsigned int j;

				for (j = KCOV_COVJUMP_RECENT_N - 1; j > i; j--) {
					top_delta[j] = top_delta[j - 1];
					top_idx[j] = top_idx[j - 1];
				}
				top_delta[i] = d;
				top_idx[i] = op;
				if (top_n < KCOV_COVJUMP_RECENT_N)
					top_n++;
				break;
			}
		}
	}

	bridge_hit = covjump_any_delta(covjump_bridge_ops,
		sizeof(covjump_bridge_ops) / sizeof(covjump_bridge_ops[0]),
		now_childop, snap_childop);
	conntrack_hit = covjump_any_delta(covjump_conntrack_ops,
		sizeof(covjump_conntrack_ops) / sizeof(covjump_conntrack_ops[0]),
		now_childop, snap_childop);
	mld_hit = covjump_any_delta(covjump_mld_ops,
		sizeof(covjump_mld_ops) / sizeof(covjump_mld_ops[0]),
		now_childop, snap_childop);
	mempress_hit = covjump_any_delta(covjump_mempress_ops,
		sizeof(covjump_mempress_ops) / sizeof(covjump_mempress_ops[0]),
		now_childop, snap_childop);

	/* Recent per-child syscall names from THIS child's syscall_ring
	 * (the CAS winner -- one of many in-flight children).  Bounded to
	 * KCOV_COVJUMP_RECENT_N entries; head-1 is the most recent. */
	syscalls_buf[0] = '\0';
	cc = this_child();
	if (cc != NULL) {
		struct child_syscall_ring *ring = &cc->syscall_ring;
		uint32_t head = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);
		size_t pos = 0;

		for (i = 0; i < KCOV_COVJUMP_RECENT_N; i++) {
			uint32_t slot;
			const struct chronicle_slot *s;
			const char *name;
			int n;

			if (head == 0 && i == 0)
				break;
			slot = (head + CHILD_SYSCALL_RING_SIZE - 1 - i)
				% CHILD_SYSCALL_RING_SIZE;
			s = &ring->recent[slot];
			if (!s->valid)
				break;
			name = print_syscall_name(s->nr, s->do32bit);
			if (name == NULL)
				name = "?";
			n = snprintf(syscalls_buf + pos,
				     sizeof(syscalls_buf) - pos,
				     "%s%s", pos == 0 ? "" : ",", name);
			if (n < 0 || (size_t)n >= sizeof(syscalls_buf) - pos)
				break;
			pos += (size_t)n;
		}
	}
	if (syscalls_buf[0] == '\0')
		snprintf(syscalls_buf, sizeof(syscalls_buf), "none");

	childops_buf[0] = '\0';
	{
		size_t pos = 0;

		for (i = 0; i < top_n; i++) {
			const char *name = alt_op_name(
				(enum child_op_type)top_idx[i]);
			int n;

			if (name == NULL)
				name = "?";
			n = snprintf(childops_buf + pos,
				     sizeof(childops_buf) - pos,
				     "%s%s:%lu", pos == 0 ? "" : ",",
				     name, top_delta[i]);
			if (n < 0 || (size_t)n >= sizeof(childops_buf) - pos)
				break;
			pos += (size_t)n;
		}
	}
	if (childops_buf[0] == '\0')
		snprintf(childops_buf, sizeof(childops_buf), "none");

	hyp = strategy_plateau_hypothesis_current();
	arm = __atomic_load_n(&shm->current_strategy, __ATOMIC_RELAXED);
	tag_buf[0] = '\0';
	{
		size_t pos = 0;
		int n;

		if (bridge_hit) {
			n = snprintf(tag_buf + pos, sizeof(tag_buf) - pos,
				     "bridge");
			if (n > 0) pos += (size_t)n;
		}
		if (conntrack_hit && pos < sizeof(tag_buf)) {
			n = snprintf(tag_buf + pos, sizeof(tag_buf) - pos,
				     "%sconntrack", pos == 0 ? "" : ",");
			if (n > 0) pos += (size_t)n;
		}
		if (mld_hit && pos < sizeof(tag_buf)) {
			n = snprintf(tag_buf + pos, sizeof(tag_buf) - pos,
				     "%smld", pos == 0 ? "" : ",");
			if (n > 0) pos += (size_t)n;
		}
		if (mempress_hit && pos < sizeof(tag_buf)) {
			/* Last tag in the chain -- no further appends, so we
			 * neither capture snprintf's return nor advance pos. */
			(void) snprintf(tag_buf + pos, sizeof(tag_buf) - pos,
					"%smempress", pos == 0 ? "" : ",");
		}
	}
	if (tag_buf[0] == '\0')
		snprintf(tag_buf, sizeof(tag_buf), "none");

	stats_log_write(
		"COVJUMP: distinct_edges +%lu over %lu calls (>=%lu) prev=%lu now=%lu hypothesis=%s arm=%s syscalls=[%s] childops=[%s] saves(pc/cmp)=+%lu/+%lu chain(save/replay)=+%lu/+%lu tags=[%s]\n",
		delta, sample_calls, KCOV_COVJUMP_DELTA_THRESHOLD,
		edges_prev, edges_now,
		strategy_plateau_hypothesis_name(hyp),
		strategy_name(arm),
		syscalls_buf, childops_buf,
		saves_pc_now > saves_pc_snap ? saves_pc_now - saves_pc_snap : 0UL,
		saves_cmp_now > saves_cmp_snap ? saves_cmp_now - saves_cmp_snap : 0UL,
		chain_saves_now > chain_saves_snap ? chain_saves_now - chain_saves_snap : 0UL,
		chain_replays_now > chain_replays_snap ? chain_replays_now - chain_replays_snap : 0UL,
		tag_buf);

refresh_snapshot:
	covjump_seed_snapshot(call_nr, edges_now);
}

void kcov_plateau_check(void)
{
	unsigned long edges_now, delta;
	struct timespec ts;
	time_t now;
	long elapsed;

	if (kcov_shm == NULL)
		return;

	/* CLOCK_MONOTONIC: window math must not be perturbed by a backward
	 * wall-clock step (e.g. an NTP correction), which under the prior
	 * CLOCK_REALTIME sampling yielded a negative elapsed and bogus
	 * plateau-window arithmetic.  plateau_window_start and
	 * plateau_entered_at are stamped from the monotonic clock too, so
	 * before/after stay in the same domain. */
	clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts.tv_sec;
	/* Sample distinct_edges, not edges_found.  edges_found increments on
	 * every (edge, bucket) bit-flip including bucket churn on already-
	 * known edges, so its per-window delta stays above threshold on flat
	 * runs and the plateau detector never fires.  distinct_edges
	 * increments once per edge (on bucket_seen[edge] == 0 -> first-bit)
	 * so its delta reflects true new-code discovery and falls to zero
	 * when the fuzzer is wedged. */
	edges_now = __atomic_load_n(&kcov_shm->distinct_edges, __ATOMIC_RELAXED);

	/* Arm the window on the first call so any pre-existing edge count
	 * (e.g. from the warm-up phase before main_loop entry) is not
	 * mis-attributed to the first 10-minute window.
	 *
	 * Companion fields (plateau_window_start, plateau_prev_edges) are
	 * written before the RELEASE-store of plateau_armed so a child
	 * reader that observes plateau_armed=true via the ACQUIRE pair is
	 * guaranteed to also see the seeded companion state. */
	if (!__atomic_load_n(&kcov_shm->plateau_armed, __ATOMIC_RELAXED)) {
		__atomic_store_n(&kcov_shm->plateau_window_start, now,
				 __ATOMIC_RELAXED);
		__atomic_store_n(&kcov_shm->plateau_prev_edges, edges_now,
				 __ATOMIC_RELAXED);
		__atomic_store_n(&kcov_shm->plateau_armed, true,
				 __ATOMIC_RELEASE);
		return;
	}

	elapsed = (long)(now - __atomic_load_n(&kcov_shm->plateau_window_start,
					       __ATOMIC_RELAXED));
	if (elapsed < 0)
		elapsed = 0;
	if (elapsed < KCOV_PLATEAU_WINDOW_SEC)
		return;

	{
		unsigned long prev_edges =
			__atomic_load_n(&kcov_shm->plateau_prev_edges,
					__ATOMIC_RELAXED);
		delta = (edges_now >= prev_edges) ? edges_now - prev_edges : 0;
	}
	__atomic_store_n(&kcov_shm->plateau_last_window_delta, delta,
			 __ATOMIC_RELAXED);
	__atomic_store_n(&kcov_shm->plateau_prev_edges, edges_now,
			 __ATOMIC_RELAXED);
	__atomic_store_n(&kcov_shm->plateau_window_start, now,
			 __ATOMIC_RELAXED);

	if (delta < KCOV_PLATEAU_ENTER_THRESHOLD) {
		/* Edge-triggered: emit the warning, bump the transition
		 * counter, and fire the auto-response hook only when we cross
		 * from healthy into PLATEAU.  Subsequent ticks while still in
		 * plateau stay silent so the operator's stats.log gets one
		 * line per episode rather than one per 600s window. */
		if (!__atomic_load_n(&kcov_shm->plateau_active,
				     __ATOMIC_ACQUIRE)) {
			/* Set entered_at BEFORE the RELEASE-store of
			 * plateau_active so a child reader pairing an
			 * ACQUIRE-load of plateau_active with a subsequent
			 * read of plateau_entered_at sees the freshly
			 * stamped entry time, not a stale 0 from a prior
			 * clearance. */
			__atomic_store_n(&kcov_shm->plateau_entered_at, now,
					 __ATOMIC_RELAXED);
			__atomic_store_n(&kcov_shm->plateau_active, true,
					 __ATOMIC_RELEASE);
			__atomic_fetch_add(&shm->stats.plateau_entered, 1,
					   __ATOMIC_RELAXED);
			stats_log_write("PLATEAU: edge-discovery rate %lu edges/%ds < enter-threshold (%d) sustained for >=%d minutes (bandit may be in local minimum, consider intervention)\n",
					delta, KCOV_PLATEAU_WINDOW_SEC,
					KCOV_PLATEAU_ENTER_THRESHOLD,
					KCOV_PLATEAU_WINDOW_SEC / 60);
			strategy_plateau_response();
			/* Lock in the current bitmap on plateau entry --
			 * discovery has stalled, so the bucket_seen table
			 * is at its high-water mark for this run.  Snapshot
			 * even if the periodic cadence wouldn't have fired
			 * yet; bypass the gate via a one-shot. */
			kcov_bitmap_maybe_snapshot();
		}
	} else if (delta >= KCOV_PLATEAU_EXIT_THRESHOLD &&
		   __atomic_load_n(&kcov_shm->plateau_active,
				   __ATOMIC_ACQUIRE)) {
		long elapsed_secs = (long)(now - __atomic_load_n(
				&kcov_shm->plateau_entered_at,
				__ATOMIC_RELAXED));
		long minutes = elapsed_secs > 0 ? elapsed_secs / 60 : 0;

		/* Hysteresis band: ENTER <= delta < EXIT keeps the current
		 * state (stay plateaued; don't re-arm a healthy run yet).
		 * Only a recovery past the higher EXIT bar clears the flag,
		 * preventing the edge-rate oscillation around ENTER from
		 * flapping plateau_active window-by-window. */
		__atomic_store_n(&kcov_shm->plateau_entered_at, 0,
				 __ATOMIC_RELAXED);
		__atomic_store_n(&kcov_shm->plateau_active, false,
				 __ATOMIC_RELEASE);
		__atomic_fetch_add(&shm->stats.plateau_exited, 1,
				   __ATOMIC_RELAXED);
		stats_log_write("PLATEAU CLEARED: edge-discovery rate %lu edges/%ds >= exit-threshold (%d) (plateau lasted %ld minutes)\n",
				delta, KCOV_PLATEAU_WINDOW_SEC,
				KCOV_PLATEAU_EXIT_THRESHOLD, minutes);
	}
}

