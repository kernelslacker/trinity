

#include <string.h>
#include <time.h>
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "strategy.h"
#include "trinity.h"
#include "main-internal.h"

/*
 * Drain the parent-visible KCOV_TRACE_CMP failure slots and emit a
 * single one-line summary of any sites that recorded a failure.  The
 * slots are written from child context — see struct kcov_cmp_diag —
 * so this is the only place they reach the operator's log.  Stays
 * silent when every count is zero so a healthy run doesn't add noise
 * to the stats cadence.
 */
static void print_kcov_cmp_diag(void)
{
	char buf[512];
	int n;
	unsigned int pc_kids, cmp_kids;

	if (kcov_shm == NULL)
		return;

	pc_kids  = __atomic_load_n(&kcov_shm->pc_mode_children,  __ATOMIC_RELAXED);
	cmp_kids = __atomic_load_n(&kcov_shm->cmp_mode_children, __ATOMIC_RELAXED);

	/* MODES has been folded into the KCOV bracket on the main
	 * iterations line — no separate emission here. */
	(void)pc_kids;
	(void)cmp_kids;

	n = kcov_cmp_diag_format(buf, sizeof(buf), KCOV_CMP_DIAG_ALL);
	if (n == 0)
		return;

	(void)n;
	/* Only emit if the DIAG payload changed since last dump — a
	 * stable run with a handful of init-time errnos shouldn't repeat
	 * the same line every cycle. */
	{
		static char last_buf[512];
		if (strcmp(buf, last_buf) != 0) {
			output(0, "KCOV CMP DIAG:%s\n", buf);
			snprintf(last_buf, sizeof(last_buf), "%s", buf);
		}
	}
}

/*
 * Drain the parent-visible KCOV PC/remote enable/disable failure
 * and retry slots.  Same suppression logic as the CMP version:
 * silent when everything is zero, only re-emits when the payload
 * changes since the last cycle.
 */
static void print_kcov_pc_diag(void)
{
	char buf[512];
	int n;

	if (kcov_shm == NULL)
		return;

	n = kcov_pc_diag_format(buf, sizeof(buf));
	if (n == 0)
		return;

	(void)n;
	{
		static char last_buf[512];
		if (strcmp(buf, last_buf) != 0) {
			output(0, "KCOV PC DIAG:%s\n", buf);
			snprintf(last_buf, sizeof(last_buf), "%s", buf);
		}
	}

	/* One-shot trap dump: emits the full chronicle snapshot +
	 * recovery counters captured by kcov_latch_first_ebadf() the
	 * first time first_ebadf_op_nr surfaces non-zero.  Subsequent
	 * calls are silent (process-local one-shot inside the helper).
	 * Parent-only call site -- children's output() is routed to
	 * /dev/null and would discard the dump. */
	(void) kcov_first_ebadf_trap_drain();
}

static unsigned long print_stats_compute_op_rate(unsigned long ops_delta)
{
	static struct timespec last_tp = { 0 };
	struct timespec now;
	unsigned long rate = 0;

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (last_tp.tv_sec > 0) {
		double elapsed = (now.tv_sec - last_tp.tv_sec) +
			(now.tv_nsec - last_tp.tv_nsec) / 1e9;
		if (elapsed > 0.01)
			rate = (unsigned long)(ops_delta / elapsed);
	}
	last_tp = now;
	return rate;
}

static void print_stats_iteration_line(unsigned long op_count, unsigned long rate, const char *stalltxt)
{
	if (kcov_shm != NULL) {
		static unsigned long last_edges = 0;
		static unsigned long last_distinct = 0;
		static unsigned long last_cmp_trunc = 0;
		static unsigned long last_cmp_unique = 0;
		unsigned long edges = __atomic_load_n(
			&kcov_shm->coverage.edges_found,
			__ATOMIC_RELAXED);
		unsigned long distinct = __atomic_load_n(
			&kcov_shm->coverage.distinct_edges,
			__ATOMIC_RELAXED);
		unsigned long cmp_trunc = __atomic_load_n(
			&kcov_shm->cmp_trace_truncated,
			__ATOMIC_RELAXED);
		unsigned long cmp_unique = __atomic_load_n(
			&kcov_shm->cmp_hints_unique_inserts,
			__ATOMIC_RELAXED);
		unsigned int pc_kids = __atomic_load_n(
			&kcov_shm->pc_mode_children, __ATOMIC_RELAXED);
		unsigned int cmp_kids = __atomic_load_n(
			&kcov_shm->cmp_mode_children, __ATOMIC_RELAXED);
		long delta = edges - last_edges;
		long distinct_delta = distinct - last_distinct;
		long cmp_trunc_delta = cmp_trunc - last_cmp_trunc;
		long cmp_unique_delta = cmp_unique - last_cmp_unique;

		/* Compact KCOV bracket: edges + CMP unique + MODES.
		 * Raw cmp_records is dropped -- it's massively inflated by
		 * dedup-refresh on hot syscalls and tells us nothing about
		 * novel CMP signal.  unique is the per-record subset that
		 * actually changed pool state (insert or evict-replace),
		 * i.e. the records that survived bloom + pool dedup.
		 * MODES is folded inline so the periodic dump is one line
		 * instead of two/three.
		 *
		 * Suppress zero-deltas; suppress unique and MODES sections
		 * when their counters are zero so plateau / no-CMP windows
		 * read cleanly.  trunc still gets its own trailing bracket
		 * when non-zero (rare; per-syscall KCOV_CMP_RECORDS_MAX
		 * overflow signal). */
		char distinct_delta_str[32] = "";
		char bucket_delta_str[32] = "";
		char warm_cold_str[48] = "";
		char unique_str[80] = "";
		char modes_str[48] = "";
		char trunc_str[48] = "";
		/* Print each count's per-window delta as " (+N)" right
		 * after the count, suppressed when that delta is zero (and
		 * on the first window, before last_* are seeded), so the
		 * line shape stays uncluttered on quiet windows. */
		if (last_edges > 0 && distinct_delta != 0)
			snprintf(distinct_delta_str,
				sizeof(distinct_delta_str),
				" (%+ld)", distinct_delta);
		if (last_edges > 0 && delta != 0)
			snprintf(bucket_delta_str,
				sizeof(bucket_delta_str),
				" (%+ld)", delta);
		/* Warm vs cold split: edges_warm_loaded is the count
		 * the warm-start cache loader seeded at startup; the
		 * remainder of edges_found is what this process has
		 * discovered on its own.  Suppress the parens entirely
		 * on cold-start runs (no cache loaded -> warm == 0) so
		 * the line shape matches the pre-instrumentation form
		 * and doesn't add noise to the common case.  Defensive
		 * clamp: if warm somehow exceeds the current total
		 * (shouldn't happen — warm is set once at load time and
		 * edges_found only grows), report cold as 0 rather than
		 * printing a negative cold count. */
		{
			unsigned long warm = __atomic_load_n(
				&kcov_shm->coverage.edges_warm_loaded,
				__ATOMIC_RELAXED);
			if (warm > 0) {
				unsigned long cold = edges > warm ?
					edges - warm : 0UL;
				snprintf(warm_cold_str,
					sizeof(warm_cold_str),
					" (warm=%lu cold=%lu)",
					warm, cold);
			}
		}
		if (cmp_unique > 0) {
			if (last_cmp_unique > 0 && cmp_unique_delta != 0)
				snprintf(unique_str, sizeof(unique_str),
					" CMP: %lu unique, %+ld",
					cmp_unique, cmp_unique_delta);
			else
				snprintf(unique_str, sizeof(unique_str),
					" CMP: %lu unique", cmp_unique);
		}
		if (cmp_kids > 0)
			snprintf(modes_str, sizeof(modes_str),
				"  CMP MODES: pc=%u cmp=%u",
				pc_kids, cmp_kids);
		if (cmp_trunc > 0) {
			if (last_cmp_trunc > 0 && cmp_trunc_delta != 0)
				snprintf(trunc_str, sizeof(trunc_str),
					" [%lu trunc, %+ld]",
					cmp_trunc, cmp_trunc_delta);
			else
				snprintf(trunc_str, sizeof(trunc_str),
					" [%lu trunc]", cmp_trunc);
		}
		output(0, "%ld iterations. [HI:%ld%s] %lu/sec  KCOV: [%lu%s distinct, %lu%s bucket%s%s%s]%s\n",
			op_count,
			hiscore,
			stall_count ? stalltxt : "",
			rate,
			distinct, distinct_delta_str, edges, bucket_delta_str,
			warm_cold_str,
			unique_str,
			modes_str,
			trunc_str);
		last_edges = edges;
		last_distinct = distinct;
		last_cmp_trunc = cmp_trunc;
		last_cmp_unique = cmp_unique;
		print_kcov_cmp_diag();
		print_kcov_pc_diag();
	} else {
		output(0, "%ld iterations. [HI:%ld%s] %lu/sec\n",
			op_count,
			hiscore,
			stall_count ? stalltxt : "",
			rate);
	}
}

static void print_stats_picker_state(enum picker_mode_t pmode, bool plateau)
{
	/*
	 * Coalesce identical PICKER lines.  In steady-state runs
	 * the tuple (pmode, explorers, plateau) is unchanged
	 * window after window and the line just repeats.  Skip
	 * the repeats but force a print every 30 windows so the
	 * log still carries a periodic state anchor.
	 */
	static enum picker_mode_t last_pmode;
	static unsigned int last_picker_explorers;
	static bool last_plateau;
	static unsigned int picker_suppress = 30; /* force first print */
	if (picker_suppress >= 30 ||
	    pmode != last_pmode ||
	    explorer_children != last_picker_explorers ||
	    plateau != last_plateau) {
		output(0, "PICKER: [picker=%s explorers=%u plateau=%s]\n",
			picker_mode_name(pmode),
			explorer_children,
			plateau ? "active" : "idle");
		last_pmode = pmode;
		last_picker_explorers = explorer_children;
		last_plateau = plateau;
		picker_suppress = 0;
	} else {
		picker_suppress++;
	}
}

static void print_stats_plateau_warning(enum picker_mode_t pmode, bool plateau)
{
	/*
	 * One-shot warning when the plateau detector fires
	 * under a non-bandit picker: the intervention
	 * rotation (RRC-bias / anti-prior / uniform-random)
	 * only runs in PICKER_BANDIT_UCB1 mode, so the
	 * round-robin / future-picker operator needs to know
	 * the plateau machinery they're watching go active
	 * isn't going to respond.  One-shot per plateau
	 * transition (active rising edge), not per dump, so a
	 * long plateau doesn't spam the log.
	 */
	static bool warned_this_plateau = false;
	if (plateau && pmode != PICKER_BANDIT_UCB1) {
		if (!warned_this_plateau) {
			output(0, "WARNING: plateau detected under non-bandit picker; plateau response is bandit-only\n");
			warned_this_plateau = true;
		}
	} else if (!plateau) {
		warned_this_plateau = false;
	}
}

static void print_stats_plateau_hypothesis(bool plateau)
{
	/*
	 * Plateau hypothesis ruleset.  Drive the per-
	 * tick check here so the hypothesis
	 * classification cadence matches the cadence
	 * the operator reads the KCOV/PICKER block at
	 * -- a transition log line in stats.log will
	 * be accompanied by the same window's
	 * hypothesis line in the periodic dump.
	 * Suppress the visibility line entirely when
	 * plateau is idle so healthy runs do not
	 * carry a perpetual NONE annotation.  The
	 * fire-count tail stays visible across plateau
	 * transitions only -- printing it on every
	 * stats tick during healthy windows would
	 * obscure that nothing has fired yet on a
	 * fresh run.
	 */
	strategy_plateau_hypothesis_tick();
	if (plateau) {
		enum plateau_hypothesis ph =
			strategy_plateau_hypothesis_current();
		const struct plateau_window_snapshot *d =
			strategy_plateau_hypothesis_delta();
		output(0,
			"plateau_hypothesis: %s (cmp_delta=+%lu pc_delta=+%lu childop_calls_delta=+%lu childop_edges_delta=+%lu generic_delta=+%lu remote_delta=+%lu/+%lu frontier_pulls=%lu frontier_picks=%lu frontier_live=%lu frontier_silent=%lu) fires: cmp_rising_pc_flat=%lu childop_dominant=%lu remote_dominant=%lu frontier_cold=%lu single_group_dominant=%lu cd_iv=%lu cr_iv=%lu\n",
			strategy_plateau_hypothesis_name(ph),
			d->cmp_unique,
			d->pc_edges,
			d->childop_calls_total,
			d->childop_edges_total,
			d->bandit_edges + d->explorer_edges,
			d->remote_calls,
			d->total_calls,
			d->frontier_pulls,
			d->frontier_picks,
			d->frontier_live_picks,
			d->frontier_silent_picks,
			strategy_plateau_hypothesis_fires(
				PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT),
			strategy_plateau_hypothesis_fires(
				PLATEAU_HYPOTHESIS_CHILDOP_DOMINANT),
			strategy_plateau_hypothesis_fires(
				PLATEAU_HYPOTHESIS_REMOTE_DOMINANT),
			strategy_plateau_hypothesis_fires(
				PLATEAU_HYPOTHESIS_FRONTIER_COLD),
			strategy_plateau_hypothesis_fires(
				PLATEAU_HYPOTHESIS_SINGLE_GROUP_DOMINANT),
			__atomic_load_n(
				&shm->stats.childop.burst_alt_picks_window,
				__ATOMIC_RELAXED),
			__atomic_load_n(
				&minicorpus_shm->cmp_rising_replay_picks,
				__ATOMIC_RELAXED));
	}
}

static void print_stats_pool_ratio(void)
{
	/* Per-pool live ratio.  When the explorer pool is empty
	 * (e.g. -C N where N/8 rounds to zero, common with ASAN
	 * configs), drop the explorer half of the line but still
	 * report bandit activity so edge-discovery visibility
	 * isn't lost. */
	static unsigned long last_bandit_edges = 0;
	unsigned long b_cur = __atomic_load_n(
		&shm->stats.picker_bandit.bandit_pool_edges_discovered,
		__ATOMIC_RELAXED);
	unsigned long b_delta = b_cur - last_bandit_edges;

	if (explorer_children > 0) {
		static unsigned long last_explorer_edges = 0;
		unsigned long e_cur = __atomic_load_n(
			&shm->stats.picker_bandit.explorer_pool_edges_discovered,
			__ATOMIC_RELAXED);
		unsigned long total = e_cur + b_cur;
		unsigned long e_delta = e_cur - last_explorer_edges;
		unsigned int e_share_pct = total > 0 ?
			(unsigned int)(e_cur * 100UL / total) : 0;
		unsigned int b_share_pct = 100U - e_share_pct;
		char e_delta_str[24] = "";
		char b_delta_str[24] = "";
		if (e_delta > 0)
			snprintf(e_delta_str, sizeof(e_delta_str),
				"/+%lu", e_delta);
		if (b_delta > 0)
			snprintf(b_delta_str, sizeof(b_delta_str),
				"/+%lu", b_delta);

		/*
		 * Coalesce identical explorer/bandit lines.  When both
		 * e_delta and b_delta are zero (steady-state run) the
		 * line is byte-for-byte unchanged, so suppress repeats
		 * and force a print every 30 windows to keep an anchor.
		 */
		static unsigned int last_eb_explorers;
		static unsigned int last_eb_max;
		static unsigned long last_eb_e_cur;
		static unsigned long last_eb_b_cur;
		static unsigned int eb_suppress = 30; /* force first print */
		if (eb_suppress >= 30 ||
		    explorer_children != last_eb_explorers ||
		    max_children != last_eb_max ||
		    e_cur != last_eb_e_cur ||
		    b_cur != last_eb_b_cur) {
			output(0, "explorer: %u/%u children, %lu edges (%u%%%s)  bandit: %u/%u, %lu edges (%u%%%s)\n",
				explorer_children, max_children,
				e_cur, e_share_pct, e_delta_str,
				max_children - explorer_children, max_children,
				b_cur, b_share_pct, b_delta_str);
			last_eb_explorers = explorer_children;
			last_eb_max = max_children;
			last_eb_e_cur = e_cur;
			last_eb_b_cur = b_cur;
			eb_suppress = 0;
		} else {
			eb_suppress++;
		}
		last_explorer_edges = e_cur;
	} else {
		if (b_delta > 0)
			output(0, "bandit: %u/%u children, %lu edges (+%lu)\n",
				max_children, max_children,
				b_cur, b_delta);
		else
			output(0, "bandit: %u/%u children, %lu edges\n",
				max_children, max_children, b_cur);
	}
	last_bandit_edges = b_cur;
}

void print_stats(void)
{
	unsigned long op_count = parent_stats.op_count;

	if (quiet)
		return;

	if (op_count > 1) {
		static unsigned long lastcount = 0;

		if (op_count - lastcount > 10000) {
			unsigned long rate;
			char stalltxt[32] = "";

			rate = print_stats_compute_op_rate(op_count - lastcount);

			if (stall_count > 0 && stall_count < 10000)
				snprintf(stalltxt, sizeof(stalltxt), " STALLED:%u", stall_count);

			print_stats_iteration_line(op_count, rate, stalltxt);

			if (kcov_shm != NULL) {
				/*
				 * Operator-facing picker state.  The plateau-
				 * intervention path in select_next_strategy() and
				 * the mode-aware explorer_children default are both
				 * bandit-gated, so when something looks wrong with
				 * the adaptive response the first question is always
				 * "which picker is actually running, and is the
				 * explorer pool non-empty?".  Surface it on every
				 * KCOV dump so the answer is in the same log line
				 * window as the edge counters that prompt the
				 * question.  No separate timer -- piggybacks on the
				 * existing periodic dump cadence.
				 */
				enum picker_mode_t pmode = (enum picker_mode_t)__atomic_load_n(
					&shm->picker_mode, __ATOMIC_RELAXED);
				bool plateau = __atomic_load_n(
					&kcov_shm->plateau_active,
					__ATOMIC_ACQUIRE);

				print_stats_picker_state(pmode, plateau);
				print_stats_plateau_warning(pmode, plateau);
				print_stats_plateau_hypothesis(plateau);
			}

			print_stats_pool_ratio();

			/* Per-syscall timeseries side-effect of --stats.
			 * No-op when --stats was not passed (the file was
			 * never opened in main_init()).  Piggybacks on the
			 * existing ~10k-op cadence so the operator gets one
			 * JSONL record per visible iterations line. */
			stats_timeseries_emit_window(op_count);

			lastcount = op_count;
		}
	}
}
