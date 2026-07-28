/*
 * Shadow soft-saturation score (row t371-b, plateau-slice observability).
 *
 * OBSERVATION-ONLY: computed every stats interval, consumed by NOTHING.
 * The hard-stall detector (kcov/plateau.c) only fires when the 600s
 * distinct-edges delta drops below KCOV_PLATEAU_ENTER_THRESHOLD (=10).
 * The rc5 saturated tail still gains ~420 edges/600s and reads
 * "healthy" to that detector -- economic saturation is invisible.
 *
 * This module keeps a ring of parent-side samples covering the last
 * ~60 minutes and, on every window, computes distinct-edge yield over
 * two trailing horizons (~10 min short, ~60 min long) normalised three
 * ways: per 10,000 completed calls (work-normalised), per wall-hour,
 * per CPU-hour.  A shadow `soft_saturated` boolean rises when both
 * horizons' yield sit below configured floors for K consecutive evals
 * (hysteresis).  Fleet-health signals veto the diagnosis -- if
 * throughput dropped in half, children wedged in D-state (`stall_count`
 * > 0), `trace_truncated` is rising in the short window, or active
 * findings (post_handler_corrupt_ptr / watchdog_fd_evict) are landing
 * in the short window, we emit the veto reason instead of concluding
 * saturated.
 *
 * MVP scope: trailing-rate + floor + hysteresis only.  No Bayesian
 * confidence interval.  The raw per-window edge blocks emitted at the
 * tail of the JSONL record let a better estimator (blocked-bootstrap
 * over rotation windows / negative-binomial -- doc's preference) be
 * dropped in later without another trinity run.
 *
 * Byte-identical guarantee: no new RNG draws, no pick/dispatch reorder,
 * no shm scalars.  Only reads: kcov_shm->coverage.{distinct_edges,
 * trace_truncated} (already loaded on this hot path), parent_stats.
 * {op_count, post_handler_corrupt_ptr, watchdog_fd_evict} (parent's own
 * aggregates), stall_count (parent's own scalar), and a
 * getrusage(RUSAGE_CHILDREN) probe on the parent for CPU accounting.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/resource.h>
#include <sys/time.h>

#include "kcov.h"
#include "main-internal.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "trinity.h"
#include "utils-proc.h"

/*
 * Sampling ring.  One slot per stats-emit interval (~10k op boundary,
 * typically 5-15s wall).  Sized to comfortably cover the 60-minute
 * long horizon at any realistic op rate: 1024 slots @ ~5s each is
 * ~85 min of history, at 15s each ~4h.  Zero-init means the pre-fill
 * region contains {t=0, edges=0, ...} which is skipped by the
 * horizon-lookup helper (guarded on ring_count).
 */
#define SAT_RING_SIZE 1024

struct sat_sample {
	uint64_t t_ns;
	unsigned long edges;
	unsigned long calls;
	uint64_t cpu_ns;
	unsigned long trace_truncated;
	/*
	 * Snapshot of parent-side finding aggregates at sample time.  Sum
	 * of post_handler_corrupt_ptr (SELF-corrupt scribble catches) and
	 * watchdog_fd_evict (in-child SIGALRM watchdog fd evictions -- a
	 * proxy for children failing to make forward progress on syscalls
	 * that hold fds).  A short-window rate on this sum feeds the
	 * finding-pending veto: if the fuzzer is actively producing
	 * findings, low edge yield is not economic saturation, it is the
	 * corruption-and-recycle loop starving new coverage.
	 */
	unsigned long finding_events;
};

static struct sat_sample sat_ring[SAT_RING_SIZE];
static unsigned int sat_ring_head;	/* next write slot */
static unsigned int sat_ring_count;	/* saturated at SAT_RING_SIZE */

/* Horizons.  Short is a fast responder, long is the anchor: both must
 * agree the yield is below floor before hysteresis starts counting. */
#define SAT_SHORT_HORIZON_NS	(10ULL * 60ULL * 1000000000ULL)
#define SAT_LONG_HORIZON_NS	(60ULL * 60ULL * 1000000000ULL)

/* Floors.  Below these the yield is considered "not moving the needle"
 * for the corresponding denominator.  Two floors AND-gated so a burst
 * that's high on one normaliser but low on the other doesn't flip us.
 * Calibrated against the rc5 fixture: the flat/bursty tail (post ~1M
 * iters) averages ~7-20 new edges per 10k calls with occasional bursts
 * to 80; the pre-saturation region (i<50) sits at ~30-200.  A floor at
 * 25 catches the tail after the hysteresis smoothing without tripping
 * on healthy runs that gain hundreds of edges per 10k calls. */
#define SAT_FLOOR_EDGES_PER_10K_CALLS	25U
#define SAT_FLOOR_EDGES_PER_WALL_HOUR	5000U

/* Hysteresis depth.  K consecutive below-floor evals before soft-
 * saturated raises; a single above-floor eval resets it. */
#define SAT_HYSTERESIS_K		3U

/* Throughput-veto threshold: short-window call rate below half the
 * long-window rate is treated as a starvation event, not saturation.
 * rc5 tail dropped 841 -> 562/sec; anything worse than that is
 * plausibly a fleet or D-state stall, not economic saturation. */
#define SAT_THROUGHPUT_VETO_RATIO_NUM	1
#define SAT_THROUGHPUT_VETO_RATIO_DEN	2

/* Trace-truncation veto ratio: veto only when the short-window
 * truncation rate outstrips the long-window baseline by this multiple.
 * KCOV trace-truncation grows slowly and steadily on saturated tails
 * (rc5: ~15 trunc/window baseline).  Vetoing on any rise would fire
 * the entire tail and mask the very saturation we're trying to see.
 * The real supply-side event we care about is a sudden burst -- e.g.
 * short-window trunc rate 3x the long-window baseline. */
#define SAT_TRUNC_VETO_RATIO_NUM	3
#define SAT_TRUNC_VETO_RATIO_DEN	1

/* Finding-pending veto threshold.  When the short-window rate of
 * finding_events (post_handler_corrupt_ptr + watchdog_fd_evict) meets
 * or exceeds this many events per wall-hour, active findings are in
 * flight and the low edge yield is more likely the corruption-and-
 * recycle loop than economic saturation.  Calibrated against run2:
 * 1,541 watchdog kills across an ~hour dwarfs any reasonable rate
 * floor, and healthy runs with occasional stray corruption catches
 * (<1 per 10 min) stay under it. */
#define SAT_FINDING_VETO_MIN_PER_WALL_HOUR	6U

enum sat_veto_reason {
	SAT_VETO_NONE = 0,
	SAT_VETO_STALLED_CHILDREN,
	SAT_VETO_FINDING_PENDING,
	SAT_VETO_TRACE_TRUNC_RISING,
	SAT_VETO_THROUGHPUT_DROP,
};

static const char *sat_veto_name(enum sat_veto_reason r)
{
	switch (r) {
	case SAT_VETO_STALLED_CHILDREN:	  return "stalled_children";
	case SAT_VETO_FINDING_PENDING:	  return "finding_pending";
	case SAT_VETO_TRACE_TRUNC_RISING: return "trace_trunc_rising";
	case SAT_VETO_THROUGHPUT_DROP:	  return "throughput_drop";
	case SAT_VETO_NONE:
	default:			  return "none";
	}
}

struct sat_yield {
	bool valid;			/* window spans >= horizon/2 and has calls */
	uint64_t window_ns;
	unsigned long edges_delta;
	unsigned long calls_delta;
	uint64_t cpu_ns_delta;
	double edges_per_10k_calls;
	double edges_per_wall_hour;
	double edges_per_cpu_hour;
};

struct sat_state {
	bool soft_saturated;
	unsigned int consec_below;
	unsigned int hysteresis_k;
	enum sat_veto_reason veto;
	struct sat_yield short_win;
	struct sat_yield long_win;
	double short_call_rate;
	double long_call_rate;
	unsigned long health_stall_count;
	unsigned long health_trace_trunc_delta_short;
	unsigned long health_finding_events_delta_short;
	double health_finding_events_per_wall_hour;
	unsigned int floor_edges_per_10k_calls;
	unsigned int floor_edges_per_wall_hour;
	unsigned int floor_finding_events_per_wall_hour;
};

static unsigned int sat_consec_below;
static struct sat_state sat_last_state;

/*
 * Find the ring sample that closes a trailing (now_ns - horizon_ns)
 * window -- the newest sample at or before the cutoff, or the oldest
 * we have when history is shorter than horizon_ns.  Returns NULL when
 * the ring hasn't accumulated enough history to trust either yield
 * (< 2 samples, or the oldest is closer than horizon/2 -- half-horizon
 * threshold keeps a fresh run from firing off half-formed windows).
 */
static const struct sat_sample *sat_find_horizon(uint64_t now_ns,
						 uint64_t horizon_ns)
{
	unsigned int n, i;
	const struct sat_sample *best = NULL;
	uint64_t cutoff;
	uint64_t span;

	if (sat_ring_count < 2)
		return NULL;

	cutoff = (now_ns > horizon_ns) ? (now_ns - horizon_ns) : 0;
	n = (sat_ring_count < SAT_RING_SIZE) ? sat_ring_count : SAT_RING_SIZE;

	/* Walk back from the newest sample.  Stop at the first sample
	 * older than the cutoff (the ideal horizon match); fall through
	 * to the oldest sample we have if none crosses. */
	for (i = 1; i <= n; i++) {
		unsigned int idx = (sat_ring_head + SAT_RING_SIZE - i)
			& (SAT_RING_SIZE - 1);
		const struct sat_sample *s = &sat_ring[idx];

		best = s;
		if (s->t_ns <= cutoff)
			break;
	}

	span = (now_ns > best->t_ns) ? (now_ns - best->t_ns) : 0;
	if (span < horizon_ns / 2)
		return NULL;
	return best;
}

static void sat_compute_yield(struct sat_yield *y,
			      const struct sat_sample *cur,
			      const struct sat_sample *base)
{
	y->window_ns = (cur->t_ns > base->t_ns) ? (cur->t_ns - base->t_ns) : 0;
	y->edges_delta = sat_sub_ul(cur->edges, base->edges);
	y->calls_delta = sat_sub_ul(cur->calls, base->calls);
	y->cpu_ns_delta = (cur->cpu_ns > base->cpu_ns) ?
		(cur->cpu_ns - base->cpu_ns) : 0;
	y->valid = (y->window_ns > 0 && y->calls_delta > 0);
	y->edges_per_10k_calls = (y->calls_delta > 0) ?
		(double)y->edges_delta * 10000.0 / (double)y->calls_delta : 0.0;
	y->edges_per_wall_hour = (y->window_ns > 0) ?
		(double)y->edges_delta * 3.6e12 / (double)y->window_ns : 0.0;
	y->edges_per_cpu_hour = (y->cpu_ns_delta > 0) ?
		(double)y->edges_delta * 3.6e12 / (double)y->cpu_ns_delta : 0.0;
}

/*
 * Sample the current parent-visible counters, append to the ring, and
 * recompute the shadow state.  Called once per print_stats() window
 * from main/stats.c -- both are parent-only paths, no lock needed.
 */
void stats_shadow_sat_tick(void)
{
	struct sat_sample s = { 0 };
	struct rusage ru;
	struct sat_state st = { 0 };
	const struct sat_sample *sh;
	const struct sat_sample *lg;
	bool short_below, long_below;

	s.t_ns = mono_ns();
	if (kcov_shm != NULL) {
		s.edges = __atomic_load_n(
			&kcov_shm->coverage.distinct_edges, __ATOMIC_RELAXED);
		s.trace_truncated = __atomic_load_n(
			&kcov_shm->coverage.trace_truncated, __ATOMIC_RELAXED);
	}
	s.calls = parent_stats.op_count;
	s.finding_events = parent_stats.post_handler_corrupt_ptr
		+ parent_stats.watchdog_fd_evict;

	/* RUSAGE_CHILDREN accumulates CPU time of reaped children.
	 * Trinity reaps its fuzzer children (reap.c) so this is a live
	 * approximation of the fleet's CPU cost.  A getrusage failure
	 * just leaves cpu_ns=0 -- edges_per_cpu_hour degrades to 0 and
	 * plays no role in the veto or yield gate (which are keyed on
	 * per-10k-calls and per-wall-hour). */
	if (getrusage(RUSAGE_CHILDREN, &ru) == 0) {
		s.cpu_ns = (uint64_t)ru.ru_utime.tv_sec * 1000000000ULL
			+ (uint64_t)ru.ru_utime.tv_usec * 1000ULL
			+ (uint64_t)ru.ru_stime.tv_sec * 1000000000ULL
			+ (uint64_t)ru.ru_stime.tv_usec * 1000ULL;
	}

	sat_ring[sat_ring_head] = s;
	sat_ring_head = (sat_ring_head + 1) & (SAT_RING_SIZE - 1);
	if (sat_ring_count < SAT_RING_SIZE)
		sat_ring_count++;

	st.hysteresis_k = SAT_HYSTERESIS_K;
	st.floor_edges_per_10k_calls = SAT_FLOOR_EDGES_PER_10K_CALLS;
	st.floor_edges_per_wall_hour = SAT_FLOOR_EDGES_PER_WALL_HOUR;
	st.floor_finding_events_per_wall_hour = SAT_FINDING_VETO_MIN_PER_WALL_HOUR;

	sh = sat_find_horizon(s.t_ns, SAT_SHORT_HORIZON_NS);
	lg = sat_find_horizon(s.t_ns, SAT_LONG_HORIZON_NS);

	if (sh != NULL)
		sat_compute_yield(&st.short_win, &s, sh);
	if (lg != NULL)
		sat_compute_yield(&st.long_win, &s, lg);

	if (st.short_win.window_ns > 0)
		st.short_call_rate = (double)st.short_win.calls_delta * 1e9
			/ (double)st.short_win.window_ns;
	if (st.long_win.window_ns > 0)
		st.long_call_rate = (double)st.long_win.calls_delta * 1e9
			/ (double)st.long_win.window_ns;

	st.health_stall_count = stall_count;
	if (sh != NULL) {
		st.health_trace_trunc_delta_short =
			sat_sub_ul(s.trace_truncated, sh->trace_truncated);
		st.health_finding_events_delta_short =
			sat_sub_ul(s.finding_events, sh->finding_events);
		if (st.short_win.window_ns > 0)
			st.health_finding_events_per_wall_hour =
				(double)st.health_finding_events_delta_short
				* 3.6e12 / (double)st.short_win.window_ns;
	}

	/* Health veto in priority order: a wedge / active finding / trunc-
	 * loss burst / throughput collapse means the low yield we're seeing
	 * is a supply-side failure, not economic saturation, and we must
	 * not conclude saturated.  rc5 tail is the archetypal case:
	 * throughput dropped 841 -> 562/sec alongside D-state wedges.
	 *
	 * The finding-pending gate is second in priority (after in-flight
	 * D-state wedges): if the short window shows finding_events
	 * (post_handler_corrupt_ptr + watchdog_fd_evict) rising at a
	 * per-wall-hour rate at or above SAT_FINDING_VETO_MIN_PER_WALL_HOUR,
	 * the fuzzer is actively churning through the corruption-and-
	 * recycle loop and the low yield is not economic saturation.
	 * run2's 1,541-watchdog-kill tail is the archetypal case: the
	 * point-in-time stall_count veto returned to 0 while findings
	 * were still landing, so the shadow score would otherwise flip
	 * saturated on active corruption.
	 *
	 * The trace-truncation gate is RATE-based rather than
	 * any-rise-based: kcov truncation grows steadily on any long run
	 * (~15/window at rc5's pace), so vetoing on any rise would mask
	 * the very saturation we're trying to see.  Only veto when the
	 * short-window trunc rate outstrips the long-window baseline by
	 * SAT_TRUNC_VETO_RATIO -- a genuine burst that indicates active
	 * instrumentation loss, not steady baseline growth. */
	if (st.health_stall_count > 0) {
		st.veto = SAT_VETO_STALLED_CHILDREN;
	} else if (sh != NULL
		   && st.health_finding_events_per_wall_hour
		      >= (double)SAT_FINDING_VETO_MIN_PER_WALL_HOUR) {
		st.veto = SAT_VETO_FINDING_PENDING;
	} else if (st.short_win.window_ns > 0 && st.long_win.window_ns > 0
		   && lg != NULL) {
		double long_trunc_delta = (double)sat_sub_ul(
			s.trace_truncated, lg->trace_truncated);
		double short_trunc_rate = (double)st.health_trace_trunc_delta_short
			/ (double)st.short_win.window_ns;
		double long_trunc_rate = long_trunc_delta
			/ (double)st.long_win.window_ns;
		if (long_trunc_rate > 0.0
		    && short_trunc_rate * (double)SAT_TRUNC_VETO_RATIO_DEN
		       > long_trunc_rate * (double)SAT_TRUNC_VETO_RATIO_NUM) {
			st.veto = SAT_VETO_TRACE_TRUNC_RISING;
		}
	}
	if (st.veto == SAT_VETO_NONE
	    && st.long_win.valid && st.short_win.valid
	    && st.long_call_rate > 0.0
	    && st.short_call_rate * (double)SAT_THROUGHPUT_VETO_RATIO_DEN
	       < st.long_call_rate * (double)SAT_THROUGHPUT_VETO_RATIO_NUM) {
		st.veto = SAT_VETO_THROUGHPUT_DROP;
	}

	/* Yield gate: both horizons must be below floor.  A horizon is
	 * "below" when EITHER normaliser trips -- work-normalised
	 * (e_per_10k_calls) or wall-normalised (e_per_wall_hour).  The
	 * two normalisers correlate at steady throughput but discriminate
	 * different failure modes: e_per_10kc catches "marginal work
	 * yields nothing new" (economic saturation), e_per_wallh catches
	 * "clock time yielded nothing new" (which can be either
	 * saturation OR starvation -- the health veto below distinguishes
	 * them by watching short vs long call-rate). */
	short_below = st.short_win.valid
		&& (st.short_win.edges_per_10k_calls
			< (double)st.floor_edges_per_10k_calls
		    || st.short_win.edges_per_wall_hour
			< (double)st.floor_edges_per_wall_hour);
	long_below = st.long_win.valid
		&& (st.long_win.edges_per_10k_calls
			< (double)st.floor_edges_per_10k_calls
		    || st.long_win.edges_per_wall_hour
			< (double)st.floor_edges_per_wall_hour);

	if (short_below && long_below && st.veto == SAT_VETO_NONE) {
		if (sat_consec_below < UINT_MAX)
			sat_consec_below++;
	} else {
		sat_consec_below = 0;
	}
	st.consec_below = sat_consec_below;
	st.soft_saturated = (sat_consec_below >= SAT_HYSTERESIS_K);

	sat_last_state = st;
}

/*
 * One-line out.log summary.  Emitted every stats window once at least
 * the short horizon has enough history to trust -- healthy runs whose
 * long horizon is still filling see just the short-window numbers, so
 * the operator has something to eyeball from the first 10 minutes
 * onward.  Suppress entirely until any horizon is valid, so the first
 * few windows of a fresh run don't add noise.
 */
void stats_shadow_sat_emit_out_log(void)
{
	const struct sat_state *st = &sat_last_state;

	if (!st->short_win.valid && !st->long_win.valid)
		return;

	output(0,
		"SHADOW_SAT: soft_saturated=%s consec=%u/%u veto=%s "
		"short[win=%.1fs edges=%lu calls=%lu e_per_10kc=%.2f e_per_wallh=%.1f e_per_cpuh=%.1f] "
		"long[win=%.1fs edges=%lu calls=%lu e_per_10kc=%.2f e_per_wallh=%.1f e_per_cpuh=%.1f] "
		"floor[e_per_10kc=%u e_per_wallh=%u find_per_wallh=%u] "
		"health[stall_count=%lu trace_trunc_delta=%lu find_delta=%lu find_per_wallh=%.1f tput_short=%.0f/s tput_long=%.0f/s]\n",
		st->soft_saturated ? "true" : "false",
		st->consec_below, st->hysteresis_k,
		sat_veto_name(st->veto),
		(double)st->short_win.window_ns / 1e9,
		st->short_win.edges_delta, st->short_win.calls_delta,
		st->short_win.edges_per_10k_calls,
		st->short_win.edges_per_wall_hour,
		st->short_win.edges_per_cpu_hour,
		(double)st->long_win.window_ns / 1e9,
		st->long_win.edges_delta, st->long_win.calls_delta,
		st->long_win.edges_per_10k_calls,
		st->long_win.edges_per_wall_hour,
		st->long_win.edges_per_cpu_hour,
		st->floor_edges_per_10k_calls,
		st->floor_edges_per_wall_hour,
		st->floor_finding_events_per_wall_hour,
		st->health_stall_count,
		st->health_trace_trunc_delta_short,
		st->health_finding_events_delta_short,
		st->health_finding_events_per_wall_hour,
		st->short_call_rate, st->long_call_rate);
}

/*
 * Bound on raw per-window blocks emitted per JSONL record.  60 samples
 * at a ~5-15s cadence covers 5-15 minutes -- enough for a downstream
 * blocked-bootstrap over rotation windows to estimate the yield's
 * variance without needing the whole ring dumped every line.
 */
#define SAT_RAW_EMIT_SAMPLES 60

void stats_ts_emit_shadow_sat(FILE *fp)
{
	const struct sat_state *st = &sat_last_state;
	unsigned int emit_n;
	int off;
	bool first = true;

	fprintf(fp,
		",\"soft_sat\":{"
		"\"active\":%s,\"consec\":%u,\"hysteresis_k\":%u,\"veto\":\"%s\","
		"\"short\":{\"window_s\":%.3f,\"edges\":%lu,\"calls\":%lu,\"cpu_s\":%.3f,"
			   "\"e_per_10kc\":%.4f,\"e_per_wall_hour\":%.3f,\"e_per_cpu_hour\":%.3f,"
			   "\"valid\":%s},"
		"\"long\":{\"window_s\":%.3f,\"edges\":%lu,\"calls\":%lu,\"cpu_s\":%.3f,"
			  "\"e_per_10kc\":%.4f,\"e_per_wall_hour\":%.3f,\"e_per_cpu_hour\":%.3f,"
			  "\"valid\":%s},"
		"\"floor\":{\"e_per_10kc\":%u,\"e_per_wall_hour\":%u,"
			  "\"finding_events_per_wall_hour\":%u},"
		"\"health\":{\"stall_count\":%lu,\"trace_trunc_delta_short\":%lu,"
			    "\"finding_events_delta_short\":%lu,"
			    "\"finding_events_per_wall_hour\":%.3f,"
			    "\"short_call_rate\":%.3f,\"long_call_rate\":%.3f}",
		st->soft_saturated ? "true" : "false",
		st->consec_below, st->hysteresis_k,
		sat_veto_name(st->veto),
		(double)st->short_win.window_ns / 1e9,
		st->short_win.edges_delta, st->short_win.calls_delta,
		(double)st->short_win.cpu_ns_delta / 1e9,
		st->short_win.edges_per_10k_calls,
		st->short_win.edges_per_wall_hour,
		st->short_win.edges_per_cpu_hour,
		st->short_win.valid ? "true" : "false",
		(double)st->long_win.window_ns / 1e9,
		st->long_win.edges_delta, st->long_win.calls_delta,
		(double)st->long_win.cpu_ns_delta / 1e9,
		st->long_win.edges_per_10k_calls,
		st->long_win.edges_per_wall_hour,
		st->long_win.edges_per_cpu_hour,
		st->long_win.valid ? "true" : "false",
		st->floor_edges_per_10k_calls,
		st->floor_edges_per_wall_hour,
		st->floor_finding_events_per_wall_hour,
		st->health_stall_count,
		st->health_trace_trunc_delta_short,
		st->health_finding_events_delta_short,
		st->health_finding_events_per_wall_hour,
		st->short_call_rate, st->long_call_rate);

	/* Raw per-window blocks so an offline estimator (blocked
	 * bootstrap / negative-binomial) can be swapped in without
	 * another run: emit the last SAT_RAW_EMIT_SAMPLES per-interval
	 * deltas ({dt_ns, de, dc, dcpu_ns, dtr}) in chronological order.
	 * Cap n at ring_count-1 so we always have a prev slot. */
	emit_n = (sat_ring_count > 1) ? (sat_ring_count - 1) : 0;
	if (emit_n > SAT_RAW_EMIT_SAMPLES)
		emit_n = SAT_RAW_EMIT_SAMPLES;

	fputs(",\"raw_windows\":[", fp);
	for (off = (int)emit_n; off >= 1; off--) {
		unsigned int idx = (sat_ring_head + SAT_RING_SIZE - off)
			& (SAT_RING_SIZE - 1);
		unsigned int previdx = (idx + SAT_RING_SIZE - 1)
			& (SAT_RING_SIZE - 1);
		const struct sat_sample *cur = &sat_ring[idx];
		const struct sat_sample *prev = &sat_ring[previdx];

		fprintf(fp,
			"%s{\"dt_ns\":%llu,\"de\":%lu,\"dc\":%lu,"
			"\"dcpu_ns\":%llu,\"dtr\":%lu,\"dfe\":%lu}",
			first ? "" : ",",
			(unsigned long long)((cur->t_ns > prev->t_ns) ?
				cur->t_ns - prev->t_ns : 0),
			sat_sub_ul(cur->edges, prev->edges),
			sat_sub_ul(cur->calls, prev->calls),
			(unsigned long long)((cur->cpu_ns > prev->cpu_ns) ?
				cur->cpu_ns - prev->cpu_ns : 0),
			sat_sub_ul(cur->trace_truncated, prev->trace_truncated),
			sat_sub_ul(cur->finding_events, prev->finding_events));
		first = false;
	}
	fputs("]}", fp);
}
