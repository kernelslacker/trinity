/*
 * Run-identity provenance + own-start deltas.
 *
 * Carved verbatim out of stats.c.  Contains stats_runid_snapshot_
 * start (captures the post-warm-load / pre-fuzz-loop baseline that
 * anchors every own-start delta at shutdown), stats_runid_render
 * (the end-of-run provenance / carrier / delta block plus knob
 * manifest), the struct run_start_baseline that carries the
 * snapshot, and the file-static run_start instance itself.  The
 * assorted runid_* helpers -- the CLOCK_MONOTONIC seconds reader,
 * the corpus-entry counter, the kallsyms + boot_id readers, the
 * warm/cold classifier, the twelve knob-name accessors, the
 * knob_append writer, and the knob_manifest_render walker -- all
 * live only inside this cluster and stay file-static.
 *
 * The two exported entry points (stats_runid_snapshot_start and
 * stats_runid_render) are already declared in include/stats.h so
 * nothing new is added to stats-internal.h.
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

/* --------------------------------------------------------------------
 * Run-identity block: provenance + post-warm-load start baseline +
 * shutdown deltas.  Closes the stale-cache-key trap from the 2026-06-14
 * triage where comparing two final cache snapshots made a fully
 * productive cold run look like zero growth (the warm cache had been
 * silently reused under a stale key).  The own-start delta is immune
 * to that: it is the work this process actually did, regardless of
 * what the carrier looked like before the run started.
 * -------------------------------------------------------------------- */

struct run_start_baseline {
	bool captured;
	time_t monotonic_at_start;
	unsigned long edges_found;
	unsigned long distinct_edges;
	unsigned long edges_warm_loaded;
	unsigned long distinct_edges_warm_loaded;
	unsigned long corpus_entries;
	/* Snapshot of the persisted cmp-hints pool taken AFTER the loader
	 * has populated cmp_hints_shm but BEFORE the fuzz loop starts.
	 * The carrier warm/cold classification has to read this -- not the
	 * runtime cmp_records_collected counter, which is zero at snapshot
	 * time and would label a warm-loaded run "cold". */
	unsigned long cmp_hints_loaded_values;
	unsigned long cmp_hints_loaded_syscalls;
};

static struct run_start_baseline run_start;

/* CLOCK_MONOTONIC second counter -- duplicate of child-canary.c's
 * file-static helper (kept private to avoid exposing it through a
 * widely-included header for two callers).  Wall-clock-skew-immune,
 * so a negative duration cannot trip a spurious panic on an NTP
 * step. */
static time_t runid_monotonic_seconds(void)
{
	struct timespec ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

/* Sum every per-syscall ring's entry count to get the parent's view
 * of total corpus size.  Reads each ring's count with __ATOMIC_RELAXED
 * since the snapshot is observability-only -- a torn read against a
 * concurrent writer at most miscounts by one entry per syscall, well
 * inside the noise floor of a "did this run grow the corpus" check.
 *
 * Each per-ring count is clamped to CORPUS_RING_SIZE before contributing
 * to the sum, matching the picker (minicorpus.c) and the snapshot
 * walker.  Both save paths (in-run minicorpus_save_with_reason and the
 * on-disk loader) cap count at CORPUS_RING_SIZE before publishing, so
 * count > CORPUS_RING_SIZE is structurally impossible through the
 * documented writer flow -- a value above the cap is a zero-false-
 * positive signal that the ring's count word has been scribbled by a
 * sibling wild write.  Without the clamp a single garbage count word
 * inflated the headline corpus_entries figure into the millions and
 * masked the underlying corruption.  On detection, bump the per-event
 * counter and (once per run) emit a first-witness line naming the ring
 * nr and the unclamped count value so the next triage pass can
 * attribute the scribbler. */
static unsigned long runid_corpus_entries_total(void)
{
	static bool overcap_warned;
	unsigned long total = 0;
	unsigned int i;

	if (minicorpus_shm == NULL)
		return 0;

	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		unsigned int count = __atomic_load_n(
			&minicorpus_shm->rings[i].count, __ATOMIC_RELAXED);

		if (unlikely(count > CORPUS_RING_SIZE)) {
			__atomic_add_fetch(
				&shm->stats.minicorpus.count_overcap_caught,
				1UL, __ATOMIC_RELAXED);
			if (!overcap_warned) {
				overcap_warned = true;
				output(0,
				       "[main] WARNING corpus_count_overcap "
				       "nr=%u count=%u clamped_to=%u "
				       "(first witness)\n",
				       i, count, CORPUS_RING_SIZE);
			}
			count = CORPUS_RING_SIZE;
		}
		total += count;
	}
	return total;
}

/* Render the 32-byte kallsyms fingerprint as a short hex prefix
 * suitable for an at-a-glance identity line; truncated to 16 hex
 * chars (8 bytes of entropy) is far past what a human eyeballs but
 * short enough to fit on one line beside the other identity fields.
 * Returns true iff the fingerprint was available -- a v5+ kcov path
 * that cannot resolve _text leaves it unavailable on this run. */
static bool runid_kallsyms_hex(char *out, size_t outlen)
{
	uint8_t fp[32];
	size_t i, want;

	if (outlen < 17)
		return false;
	if (!kcov_get_kernel_fp(fp))
		return false;
	want = 8;
	for (i = 0; i < want; i++)
		snprintf(out + (i * 2), outlen - (i * 2), "%02x", fp[i]);
	out[want * 2] = '\0';
	return true;
}

/* Read /proc/sys/kernel/random/boot_id into a NUL-terminated string
 * (the on-disk value is a 36-char UUID followed by a newline).
 * Returns true on success.  The boot_id is no longer used as a
 * cache-key guard (KCOV bitmap moved to canonicalised PCs at file
 * version 5), but it remains the single most useful "did the kernel
 * reboot between these two runs" anchor for the run-identity block. */
static bool runid_read_boot_id(char *out, size_t outlen)
{
	int fd;
	ssize_t n;

	if (outlen < 37)
		return false;

	fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
	if (fd < 0)
		return false;
	n = read(fd, out, outlen - 1);
	close(fd);
	if (n <= 0)
		return false;
	out[n] = '\0';
	/* Strip the trailing newline so the value renders inline. */
	if (n > 0 && out[n - 1] == '\n')
		out[n - 1] = '\0';
	return true;
}

void __cold stats_runid_snapshot_start(void)
{
	if (run_start.captured)
		return;

	run_start.monotonic_at_start = runid_monotonic_seconds();
	if (kcov_shm != NULL) {
		run_start.edges_found = __atomic_load_n(
			&kcov_shm->edges_found, __ATOMIC_RELAXED);
		run_start.distinct_edges = __atomic_load_n(
			&kcov_shm->distinct_edges, __ATOMIC_RELAXED);
		run_start.edges_warm_loaded = __atomic_load_n(
			&kcov_shm->edges_warm_loaded, __ATOMIC_RELAXED);
		run_start.distinct_edges_warm_loaded = __atomic_load_n(
			&kcov_shm->distinct_edges_warm_loaded,
			__ATOMIC_RELAXED);
	}
	run_start.corpus_entries = runid_corpus_entries_total();

	/* Sum the persisted cmp-hints pool as it stands right after the
	 * loader has finished -- this is the authoritative "did a prior
	 * run hand us a warm cache" answer for the cmp_hints carrier.
	 * Per-arch slots count individually, matching the JSON / text
	 * pool histograms emitted elsewhere in this file. */
	run_start.cmp_hints_loaded_values = 0;
	run_start.cmp_hints_loaded_syscalls = 0;
	if (cmp_hints_shm != NULL) {
		unsigned int i, a;

		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			for (a = 0; a < 2; a++) {
				unsigned int n = cmp_hints_pool_safe_count(
					&cmp_hints_shm->pools[i][a]);

				if (n > 0) {
					run_start.cmp_hints_loaded_values += n;
					run_start.cmp_hints_loaded_syscalls++;
				}
			}
		}
	}

	run_start.captured = true;
}

static const char *runid_warm_state(bool gated_off, unsigned long start_value)
{
	if (gated_off)
		return "disabled";
	return start_value > 0 ? "warm" : "cold";
}

static const char *runid_transition_coverage_name(void)
{
	switch (kcov_transition_coverage_mode) {
	case KCOV_TRANSITION_COVERAGE_OFF:    return "off";
	case KCOV_TRANSITION_COVERAGE_SHADOW: return "shadow";
	}
	return "?";
}

static const char *runid_transition_reward_name(void)
{
	switch (kcov_transition_reward_mode) {
	case KCOV_TRANSITION_REWARD_OFF:         return "off";
	case KCOV_TRANSITION_REWARD_SHADOW_ONLY: return "shadow_only";
	case KCOV_TRANSITION_REWARD_COMBINED:    return "combined";
	}
	return "?";
}

/*
 * Append "<name>=<value>" to the manifest buffer, prefixed with a
 * separating space when the buffer is non-empty.  Returns the new
 * tail offset; on truncation the buffer stays NUL-terminated at its
 * prior contents and the same offset is returned so subsequent
 * appends become no-ops (the caller still sees off > 0 and prints
 * what fit, not "all defaults").
 */
static size_t runid_knob_append(char *buf, size_t buflen, size_t off,
				const char *name, const char *value)
{
	int n;

	if (off >= buflen)
		return off;
	n = snprintf(buf + off, buflen - off, "%s%s=%s",
		     off > 0 ? " " : "", name, value);
	if (n < 0 || (size_t)n >= buflen - off) {
		buf[off] = '\0';
		return off;
	}
	return off + (size_t)n;
}

static const char *runid_frontier_live_cooldown_mode_name(void)
{
	switch (frontier_live_cooldown_mode) {
	case FRONTIER_LIVE_COOLDOWN_MODE_OFF:         return "off";
	case FRONTIER_LIVE_COOLDOWN_MODE_SHADOW_ONLY: return "shadow-only";
	case FRONTIER_LIVE_COOLDOWN_MODE_COMBINED:    return "combined";
	}
	return "?";
}

static const char *runid_frontier_saturation_cooldown_mode_name(void)
{
	switch (frontier_saturation_cooldown_mode) {
	case FRONTIER_SATURATION_COOLDOWN_MODE_OFF:         return "off";
	case FRONTIER_SATURATION_COOLDOWN_MODE_SHADOW_ONLY: return "shadow-only";
	case FRONTIER_SATURATION_COOLDOWN_MODE_COMBINED:    return "combined";
	}
	return "?";
}

static const char *runid_frontier_barren_demote_mode_name(void)
{
	switch (frontier_barren_demote_mode) {
	case FRONTIER_BARREN_DEMOTE_MODE_OFF:         return "off";
	case FRONTIER_BARREN_DEMOTE_MODE_SHADOW_ONLY: return "shadow-only";
	case FRONTIER_BARREN_DEMOTE_MODE_COMBINED:    return "combined";
	}
	return "?";
}

static const char *runid_frontier_group_antilock_mode_name(void)
{
	switch (frontier_group_antilock_mode) {
	case FRONTIER_GROUP_ANTILOCK_MODE_OFF:         return "off";
	case FRONTIER_GROUP_ANTILOCK_MODE_SHADOW_ONLY: return "shadow-only";
	case FRONTIER_GROUP_ANTILOCK_MODE_COMBINED:    return "combined";
	}
	return "?";
}

static const char *runid_cost_pool_selector_mode_name(void)
{
	switch (cost_pool_selector_mode) {
	case COST_POOL_SELECTOR_MODE_OFF:         return "off";
	case COST_POOL_SELECTOR_MODE_SHADOW_ONLY: return "shadow-only";
	case COST_POOL_SELECTOR_MODE_COMBINED:    return "combined";
	}
	return "?";
}

static const char *runid_expensive_adaptive_mode_name(void)
{
	switch (expensive_adaptive_mode) {
	case EXPENSIVE_ADAPTIVE_MODE_OFF:         return "off";
	case EXPENSIVE_ADAPTIVE_MODE_SHADOW_ONLY: return "shadow-only";
	case EXPENSIVE_ADAPTIVE_MODE_COMBINED:    return "combined";
	}
	return "?";
}

static const char *runid_reach_band_mode_name(void)
{
	switch (__atomic_load_n(&reach_band_mode, __ATOMIC_RELAXED)) {
	case REACH_BAND_OFF:         return "off";
	case REACH_BAND_SHADOW_ONLY: return "shadow-only";
	case REACH_BAND_COMBINED:    return "combined";
	}
	return "?";
}

static const char *runid_arg_len_semantics_mode_name(void)
{
	switch (__atomic_load_n(&arg_len_semantics_mode, __ATOMIC_RELAXED)) {
	case ARG_LEN_SEMANTICS_OFF: return "off";
	case ARG_LEN_SEMANTICS_ON:  return "on";
	}
	return "?";
}

static const char *runid_childop_kcov_attr_mode_name(void)
{
	switch (childop_kcov_attr_mode) {
	case CHILDOP_KCOV_ATTR_OFF:  return "off";
	case CHILDOP_KCOV_ATTR_DUAL: return "dual";
	case CHILDOP_KCOV_ATTR_ON:   return "on";
	}
	return "?";
}

static const char *runid_childop_cmp_harvest_mode_name(void)
{
	switch (childop_cmp_harvest_mode) {
	case CHILDOP_CMP_HARVEST_OFF: return "off";
	case CHILDOP_CMP_HARVEST_ON:  return "on";
	}
	return "?";
}

static const char *runid_childop_cmp_consume_mode_name(void)
{
	switch (childop_cmp_consume_mode) {
	case CHILDOP_CMP_CONSUME_OFF: return "off";
	case CHILDOP_CMP_CONSUME_ON:  return "on";
	}
	return "?";
}

/*
 * Emit a single line listing every experimental knob whose current
 * value differs from its compile-time default.  Knobs at their
 * default value are intentionally omitted to keep the line scannable;
 * a run with nothing overridden prints "all defaults" so the line
 * still appears unconditionally and a downstream parser can rely on
 * its presence.  Default-OFF booleans render as "<name>=on" so the
 * value column is uniform with the enum knobs.
 *
 * Knobs whose default is not OFF (childop-kcov-attribution = dual,
 * kcov-transition-coverage = shadow, kcov-transition-reward =
 * combined, strategy = bandit-ucb1) compare against their actual
 * default, not zero, so flipping COMBINED back to shadow_only shows
 * up in the manifest rather than hiding behind an enum-zero check.
 */
static void runid_knob_manifest_render(void)
{
	char buf[1024];
	size_t off = 0;

	buf[0] = '\0';

	if (picker_mode_arg != PICKER_BANDIT_UCB1)
		off = runid_knob_append(buf, sizeof(buf), off,
					"strategy",
					picker_mode_name(picker_mode_arg));
	if (group_bias)
		off = runid_knob_append(buf, sizeof(buf), off,
					"group-bias", "on");
	if (cred_throttle)
		off = runid_knob_append(buf, sizeof(buf), off,
					"cred-throttle", "on");
	if (frontier_live_cooldown_mode != FRONTIER_LIVE_COOLDOWN_MODE_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"frontier-live-cooldown-mode",
					runid_frontier_live_cooldown_mode_name());
	if (frontier_saturation_cooldown_mode !=
	    FRONTIER_SATURATION_COOLDOWN_MODE_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"frontier-saturation-cooldown",
					runid_frontier_saturation_cooldown_mode_name());
	if (frontier_barren_demote_mode !=
	    FRONTIER_BARREN_DEMOTE_MODE_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"frontier-barren-demote",
					runid_frontier_barren_demote_mode_name());
	if (frontier_group_antilock_mode !=
	    FRONTIER_GROUP_ANTILOCK_MODE_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"frontier-group-antilock",
					runid_frontier_group_antilock_mode_name());
	if (cost_pool_selector_mode != COST_POOL_SELECTOR_MODE_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"cost-pool-selector",
					runid_cost_pool_selector_mode_name());
	if (__atomic_load_n(&reach_band_mode, __ATOMIC_RELAXED) !=
	    REACH_BAND_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"reach-band",
					runid_reach_band_mode_name());
	if (__atomic_load_n(&arg_len_semantics_mode, __ATOMIC_RELAXED) !=
	    ARG_LEN_SEMANTICS_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"arg-len-semantics",
					runid_arg_len_semantics_mode_name());
	if (expensive_adaptive_mode != EXPENSIVE_ADAPTIVE_MODE_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"expensive-adaptive",
					runid_expensive_adaptive_mode_name());
	if (redqueen_pending_pick_mode_arg != REDQUEEN_PENDING_PICK_RANDOM)
		off = runid_knob_append(buf, sizeof(buf), off,
					"redqueen-pending-pick",
					redqueen_pending_pick_name(redqueen_pending_pick_mode_arg));
	if (childop_kcov_attr_mode != CHILDOP_KCOV_ATTR_DUAL)
		off = runid_knob_append(buf, sizeof(buf), off,
					"childop-kcov-attribution",
					runid_childop_kcov_attr_mode_name());
	if (childop_cmp_harvest_mode != CHILDOP_CMP_HARVEST_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"childop-cmp-harvest",
					runid_childop_cmp_harvest_mode_name());
	if (childop_cmp_consume_mode != CHILDOP_CMP_CONSUME_OFF)
		off = runid_knob_append(buf, sizeof(buf), off,
					"childop-cmp-consume",
					runid_childop_cmp_consume_mode_name());
	if (kcov_transition_coverage_mode != KCOV_TRANSITION_COVERAGE_SHADOW)
		off = runid_knob_append(buf, sizeof(buf), off,
					"kcov-transition-coverage",
					runid_transition_coverage_name());
	if (kcov_transition_reward_mode != KCOV_TRANSITION_REWARD_COMBINED)
		off = runid_knob_append(buf, sizeof(buf), off,
					"kcov-transition-reward",
					runid_transition_reward_name());
	if (corpus_save_errno_grad_live)
		off = runid_knob_append(buf, sizeof(buf), off,
					"corpus-save-errno-grad-live", "on");
	if (fork_pressure_drain)
		off = runid_knob_append(buf, sizeof(buf), off,
					"fork-pressure-drain", "on");

	output(0, "run-id knobs: %s\n", off > 0 ? buf : "all defaults");
}

void __cold stats_runid_render(void)
{
	unsigned long end_edges = 0;
	unsigned long end_distinct = 0;
	unsigned long end_corpus = 0;
	unsigned long edges_delta = 0;
	unsigned long distinct_delta = 0;
	unsigned long corpus_delta = 0;
	time_t now = runid_monotonic_seconds();
	long elapsed = 0;
	struct utsname uts;
	bool have_uname;
	char kallsyms_hex[17] = "(unavailable)";
	char boot_id[64] = "(unavailable)";
	const char *kcov_state;
	const char *corpus_state;
	const char *cmp_state;

	have_uname = (uname(&uts) == 0);
	(void)runid_kallsyms_hex(kallsyms_hex, sizeof(kallsyms_hex));
	(void)runid_read_boot_id(boot_id, sizeof(boot_id));

	if (kcov_shm != NULL) {
		end_edges = __atomic_load_n(&kcov_shm->edges_found,
					    __ATOMIC_RELAXED);
		end_distinct = __atomic_load_n(&kcov_shm->distinct_edges,
					       __ATOMIC_RELAXED);
	}
	end_corpus = runid_corpus_entries_total();

	output(0, "\n");
	output(0, "===== run identity =====\n");

	/* Identity / provenance triple: the three values that together
	 * decide whether a persisted warm cache will load on the next run.
	 * Cache-key drift across runs is the failure mode the 2026-06-14
	 * triage chased; printing the triple at shutdown makes the drift
	 * visible without needing the loader's verbose path. */
	output(0, "run-id provenance: build=%s kernel=%s%s%s kallsyms=%s "
		  "boot_id=%s asan=%s\n",
	       GIT_HASH,
	       have_uname ? uts.release : "(uname-failed)",
	       have_uname ? " " : "",
	       have_uname ? uts.version : "",
	       kallsyms_hex,
	       boot_id,
#ifdef __SANITIZE_ADDRESS__
	       "on"
#else
	       "off"
#endif
	       );

	/* Cohort + the parent-side knobs that change selection at the
	 * coarse level.  Per-child A/B stamps (redqueen_enabled,
	 * cmp_hint_inject_arm_b, ...) are not parent-visible globals and
	 * are intentionally omitted -- they belong in the per-child
	 * attribution dumps, not this identity line. */
	output(0, "run-id cohort: children=%u alt_op_children=%u "
		  "canary_slots=%u canary_window_iters=%u canary_queue=%s "
		  "transition_coverage=%s transition_reward=%s\n",
	       max_children, alt_op_children,
	       canary_slots, canary_window_iters,
	       canary_queue_disabled ? "off" : "on",
	       runid_transition_coverage_name(),
	       runid_transition_reward_name());

	/* Cold/warm classification of each cross-run carrier.  "disabled"
	 * means the --no-*-warm-start opt-out is in effect (no save and no
	 * load this run); "warm" means the carrier had a non-zero starting
	 * baseline at snapshot time (a prior run's state survived into
	 * this one); "cold" means the carrier started empty (genuine
	 * first-run-on-this-cache-key). */
	kcov_state = runid_warm_state(no_kcov_warm_start,
				      run_start.edges_warm_loaded);
	corpus_state = runid_warm_state(no_warm_start,
					run_start.corpus_entries);
	/* Classify cmp_hints from the post-load pool snapshot, not from
	 * the runtime cmp_records_collected counter -- the latter is zero
	 * at start-snapshot time and would mislabel a warm-loaded run
	 * (e.g. 4636 entries / 290 syscalls reloaded by the persistence
	 * layer) as "cold". */
	cmp_state = runid_warm_state(no_cmp_hints_warm_start,
				     run_start.cmp_hints_loaded_values);
	output(0, "run-id carriers: kcov=%s minicorpus=%s cmp_hints=%s "
		  "kcov_warm_loaded_edges=%lu kcov_warm_loaded_distinct=%lu "
		  "cmp_hints_loaded_values=%lu cmp_hints_loaded_syscalls=%lu\n",
	       kcov_state, corpus_state, cmp_state,
	       run_start.edges_warm_loaded,
	       run_start.distinct_edges_warm_loaded,
	       run_start.cmp_hints_loaded_values,
	       run_start.cmp_hints_loaded_syscalls);

	if (!run_start.captured) {
		/* Reached the shutdown render without ever taking the
		 * start snapshot (early-exit dump path or a regression
		 * in the main_loop hook).  Print the end values alone so
		 * the operator still has the identity block, but suppress
		 * the deltas rather than emit a misleading "start=0
		 * end=N delta=N" line that would re-create the exact
		 * 2026-06-14 trap (mistaking a known-prior carrier for
		 * coverage this run discovered). */
		output(0, "run-id baseline: NOT CAPTURED -- deltas suppressed; "
			  "end edges_found=%lu distinct_edges=%lu "
			  "corpus_entries=%lu\n",
		       end_edges, end_distinct, end_corpus);
		runid_knob_manifest_render();
		output(0, "===== end run identity =====\n");
		return;
	}

	if (end_edges >= run_start.edges_found)
		edges_delta = end_edges - run_start.edges_found;
	if (end_distinct >= run_start.distinct_edges)
		distinct_delta = end_distinct - run_start.distinct_edges;
	if (end_corpus >= run_start.corpus_entries)
		corpus_delta = end_corpus - run_start.corpus_entries;
	if (now >= run_start.monotonic_at_start)
		elapsed = (long)(now - run_start.monotonic_at_start);

	output(0, "run-id baseline: start edges_found=%lu distinct_edges=%lu "
		  "corpus_entries=%lu\n",
	       run_start.edges_found, run_start.distinct_edges,
	       run_start.corpus_entries);
	output(0, "run-id shutdown: end   edges_found=%lu distinct_edges=%lu "
		  "corpus_entries=%lu elapsed=%lds\n",
	       end_edges, end_distinct, end_corpus, elapsed);
	output(0, "run-id own-start deltas: edges_found=+%lu "
		  "distinct_edges=+%lu corpus_entries=+%lu\n",
	       edges_delta, distinct_delta, corpus_delta);

	runid_knob_manifest_render();

	output(0, "===== end run identity =====\n");
}
