#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <stdio.h>
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
#include "shadow_promote.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "strategy.h"		/* frontier_spare_lane_decide, enum frontier_spare_reason */
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "utils-proc.h"
#include "version.h"

#include "dump-internal.h"

static void dump_stats_render_kcov_transition_edges(void)
{
		unsigned long kc_tedges = __atomic_load_n(
			&kcov_shm->transitions.transition_edges_found,
			__ATOMIC_RELAXED);
		unsigned long kc_tdistinct = __atomic_load_n(
			&kcov_shm->transitions.transition_distinct_edges,
			__ATOMIC_RELAXED);

		if (kc_tedges > 0)
			stat_row("kcov_coverage",
				 "transition_edges_found",
				 kc_tedges);
		if (kc_tdistinct > 0)
			stat_row("kcov_coverage",
				 "transition_distinct_edges",
				 kc_tdistinct);
}

void dump_stats_render_kcov_warm_known_hits(void)
{
		/* total_warm_known_hits migrated off the kcov_shm
		 * atomic onto the per-child staged counter drained
		 * into parent_stats; the shm field is write-dead but
		 * kept for shared-mapping ABI stability.  See
		 * stats_ring.h. */
		unsigned long warm_known = parent_stats.total_warm_known_hits;
		if (warm_known > 0)
			stat_row("kcov_coverage", "warm_known_hits", warm_known);
}

void dump_stats_render_kcov_exit_edge_delta(void)
{
		unsigned long rc_inserts = __atomic_load_n(&kcov_shm->cmp_recent.cmp_recent_inserts, __ATOMIC_RELAXED);
		unsigned long rc_evicts = __atomic_load_n(&kcov_shm->cmp_recent.cmp_recent_evicts, __ATOMIC_RELAXED);
		unsigned long rc_would_pick = __atomic_load_n(&kcov_shm->cmp_recent.cmp_recent_would_pick, __ATOMIC_RELAXED);
		unsigned long rc_would_miss = __atomic_load_n(&kcov_shm->cmp_recent.cmp_recent_would_miss, __ATOMIC_RELAXED);
		unsigned long rc_live_picks = __atomic_load_n(&kcov_shm->cmp_recent.cmp_recent_live_picks, __ATOMIC_RELAXED);
		unsigned long st_ips = __atomic_load_n(&kcov_shm->cmp_shared_tier.cmp_shared_tier_ips, __ATOMIC_RELAXED);
		unsigned long st_entries = __atomic_load_n(&kcov_shm->cmp_shared_tier.cmp_shared_tier_entries, __ATOMIC_RELAXED);
		unsigned long st_excluded = __atomic_load_n(&kcov_shm->cmp_shared_tier.cmp_shared_tier_entry_path_excluded_ips, __ATOMIC_RELAXED);
		unsigned long st_eligible = __atomic_load_n(&kcov_shm->cmp_shared_tier.cmp_shared_tier_shadow_warmstart_eligible, __ATOMIC_RELAXED);
		unsigned long st_would_confirm = __atomic_load_n(&kcov_shm->cmp_shared_tier_shadow.cmp_shared_tier_shadow_would_confirm, __ATOMIC_RELAXED);
		unsigned long st_supplied = __atomic_load_n(&kcov_shm->cmp_shared_tier.cmp_shared_tier_shadow_dedup_supplied, __ATOMIC_RELAXED);

		if (rc_inserts > 0)
			stat_row("kcov_coverage", "cmp_recent_inserts", rc_inserts);
		if (rc_evicts > 0)
			stat_row("kcov_coverage", "cmp_recent_evicts", rc_evicts);
		if (rc_would_pick > 0)
			stat_row("kcov_coverage", "cmp_recent_would_pick", rc_would_pick);
		if (rc_would_miss > 0)
			stat_row("kcov_coverage", "cmp_recent_would_miss", rc_would_miss);
		if (rc_live_picks > 0)
			stat_row("kcov_coverage", "cmp_recent_live_picks", rc_live_picks);
		if (st_ips > 0)
			stat_row("kcov_coverage", "cmp_shared_tier_ips", st_ips);
		if (st_entries > 0)
			stat_row("kcov_coverage", "cmp_shared_tier_entries", st_entries);
		if (st_excluded > 0)
			stat_row("kcov_coverage", "cmp_shared_tier_entry_path_excluded_ips", st_excluded);
		if (st_eligible > 0)
			stat_row("kcov_coverage", "cmp_shared_tier_shadow_warmstart_eligible", st_eligible);
		if (st_would_confirm > 0)
			stat_row("kcov_coverage", "cmp_shared_tier_shadow_would_confirm", st_would_confirm);
		if (st_supplied > 0)
			stat_row("kcov_coverage", "cmp_shared_tier_shadow_dedup_supplied", st_supplied);
}

void dump_stats_render_kcov_exit_edge_totals(void)
{
		unsigned long plateau_entered_v = __atomic_load_n(&shm->stats.plateau.entered, __ATOMIC_RELAXED);
		unsigned long plateau_exited_v = __atomic_load_n(&shm->stats.plateau.exited, __ATOMIC_RELAXED);
		unsigned long bucket_canary_checks_v = __atomic_load_n(&shm->stats.plateau.bucket_canary_checks, __ATOMIC_RELAXED);
		unsigned long bucket_canary_deficits_v = __atomic_load_n(&shm->stats.plateau.bucket_canary_deficits, __ATOMIC_RELAXED);

		if (plateau_entered_v > 0)
			stat_row("kcov_coverage", "plateau_entered", plateau_entered_v);
		if (plateau_exited_v > 0)
			stat_row("kcov_coverage", "plateau_exited", plateau_exited_v);
		if (bucket_canary_checks_v > 0)
			stat_row("kcov_coverage", "bucket_canary_checks", bucket_canary_checks_v);
		if (bucket_canary_deficits_v > 0)
			stat_row("kcov_coverage", "bucket_canary_deficits", bucket_canary_deficits_v);
}

void dump_stats_render_kcov_base_stats(void)
{
	unsigned long kc_edges       = __atomic_load_n(&kcov_shm->coverage.edges_found,            __ATOMIC_RELAXED);
	/* See per-child kcov stats migration in stats_ring.h:
	 * total_pcs / total_calls / remote_calls read from
	 * parent_stats.  kcov_shm->coverage.total_calls is retained solely
	 * as the stamp source for last_edge_at[] / last_efault_at[];
	 * the kcov_shm total_pcs and remote_calls slots have no
	 * stamp-role consumer and are not bumped. */
	unsigned long kc_pcs         = parent_stats.total_pcs;
	unsigned long kc_calls       = parent_stats.total_calls;
	unsigned long kc_remote      = parent_stats.remote_calls;
	unsigned long kc_cmp_records = __atomic_load_n(&kcov_shm->cmp_records.cmp_records_collected,  __ATOMIC_RELAXED);
	unsigned long kc_cmp_trunc   = __atomic_load_n(&kcov_shm->cmp_records.cmp_trace_truncated,    __ATOMIC_RELAXED);
	unsigned long kc_dedup_overflow    = __atomic_load_n(&kcov_shm->dedup.dedup_probe_overflow,   __ATOMIC_RELAXED);
	unsigned long kc_dedup_max_probe   = __atomic_load_n(&kcov_shm->dedup.dedup_max_probe_seen,   __ATOMIC_RELAXED);
	unsigned long kc_cmp_bloom_skipped = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_bloom_skipped, __ATOMIC_RELAXED);
	unsigned long kc_cmp_strip_skipped = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_strip_skipped, __ATOMIC_RELAXED);
	unsigned long kc_cmp_unique  = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_unique_inserts, __ATOMIC_RELAXED);
	unsigned long kc_cmp_save_reject_nonconst      = __atomic_load_n(&kcov_shm->hint_reject.cmp_hints_save_reject_nonconst,      __ATOMIC_RELAXED);
	unsigned long kc_cmp_save_reject_uninteresting = __atomic_load_n(&kcov_shm->hint_reject.cmp_hints_save_reject_uninteresting, __ATOMIC_RELAXED);
	unsigned long kc_cmp_save_reject_sentinel      = __atomic_load_n(&kcov_shm->hint_reject.cmp_hints_save_reject_sentinel,      __ATOMIC_RELAXED);
	unsigned long kc_cmp_save_reject_dup           = __atomic_load_n(&kcov_shm->hint_reject.cmp_hints_save_reject_dup,           __ATOMIC_RELAXED);
	unsigned long kc_cmp_save_reject_cap           = __atomic_load_n(&kcov_shm->hint_reject.cmp_hints_save_reject_cap,           __ATOMIC_RELAXED);

	stat_row("kcov_coverage", "unique_edges",          kc_edges);
	stat_row("kcov_coverage", "total_pcs",             kc_pcs);
	stat_row("kcov_coverage", "total_calls",           kc_calls);
	stat_row("kcov_coverage", "remote_calls",          kc_remote);
	stat_row("kcov_coverage", "cmp_records_collected", kc_cmp_records);

	/* Shadow transition-coverage globals.  See the
	 * kcov_transition_coverage_mode enum + KCOV_NUM_TRANSITIONS
	 * comments in include/kcov.h for the design; this block
	 * surfaces the two run-wide counters so PC vs transition
	 * yield can be compared side-by-side without parsing a
	 * separate log channel.  Both stay at zero when the mode is
	 * OFF, so the early-out below keeps the stats stream quiet
	 * for runs that opted out. */
	dump_stats_render_kcov_transition_edges();
	if (kc_cmp_trunc > 0)
		stat_row("kcov_coverage", "cmp_trace_truncated", kc_cmp_trunc);
	if (kc_dedup_overflow > 0)
		stat_row("kcov_coverage", "dedup_probe_overflow", kc_dedup_overflow);
	if (kc_dedup_max_probe > 0)
		stat_row("kcov_coverage", "dedup_max_probe_seen", kc_dedup_max_probe);
	if (kc_cmp_bloom_skipped > 0)
		stat_row("kcov_coverage", "cmp_hints_bloom_skipped", kc_cmp_bloom_skipped);
	if (kc_cmp_strip_skipped > 0)
		stat_row("kcov_coverage", "cmp_hints_strip_skipped", kc_cmp_strip_skipped);
	if (kc_cmp_unique > 0)
		stat_row("kcov_coverage", "cmp_hints_unique_inserts", kc_cmp_unique);
	if (kc_cmp_save_reject_nonconst > 0)
		stat_row("kcov_coverage", "cmp_hints_save_reject_nonconst", kc_cmp_save_reject_nonconst);
	if (kc_cmp_save_reject_uninteresting > 0)
		stat_row("kcov_coverage", "cmp_hints_save_reject_uninteresting", kc_cmp_save_reject_uninteresting);
	if (kc_cmp_save_reject_sentinel > 0)
		stat_row("kcov_coverage", "cmp_hints_save_reject_sentinel", kc_cmp_save_reject_sentinel);
	if (kc_cmp_save_reject_dup > 0)
		stat_row("kcov_coverage", "cmp_hints_save_reject_dup", kc_cmp_save_reject_dup);
	if (kc_cmp_save_reject_cap > 0)
		stat_row("kcov_coverage", "cmp_hints_save_reject_cap", kc_cmp_save_reject_cap);

	dump_stats_render_kcov_shadow_measurements();
}
