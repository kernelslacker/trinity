#ifndef _TRINITY_STATS_INTERNAL_H
#define _TRINITY_STATS_INTERNAL_H

/*
 * Internal interface shared by stats/ implementation files.
 *
 * Section TUs under stats/dump/, stats/childop/, stats/network/, and
 * stats/kcov/ share descriptor types, named category tables, KCOV diag
 * selectors, and rendering helpers through this header.  Not a public
 * header: only stats.c and files under stats/ are expected to include it.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>    /* FILE * -- shadow_sat JSONL emitter */
#include "params.h"   /* ARRAY_SIZE for STAT_CATEGORY() */
#include "shm.h"      /* struct stats_s for offsetof() in macros */

/* Shadow soft-saturation JSONL emitter (row t371-b).  Appends the
 * ",\"soft_sat\":{...},\"raw_windows\":[...]" block to fp.  Called
 * from stats_timeseries_emit_window() in stats/log.c after the last
 * scalar block and before the "per_syscall" array.  Public API
 * (stats_shadow_sat_tick / stats_shadow_sat_emit_out_log) is in
 * stats.h -- this prototype stays here because FILE * is not part of
 * that header's public surface. */
void stats_ts_emit_shadow_sat(FILE *fp);

/* Aggregate-stats descriptor types.  One stat_field per counter, one
 * stat_category per group; the renderer walks the field table and
 * pulls each value at f->offset from shm->stats. */
struct stat_field {
	const char *name;	/* JSON key / text metric column */
	const char *json_key;	/* Optional JSON-key override (NULL = use .name). */
	size_t      offset;	/* offsetof(struct stats_s, <field>) */
};

struct stat_category {
	const char              *name;		/* JSON object key / text category column */
	const struct stat_field *fields;
	size_t                   n_fields;
};

#define STAT_FIELD(cat, suffix) \
	{ .name = #suffix, \
	  .offset = offsetof(struct stats_s, cat##_##suffix) }

/* Dotted variant for members that live inside a per-subsystem sub-struct
 * (struct stats_s { struct blob_stats blob; ...}).  Callers migrated to
 * stats/subsys/<sub>.c use STAT_FIELD_SUB(sub, field); unmigrated flat
 * subsystems keep STAT_FIELD(cat, suffix).  Both coexist during the
 * per-subsystem split; the flat form is retired in the macro-cleanup
 * commit once every array has moved. */
#define STAT_FIELD_SUB(sub, field) \
	{ .name = #field, \
	  .offset = offsetof(struct stats_s, sub.field) }

#define STAT_FIELD_JSON(cat, suffix, jkey) \
	{ .name = #suffix, \
	  .json_key = (jkey), \
	  .offset = offsetof(struct stats_s, cat##_##suffix) }

/* Dotted variant of STAT_FIELD_JSON for members that live inside a per-
 * subsystem sub-struct.  The pinned JSON key survives the move; .name
 * carries the full member identifier so any future text emission via
 * stat_category_emit_text() still yields a grep-friendly column. */
#define STAT_FIELD_JSON_SUB(sub, field, jkey) \
	{ .name = #field, \
	  .json_key = (jkey), \
	  .offset = offsetof(struct stats_s, sub.field) }

/*
 * STAT_CATEGORY(cat_name, fields_array)
 *
 * stat_category_emit_text() decides whether to emit by walking fields[] and
 * checking whether any value is non-zero, so adding a new field to a category
 * automatically covers it.
 */
#define STAT_CATEGORY(cat_name, fields_array) \
	{ (cat_name), \
	  (fields_array), \
	  ARRAY_SIZE(fields_array) }

/* Aggregate-stats table column widths.  Header and every row use the
 * same format string so the dump is greppable and human-scannable. */
#define STATS_ROW_FMT "%-22s  %-32s  %lu\n"
#define STATS_HDR_FMT "%-22s  %-32s  %s\n"

/* Cap on rows in per-syscall top-N tables emitted from the text dump leaves. */
#define TOP_SYSCALLS_DUMP_TOPN	5

/* Periodic dump cadence shared by the defense-counter, cost-pool,
 * top-syscalls, and kcov-cmp periodic rate dumps.  Every consumer
 * self-rate-limits on this same interval so the parent's tick-driven
 * rate lines land in a single burst per window.  Also referenced from
 * breadcrumb_ring.c to keep the corrupt_ptr breadcrumb cadence aligned
 * with the defense rollup it prints beneath. */
#define DEFENSE_DUMP_INTERVAL_SEC	600

/* Per-syscall KCOV diag counter selector for kcov_diag_emit_block(). */
enum kcov_diag_counter {
	KCOV_DIAG_BUCKET_BITS_REAL,
	KCOV_DIAG_CMP_TRACE_TRUNCATED,
	KCOV_DIAG_DEDUP_PROBE_OVERFLOW,
	KCOV_DIAG_DISTINCT_PCS,
	KCOV_DIAG_MAX_TRACE_SIZE,
	KCOV_DIAG_TRACE_TRUNCATED,
};

/* Shared render helpers. */
void stat_row(const char *category, const char *metric, unsigned long value);
void stat_category_emit_text(const struct stat_category *cat);
void topn_push(unsigned long *vals, unsigned int *nrs,
	       unsigned int *count, unsigned int cap,
	       unsigned long value, unsigned int nr);
void kcov_diag_emit_block(const char *counter_name,
			  enum kcov_diag_counter counter);
void kcov_diag_emit_truncation_topn(void);
void dump_satcool_would_skip_per_syscall_top(void);
void dump_barren_would_skip_per_syscall_top(void);
void dump_live_cooldown_would_skip_per_syscall_top(void);
void dump_live_cool_per_syscall_top(const unsigned long *arr,
				    const char *label);
void dump_context_regular_suppressed_per_syscall_top(void);

/* Cross-cluster surface for the stats file split. */
extern const char * const op_names[];
bool pc_in_text(void *pc);
unsigned long stat_field_load(const struct stat_field *f);

/* Cluster entry points called by dump_stats().  dump_stats_json() lives in
 * stats/json/; childop_split_dump() lives in stats/periodic/childop-split.c. */
void dump_stats_json(void);
void childop_split_dump(void);
void dump_stats_runtime_header(void);
void dump_stats_per_syscall_tables(void);
void dump_stats_top_wedging_syscalls(void);
void dump_stats_top_wedging_childops(void);
void dump_stats_fd_tracking(void);
void dump_stats_shared_buffer_misc(void);
void dump_syscall_category_histogram(void);
void dump_stats_childop_runs_local(void);
void dump_stats_childop_fd_delta(void) __cold;
void dump_stats_topo_pair_shadow(void) __cold;
void dump_stats_corpus_and_taint_tail(void);

/* corrupt_ptr cluster in stats/corrupt_ptr.c.  Called from shutdown and
 * periodic stats dump leaves. */
void dump_range_overlaps_shared_top_offenders(void);
void corrupt_ptr_attr_dump(void);
void deferred_free_reject_pc_dump(void);

/* Pure-render dump_stats_* emitters under stats/dump/ and sibling subdirs. */
void dump_stats_oracle_anomalies(void);
void dump_stats_fuzzer_subsystems(void);
void dump_stats_corruption_and_pool(void);
void dump_stats_childop_ranked_tables(void);
void dump_stats_strategy_summary(void);
void dump_stats_childop_runs_network(void);
void dump_stats_kcov_block(void);

/* Named stat_category tables defined under stats/categories/ and stats/json/. */
extern const struct stat_category af_unix_scm_rights_gc_category;
extern const struct stat_category aio_category;
extern const struct stat_category blob_mutator_category;
extern const struct stat_category blob_ab_mode_category;
extern const struct stat_category bpf_fd_provider_category;
extern const struct stat_category child_category;
extern const struct stat_category cold_overflow_category;
extern const struct stat_category cred_transition_category;
extern const struct stat_category epoll_volatility_category;
extern const struct stat_category errno_gradient_category;
extern const struct stat_category espintcp_coalesce_category;
extern const struct stat_category fd_runtime_skipped_category;
extern const struct stat_category fdstress_category;
extern const struct stat_category prctl_futex_hash_category;
extern const struct stat_category genl_family_calls_category;
extern const struct stat_category icmp_inject_category;
extern const struct stat_category inplace_crypto_category;
extern const struct stat_category iouring_eventfd_category;
extern const struct stat_category iouring_send_zc_churn_category;
extern const struct stat_category ipv6_pmtu_race_category;
extern const struct stat_category netlink_generator_category;
extern const struct stat_category netns_mountns_setup_category;
extern const struct stat_category netns_teardown_category;
extern const struct stat_category nfnl_subsys_calls_category;
extern const struct stat_category no_domains_category;
extern const struct stat_category oracle_category;
extern const struct stat_category parent_category;
extern const struct stat_category vsock_transport_churn_category;
extern const struct stat_category pkt_builder_category;
extern const struct stat_category posix_timer_category;
extern const struct stat_category refcount_audit_category;
extern const struct stat_category rpl_clone_fidelity_category;
extern const struct stat_category rtnl_ack_oracle_category;
extern const struct stat_category rxrpc_key_install_category;
extern const struct stat_category setsockopt_pairing_category;
extern const struct stat_category socket_family_grammar_category;
extern const struct stat_category xfrm_grammar_category;
extern const struct stat_category statmount_idmap_category;
extern const struct stat_category uid_change_category;
extern const struct stat_category userns_bootstrap_category;
extern const struct stat_category vfs_writes_category;
extern const struct stat_category xattr_thrash_category;
extern const struct stat_category xfrm_ah_esn_category;
extern const struct stat_category xfrm_compat_category;
extern const struct stat_category zombie_slots_category;

#endif /* _TRINITY_STATS_INTERNAL_H */
