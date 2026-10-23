#pragma once

/*
 * Golden text for stats_render_test.c.  The definitions live in
 * stats_render_golden.c; see the blessing note at the top of the test.
 */

/* Periodic KCOV CMP dump: every counter moving, then a window with none. */
extern const char stats_golden_cmp_full_1[];
extern const char stats_golden_cmp_full_2[];
extern const char stats_golden_cmp_idle[];

/* Periodic KCOV CMP dump: one counter moving in an otherwise quiet window. */
extern const char stats_golden_cmp_probe_frontier[];
extern const char stats_golden_cmp_probe_records[];
extern const char stats_golden_cmp_probe_gate_pass[];
extern const char stats_golden_cmp_probe_parent_ctl[];
extern const char stats_golden_cmp_probe_credit_evicted[];
extern const char stats_golden_cmp_probe_mut_structured[];
extern const char stats_golden_cmp_probe_remote_adaptive[];
extern const char stats_golden_cmp_probe_callsite[];
extern const char stats_golden_cmp_probe_wins[];
extern const char stats_golden_cmp_probe_misses[];
extern const char stats_golden_cmp_probe_prop[];
extern const char stats_golden_cmp_probe_by_arm[];
extern const char stats_golden_cmp_probe_levels[];
extern const char stats_golden_cmp_probe_try_get[];
extern const char stats_golden_cmp_probe_chaos_off[];
extern const char stats_golden_cmp_probe_chaos_on[];

/* Periodic KCOV CMP dump: the paths around the any-delta gate. */
extern const char stats_golden_cmp_edge_up[];
extern const char stats_golden_cmp_edge_back[];
extern const char stats_golden_cmp_edge_divergence[];
extern const char stats_golden_cmp_edge_no_minicorpus[];

/* The core sections of the --stats-json "stats" object. */
extern const char stats_golden_json_core[];
