#pragma once

/* Sub-struct of struct kcov_shared, embedded as .covjump.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_covjump {
unsigned long covjump_window_start_call_nr;
unsigned long covjump_window_start_distinct_edges;
unsigned long covjump_snap_saves_pc;
unsigned long covjump_snap_saves_cmp;
unsigned long covjump_snap_chain_saves;
unsigned long covjump_snap_chain_replays;
unsigned long covjump_snap_childop_invocations[KCOV_CHILDOP_NR_MAX];
unsigned long covjump_last_emit_call_nr;
bool covjump_window_armed;
};
