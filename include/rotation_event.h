#pragma once

/*
 * Durable per-rotation-block intervention event stream.
 *
 * Appends one JSON-Lines record per completed strategy-rotation window
 * (one call per maybe_rotate_strategy() close) to a dedicated file in
 * the operator's launch CWD.  This is the raw per-block substrate the
 * intervention-experiment analysis needs: the periodic --stats JSONL
 * carries cumulative counters at a coarser cadence, and the cumulative
 * per-PIM-mode totals in shm cannot answer per-block confirmation
 * questions ("did this specific PIM_ANTI_PRIOR block clear both the
 * yield floor and the control block").
 *
 * OBSERVATION-ONLY.  Nothing in the fuzz loop reads these records;
 * emission has no side effects on picker/dispatch state and does not
 * draw from any RNG.  Byte-identical to the pre-record run under a
 * fixed seed in a non-saturated regime.
 *
 * File-handle lifecycle mirrors stats/log.c's timeseries sink except
 * that the sink is intentionally SHARED with children -- the CAS-
 * winning child is the writer, so the fd stays open across fork() and
 * every child inherits the same O_APPEND file description.  Children
 * do NOT drop the fd on fork; concurrent writers rely on the O_APPEND
 * writev() atomic-seek-to-end contract in lib/jsonl.c.
 */

#include <stdbool.h>
#include <stdint.h>

/*
 * Per-block snapshot assembled by the CAS-winning child at rotation
 * close, BEFORE the next arm is published.  All fields are captured
 * from shm/kcov_shm loads the caller already performed on the close
 * path -- this struct is a transport shape, not a new counter surface.
 *
 * Kept in the header so the caller in random_syscall/strategy-rotate.c
 * can populate it inline without pulling stats/rotation_event.c into
 * its dependency graph beyond the emit call.
 */
struct rotation_event {
	uint64_t t_close_mono_ns;	/* CLOCK_MONOTONIC at close */
	uint64_t start_mono_ns;		/* run anchor (env fingerprint) */
	unsigned long op_count_start;	/* fleet_op_count at window open */
	unsigned long op_count_end;	/* fleet_op_count at window close */
	unsigned long syscalls_in_window;
	int strategy_prev;		/* just-closed arm */
	int strategy_next;		/* published next arm */
	int selection_reason_prev;	/* enum strategy_selection_reason */
	int selection_reason_next;
	int pim_mode;			/* enum plateau_intervention_mode
					 * effective for the just-closed
					 * window; -1 when the window was
					 * not SR_PLATEAU_FORCE */
	unsigned long pc_edge_calls_in_window;	/* productive calls */
	unsigned long pc_edges_in_window;	/* new distinct PC edges */
	unsigned long cmp_wins_in_window;	/* CMP novel constants */
	unsigned long warn_fires_in_window;	/* kmsg WARN deltas */
	bool was_chaos;			/* chaos-mode cohort of closed win */
	bool plateau_active;		/* kcov_shm plateau latch at close */
	unsigned long distinct_edges_now;	/* coverage fingerprint --
						 * cumulative kcov distinct
						 * edges at close, so consumers
						 * can join events to a
						 * coverage progress point */
};

/*
 * Open the append-only per-rotation-block JSONL sink.  Called from the
 * parent BEFORE fork() so every child inherits the same open file
 * description; opening later would leave post-fork children with an
 * unopened fd and lose their emissions.  No-op when --stats was not
 * passed (matches stats_timeseries_open()'s gating so an operator who
 * turned off the timeseries also gets no rotation-event file).
 *
 * Failure logs a warning and leaves the sink disabled; the emit path
 * is a no-op when the fd is < 0.
 */
void stats_rotation_event_open(void);

/*
 * Close the sink from the parent at shutdown.  Safe to call when open
 * was skipped or failed.
 */
void stats_rotation_event_close(void);

/*
 * Append one rotation event.  Formats the struct as a single-line JSON
 * object and hands it to jsonl_write() (O_APPEND writev() gives us the
 * concurrent-child atomic-record contract without a lock).  No-op when
 * the sink was never opened.
 */
void stats_rotation_event_emit(const struct rotation_event *ev);
