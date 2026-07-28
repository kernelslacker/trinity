/*
 * Durable per-rotation-block intervention event stream (see
 * include/rotation_event.h).
 *
 * Opens one JSONL sink in the parent before fork() so every child
 * inherits the same O_APPEND file description; the CAS-winning child
 * of maybe_rotate_strategy() writes a single record per closed window
 * via lib/jsonl.c's writev()-based emit path.  No parent-side aggregate
 * is maintained -- the records are the surface.
 *
 * OBSERVATION-ONLY: byte-identical under fixed seed in a non-saturated
 * regime.  Emission does not touch shm state, does not sample the RNG,
 * and only reads counters the caller already loaded on the close path.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "jsonl.h"
#include "params.h"
#include "pids.h"
#include "rotation_event.h"
#include "strategy.h"
#include "trinity.h"
#include "utils-proc.h"

/*
 * Sink fd.  <0 means the file is not open (either --stats was off, or
 * the open failed).  All emit calls short-circuit on this predicate so
 * the fast path stays a single compare + branch when the sink is off.
 *
 * Deliberately inherited across fork(): unlike stats_timeseries_fp
 * (parent-only writer, dropped in children), the rotation-event writer
 * is the CAS-winning fuzz child.  No drop-in-child helper is provided
 * for this reason -- see include/rotation_event.h.
 */
static int rotation_event_fd = -1;

void stats_rotation_event_open(void)
{
	char path[96];
	time_t now;

	if (show_stats == false)
		return;

	/* Same filename shape as stats_timeseries_open(): seconds +
	 * pid + CLOCK_MONOTONIC-ns so two runs launched inside one
	 * wall-clock second (or under an NTP step) do not collide on
	 * the same file and interleave records.  Kept short enough
	 * that a typical launch CWD fits the whole family. */
	now = time(NULL);
	snprintf(path, sizeof(path),
		 "rotation-events-%lld-p%d-%llu.jsonl",
		 (long long)now, (int)mypid(),
		 (unsigned long long)mono_ns());

	rotation_event_fd = jsonl_open(path);
	if (rotation_event_fd < 0) {
		outputerr("failed to open rotation event file %s: %s\n",
			  path, strerror(errno));
		return;
	}
}

void stats_rotation_event_close(void)
{
	if (rotation_event_fd < 0)
		return;
	close(rotation_event_fd);
	rotation_event_fd = -1;
}

/*
 * Assemble the JSON line into a stack buffer sized well above the
 * expected record length (all numeric fields, no unbounded strings) so
 * we never allocate on this path.  If snprintf would truncate we drop
 * the record silently rather than emit an ill-formed line -- the sink
 * is observation-only and a downstream consumer already tolerates gaps
 * (a child killed mid-CAS drops its record too).
 */
#define ROTATION_EVENT_JSON_BUFSIZE 1024

void stats_rotation_event_emit(const struct rotation_event *ev)
{
	char buf[ROTATION_EVENT_JSON_BUFSIZE];
	const char *pim_name = "";
	int n;

	if (rotation_event_fd < 0 || ev == NULL)
		return;

	if (ev->pim_mode >= 0 && ev->pim_mode < NR_PIM_MODES)
		pim_name = plateau_intervention_mode_name(
			(enum plateau_intervention_mode)ev->pim_mode);

	n = snprintf(buf, sizeof(buf),
		"{\"t_close_mono_ns\":%" PRIu64
		",\"start_mono_ns\":%" PRIu64
		",\"op_count_start\":%lu,\"op_count_end\":%lu"
		",\"syscalls_in_window\":%lu"
		",\"strategy_prev\":%d,\"strategy_prev_name\":\"%s\""
		",\"strategy_next\":%d,\"strategy_next_name\":\"%s\""
		",\"selection_reason_prev\":%d,\"selection_reason_prev_name\":\"%s\""
		",\"selection_reason_next\":%d,\"selection_reason_next_name\":\"%s\""
		",\"pim_mode\":%d,\"pim_mode_name\":\"%s\""
		",\"pc_edge_calls_in_window\":%lu"
		",\"pc_edges_in_window\":%lu"
		",\"cmp_wins_in_window\":%lu"
		",\"warn_fires_in_window\":%lu"
		",\"was_chaos\":%s"
		",\"plateau_active\":%s"
		",\"distinct_edges_now\":%lu"
		"}",
		ev->t_close_mono_ns,
		ev->start_mono_ns,
		ev->op_count_start, ev->op_count_end,
		ev->syscalls_in_window,
		ev->strategy_prev, strategy_name(ev->strategy_prev),
		ev->strategy_next, strategy_name(ev->strategy_next),
		ev->selection_reason_prev,
		strategy_selection_reason_name(
			(enum strategy_selection_reason)ev->selection_reason_prev),
		ev->selection_reason_next,
		strategy_selection_reason_name(
			(enum strategy_selection_reason)ev->selection_reason_next),
		ev->pim_mode, pim_name,
		ev->pc_edge_calls_in_window,
		ev->pc_edges_in_window,
		ev->cmp_wins_in_window,
		ev->warn_fires_in_window,
		ev->was_chaos ? "true" : "false",
		ev->plateau_active ? "true" : "false",
		ev->distinct_edges_now);

	if (n < 0 || (size_t)n >= sizeof(buf))
		return;

	jsonl_write(rotation_event_fd, buf);
}
