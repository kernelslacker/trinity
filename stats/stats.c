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

void __cold dump_stats(void)
{
	if (stats_json) {
		dump_stats_json();
		return;
	}

	/* Lead the shutdown report with the run-identity block so the
	 * provenance triple + cold/warm carrier state + own-start deltas
	 * are the first thing an operator sees -- the post-mortem hook a
	 * "did this run actually advance coverage" check needs before
	 * any of the downstream tables can be interpreted. */
	stats_runid_render();

	dump_stats_runtime_header();

	dump_stats_per_syscall_tables();

	dump_stats_top_wedging_syscalls();

	dump_stats_top_wedging_childops();

	dump_stats_fd_tracking();

	dump_stats_oracle_anomalies();

	dump_stats_fuzzer_subsystems();

	dump_stats_corruption_and_pool();

	dump_stats_childop_ranked_tables();

	childop_score_dump();

	childop_outcome_window_dump();

	dump_stats_childop_decay_recency();

	dump_stats_childop_fd_delta();

	dump_stats_topo_pair_shadow();

	dump_stats_shared_buffer_misc();

	dump_stats_strategy_summary();

	dump_stats_childop_runs_local();

	dump_stats_childop_runs_network();

	dump_stats_kcov_block();

	dump_stats_corpus_and_taint_tail();

	/* Cumulative childop vs random-syscall effort split.  Also emitted
	 * mid-run from periodic_counter_rates_dump on the 600 s cadence
	 * for long-fuzz visibility, but a short --dry-run (or any run that
	 * exits before the first periodic dump fires) still needs to see
	 * the block, so emit it unconditionally from the shutdown dump too.
	 * Self-skips silently if no dispatch has happened yet. */
	childop_split_dump();
}
