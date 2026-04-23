#include <errno.h>
#include <string.h>
#include "arch.h"
#include "cmp_hints.h"
#include "edgepair.h"
#include "kcov.h"
#include "minicorpus.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/*
 * Aggregate-stats table column widths. Header + every row uses the same
 * format string so output is greppable (grep '^fd_lifecycle ') and
 * human-scannable (columns line up).
 */
#define STATS_ROW_FMT "%-22s  %-32s  %lu\n"
#define STATS_HDR_FMT "%-22s  %-32s  %s\n"

static void stats_emit_header(void)
{
	output(0, "\n");
	output(0, STATS_HDR_FMT, "CATEGORY", "METRIC", "VALUE");
	output(0, STATS_HDR_FMT,
	       "----------------------",
	       "--------------------------------",
	       "-----");
}

static void stat_row(const char *category, const char *metric, unsigned long value)
{
	output(0, STATS_ROW_FMT, category, metric, value);
}

static void dump_entry(const struct syscalltable *table, unsigned int i)
{
	struct syscallentry *entry;
	unsigned int j;

	entry = table[i].entry;
	if (entry == NULL)
		return;

	if (entry->attempted == 0)
		return;

	output(0, "%s: (attempted:%u. success:%u. failures:%u.\n", entry->name, entry->attempted, entry->successes, entry->failures);

	for (j = 0; j < NR_ERRNOS; j++) {
		if (entry->errnos[j] != 0) {
			output(0, "    %s: %d\n", strerror(j), entry->errnos[j]);
		}
	}
}

void dump_stats(void)
{
	unsigned int i;

	if (biarch == true) {
		output(0, "32bit:\n");
		for_each_32bit_syscall(i) {
			dump_entry(syscalls_32bit, i);
		}
		output(0, "64bit:\n");
		for_each_64bit_syscall(i) {
			dump_entry(syscalls_64bit, i);
		}
	} else {
		for_each_syscall(i) {
			dump_entry(syscalls, i);
		}
	}

	stats_emit_header();

	if (shm->stats.fault_injected) {
		stat_row("fault_injection", "armed_fail_nth",  shm->stats.fault_injected);
		stat_row("fault_injection", "returned_enomem", shm->stats.fault_consumed);
	}

	if (shm->stats.fd_stale_detected || shm->stats.fd_closed_tracked ||
	    shm->stats.fd_regenerated || shm->stats.fd_stale_by_generation ||
	    shm->stats.fd_duped || shm->stats.fd_events_processed) {
		stat_row("fd_lifecycle", "stale_detected",      shm->stats.fd_stale_detected);
		stat_row("fd_lifecycle", "stale_by_generation", shm->stats.fd_stale_by_generation);
		stat_row("fd_lifecycle", "closed_tracked",      shm->stats.fd_closed_tracked);
		stat_row("fd_lifecycle", "regenerated",         shm->stats.fd_regenerated);
		stat_row("fd_lifecycle", "duped",               shm->stats.fd_duped);
		stat_row("fd_lifecycle", "events_processed",    shm->stats.fd_events_processed);
		stat_row("fd_lifecycle", "events_dropped",      shm->stats.fd_events_dropped);
	}

	if (shm->stats.fd_oracle_anomalies)
		stat_row("oracle", "fd_anomalies",   shm->stats.fd_oracle_anomalies);
	if (shm->stats.mmap_oracle_anomalies)
		stat_row("oracle", "mmap_anomalies", shm->stats.mmap_oracle_anomalies);
	if (shm->stats.cred_oracle_anomalies)
		stat_row("oracle", "cred_anomalies", shm->stats.cred_oracle_anomalies);

	if (shm->stats.procfs_writes || shm->stats.sysfs_writes ||
	    shm->stats.debugfs_writes) {
		stat_row("vfs_writes", "procfs",  shm->stats.procfs_writes);
		stat_row("vfs_writes", "sysfs",   shm->stats.sysfs_writes);
		stat_row("vfs_writes", "debugfs", shm->stats.debugfs_writes);
	}

	if (shm->stats.memory_pressure_runs)
		stat_row("memory_pressure", "runs_madv_pageout", shm->stats.memory_pressure_runs);

	if (shm->stats.sched_cycler_runs) {
		stat_row("sched_cycler", "runs",  shm->stats.sched_cycler_runs);
		stat_row("sched_cycler", "eperm", shm->stats.sched_cycler_eperm);
	}

	if (shm->stats.userns_runs) {
		stat_row("userns_fuzzer", "runs",          shm->stats.userns_runs);
		stat_row("userns_fuzzer", "inner_crashed", shm->stats.userns_inner_crashed);
		stat_row("userns_fuzzer", "unsupported",   shm->stats.userns_unsupported);
	}

	if (shm->stats.barrier_racer_runs) {
		stat_row("barrier_racer", "runs",          shm->stats.barrier_racer_runs);
		stat_row("barrier_racer", "inner_crashed", shm->stats.barrier_racer_inner_crashed);
	}

	if (shm->stats.genetlink_families_discovered ||
	    shm->stats.genetlink_msgs_sent) {
		stat_row("genetlink_fuzzer", "families_discovered", shm->stats.genetlink_families_discovered);
		stat_row("genetlink_fuzzer", "msgs_sent",           shm->stats.genetlink_msgs_sent);
		stat_row("genetlink_fuzzer", "eperm",               shm->stats.genetlink_eperm);
	}

	if (shm->stats.netlink_nested_attrs_emitted)
		stat_row("netlink_generator", "nested_attrs_emitted", shm->stats.netlink_nested_attrs_emitted);

	if (shm->stats.perf_chains_runs) {
		stat_row("perf_event_chains", "runs",           shm->stats.perf_chains_runs);
		stat_row("perf_event_chains", "groups_created", shm->stats.perf_chains_groups_created);
		stat_row("perf_event_chains", "ioctl_ops",      shm->stats.perf_chains_ioctl_ops);
	}

	if (shm->stats.tracefs_kprobe_writes || shm->stats.tracefs_uprobe_writes ||
	    shm->stats.tracefs_filter_writes || shm->stats.tracefs_event_enable_writes ||
	    shm->stats.tracefs_misc_writes) {
		stat_row("tracefs_fuzzer", "kprobe_writes",       shm->stats.tracefs_kprobe_writes);
		stat_row("tracefs_fuzzer", "uprobe_writes",       shm->stats.tracefs_uprobe_writes);
		stat_row("tracefs_fuzzer", "filter_writes",       shm->stats.tracefs_filter_writes);
		stat_row("tracefs_fuzzer", "event_enable_writes", shm->stats.tracefs_event_enable_writes);
		stat_row("tracefs_fuzzer", "misc_writes",         shm->stats.tracefs_misc_writes);
	}

	if (shm->stats.bpf_lifecycle_runs) {
		stat_row("bpf_lifecycle", "runs",             shm->stats.bpf_lifecycle_runs);
		stat_row("bpf_lifecycle", "progs_loaded",     shm->stats.bpf_lifecycle_progs_loaded);
		stat_row("bpf_lifecycle", "attached",         shm->stats.bpf_lifecycle_attached);
		stat_row("bpf_lifecycle", "triggered",        shm->stats.bpf_lifecycle_triggered);
		stat_row("bpf_lifecycle", "verifier_rejects", shm->stats.bpf_lifecycle_verifier_rejects);
		stat_row("bpf_lifecycle", "attach_failed",    shm->stats.bpf_lifecycle_attach_failed);
		stat_row("bpf_lifecycle", "eperm",            shm->stats.bpf_lifecycle_eperm);
	}

	if (shm->stats.bpf_maps_provided || shm->stats.bpf_progs_provided) {
		stat_row("bpf_fd_provider", "maps_provided",  shm->stats.bpf_maps_provided);
		stat_row("bpf_fd_provider", "progs_provided", shm->stats.bpf_progs_provided);
	}

	if (shm->stats.recipe_runs) {
		stat_row("recipe_runner", "runs",        shm->stats.recipe_runs);
		stat_row("recipe_runner", "completed",   shm->stats.recipe_completed);
		stat_row("recipe_runner", "partial",     shm->stats.recipe_partial);
		stat_row("recipe_runner", "unsupported", shm->stats.recipe_unsupported);
		recipe_runner_dump_stats();
	}

	if (shm->stats.iouring_recipes_runs) {
		stat_row("iouring_recipes", "runs",      shm->stats.iouring_recipes_runs);
		stat_row("iouring_recipes", "completed", shm->stats.iouring_recipes_completed);
		stat_row("iouring_recipes", "partial",   shm->stats.iouring_recipes_partial);
		stat_row("iouring_recipes", "enosys",    shm->stats.iouring_recipes_enosys);
		iouring_recipes_dump_stats();
	}

	if (shm->stats.zombies_reaped || shm->stats.zombies_timed_out ||
	    shm->stats.zombie_slots_pending) {
		stat_row("zombie_slots", "pending",   shm->stats.zombie_slots_pending);
		stat_row("zombie_slots", "reaped",    shm->stats.zombies_reaped);
		stat_row("zombie_slots", "timed_out", shm->stats.zombies_timed_out);
	}

	if (shm->stats.local_op_count_corrupted)
		stat_row("corruption", "local_op_count",         shm->stats.local_op_count_corrupted);
	if (shm->stats.fd_event_ring_corrupted)
		stat_row("corruption", "fd_event_ring_noncanon", shm->stats.fd_event_ring_corrupted);
	if (shm->stats.fd_event_ring_overwritten)
		stat_row("corruption", "fd_event_ring_canary",   shm->stats.fd_event_ring_overwritten);

	if (shm->stats.shared_buffer_redirected)
		stat_row("shared_buffer", "args_redirected",     shm->stats.shared_buffer_redirected);
	if (shm->stats.range_overlap_rejects)
		stat_row("shared_buffer", "range_overlap_rejects", shm->stats.range_overlap_rejects);

	dump_obj_heap_stats();

	if (shm->stats.refcount_audit_runs) {
		stat_row("refcount_audit", "runs",           shm->stats.refcount_audit_runs);
		stat_row("refcount_audit", "fd_anomalies",   shm->stats.refcount_audit_fd_anomalies);
		stat_row("refcount_audit", "mmap_anomalies", shm->stats.refcount_audit_mmap_anomalies);
		stat_row("refcount_audit", "sock_anomalies", shm->stats.refcount_audit_sock_anomalies);
	}

	if (shm->stats.fs_lifecycle_tmpfs || shm->stats.fs_lifecycle_ramfs ||
	    shm->stats.fs_lifecycle_overlay || shm->stats.fs_lifecycle_unsupported) {
		stat_row("fs_lifecycle", "tmpfs",       shm->stats.fs_lifecycle_tmpfs);
		stat_row("fs_lifecycle", "ramfs",       shm->stats.fs_lifecycle_ramfs);
		stat_row("fs_lifecycle", "rdonly",      shm->stats.fs_lifecycle_rdonly);
		stat_row("fs_lifecycle", "overlay",     shm->stats.fs_lifecycle_overlay);
		stat_row("fs_lifecycle", "unsupported", shm->stats.fs_lifecycle_unsupported);
	}

	if (shm->stats.signal_storm_runs) {
		stat_row("signal_storm", "runs",       shm->stats.signal_storm_runs);
		stat_row("signal_storm", "kill",       shm->stats.signal_storm_kill);
		stat_row("signal_storm", "sigqueue",   shm->stats.signal_storm_sigqueue);
		stat_row("signal_storm", "no_targets", shm->stats.signal_storm_no_targets);
	}

	if (shm->stats.futex_storm_runs)
		output(0, "\nfutex storm: runs:%lu inner_crashed:%lu iters:%lu\n",
			shm->stats.futex_storm_runs,
			shm->stats.futex_storm_inner_crashed,
			shm->stats.futex_storm_iters);

	if (shm->stats.pipe_thrash_runs) {
		stat_row("pipe_thrash", "runs",         shm->stats.pipe_thrash_runs);
		stat_row("pipe_thrash", "pipes",        shm->stats.pipe_thrash_pipes);
		stat_row("pipe_thrash", "socketpairs",  shm->stats.pipe_thrash_socketpairs);
		stat_row("pipe_thrash", "alloc_failed", shm->stats.pipe_thrash_alloc_failed);
	}

	if (kcov_shm != NULL) {
		unsigned int top_nr[10];
		unsigned long top_edges[10];
		unsigned int top_count = 0;
		unsigned int cold_count = 0;
		unsigned int j;

		unsigned long kc_edges  = __atomic_load_n(&kcov_shm->edges_found,   __ATOMIC_RELAXED);
		unsigned long kc_pcs    = __atomic_load_n(&kcov_shm->total_pcs,     __ATOMIC_RELAXED);
		unsigned long kc_calls  = __atomic_load_n(&kcov_shm->total_calls,   __ATOMIC_RELAXED);
		unsigned long kc_remote = __atomic_load_n(&kcov_shm->remote_calls,  __ATOMIC_RELAXED);

		stat_row("kcov_coverage", "unique_edges", kc_edges);
		stat_row("kcov_coverage", "total_pcs",    kc_pcs);
		stat_row("kcov_coverage", "total_calls",  kc_calls);
		stat_row("kcov_coverage", "remote_calls", kc_remote);

		/* Find top 10 edge-producing syscalls via insertion sort. */
		unsigned int nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
		const struct syscalltable *table = biarch ? syscalls_64bit : syscalls;

		memset(top_edges, 0, sizeof(top_edges));
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long edges = __atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);

			if (edges == 0)
				continue;

			if (kcov_syscall_is_cold(i))
				cold_count++;

			/* Find insertion point. */
			for (j = top_count; j > 0 && edges > top_edges[j - 1]; j--) {
				if (j < 10) {
					top_edges[j] = top_edges[j - 1];
					top_nr[j] = top_nr[j - 1];
				}
			}
			if (j < 10) {
				top_edges[j] = edges;
				top_nr[j] = i;
				if (top_count < 10)
					top_count++;
			}
		}

		if (top_count > 0) {
			output(0, "Top edge-producing syscalls:\n");
			for (j = 0; j < top_count; j++) {
				struct syscallentry *entry = table[top_nr[j]].entry;
				const char *name = entry ? entry->name : "???";

				output(0, "  %-24s %lu\n", name, top_edges[j]);
			}
		}

		/* Top-N by per-interval edge growth (delta since last dump_stats). */
		{
			unsigned int delta_nr[10];
			unsigned long delta_edges[10];
			unsigned int delta_count = 0;
			bool any_delta = false;

			memset(delta_edges, 0, sizeof(delta_edges));
			for (i = 0; i < nr_syscalls_to_scan; i++) {
				unsigned long prev = kcov_shm->per_syscall_edges_previous[i];
				unsigned long curr = __atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);
				unsigned long delta = (curr > prev) ? curr - prev : 0;

				if (delta > 0)
					any_delta = true;

				if (delta == 0)
					continue;

				for (j = delta_count; j > 0 && delta > delta_edges[j - 1]; j--) {
					if (j < 10) {
						delta_edges[j] = delta_edges[j - 1];
						delta_nr[j] = delta_nr[j - 1];
					}
				}
				if (j < 10) {
					delta_edges[j] = delta;
					delta_nr[j] = i;
					if (delta_count < 10)
						delta_count++;
				}
			}

			if (any_delta && delta_count > 0) {
				output(0, "Top syscalls by recent edge growth:\n");
				for (j = 0; j < delta_count; j++) {
					struct syscallentry *entry = table[delta_nr[j]].entry;
					const char *name = entry ? entry->name : "???";

					output(0, "  %-24s +%lu\n", name, delta_edges[j]);
				}
			}

			/* Snapshot current counts for the next interval. */
			for (i = 0; i < nr_syscalls_to_scan; i++)
				kcov_shm->per_syscall_edges_previous[i] =
					__atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);
		}

		if (cold_count > 0) {
			output(0, "Cold syscalls (need better sanitise): %u\n", cold_count);
			for (i = 0; i < nr_syscalls_to_scan; i++) {
				struct syscallentry *entry;

				unsigned long slot_edges = __atomic_load_n(&kcov_shm->per_syscall_edges[i], __ATOMIC_RELAXED);

				if (slot_edges == 0)
					continue;
				if (!kcov_syscall_is_cold(i))
					continue;

				entry = table[i].entry;
				output(0, "  %-24s (edges:%lu, last new @ call %lu)\n",
					entry ? entry->name : "???",
					slot_edges,
					kcov_shm->last_edge_at[i]);
			}
		}
	}

	if (minicorpus_shm != NULL) {
		static const char * const op_names[MUT_NUM_OPS] = {
			"bit-flip", "add", "sub", "boundary", "byte-shuf", "keep",
			"bswap-add", "bswap-sub"
		};
		unsigned long tot_trials = 0;
		unsigned long r_count, r_wins, s_hits, s_wins, pct10;
		unsigned long histo_total;
		char hbuf[80];
		int hpos;

		for (i = 0; i < MUT_NUM_OPS; i++)
			tot_trials += __atomic_load_n(&minicorpus_shm->mut_trials[i],
						      __ATOMIC_RELAXED);

		if (tot_trials > 0) {
			output(0, "\nMutator productivity (wins/trials):\n");
			for (i = 0; i < MUT_NUM_OPS; i++) {
				unsigned long t = __atomic_load_n(&minicorpus_shm->mut_trials[i],
								  __ATOMIC_RELAXED);
				unsigned long w = __atomic_load_n(&minicorpus_shm->mut_wins[i],
								  __ATOMIC_RELAXED);
				pct10 = t ? (w * 1000UL / t) : 0UL;
				output(0, "  %-10s %lu/%lu (%lu.%lu%%)\n",
				       op_names[i], w, t, pct10 / 10, pct10 % 10);
			}
		}

		s_hits = __atomic_load_n(&minicorpus_shm->splice_hits, __ATOMIC_RELAXED);
		s_wins = __atomic_load_n(&minicorpus_shm->splice_wins, __ATOMIC_RELAXED);
		if (s_hits > 0) {
			pct10 = s_wins * 1000UL / s_hits;
			output(0, "Splice: %lu hits  %lu wins (%lu.%lu%%)\n",
			       s_hits, s_wins, pct10 / 10, pct10 % 10);
		}

		histo_total = 0;
		for (i = 1; i <= STACK_MAX; i++)
			histo_total += __atomic_load_n(&minicorpus_shm->stack_depth_histogram[i],
						       __ATOMIC_RELAXED);
		if (histo_total > 0) {
			hpos = 0;
			for (i = 1; i <= STACK_MAX; i++) {
				unsigned long d = __atomic_load_n(
					&minicorpus_shm->stack_depth_histogram[i],
					__ATOMIC_RELAXED);
				hpos += snprintf(hbuf + hpos, sizeof(hbuf) - hpos,
						 " [%u]:%lu", i, d);
				if (hpos >= (int)sizeof(hbuf) - 1)
					break;
			}
			output(0, "Stack depth:%s\n", hbuf);
		}

		r_count = __atomic_load_n(&minicorpus_shm->replay_count, __ATOMIC_RELAXED);
		r_wins  = __atomic_load_n(&minicorpus_shm->replay_wins,  __ATOMIC_RELAXED);
		if (r_count > 0) {
			pct10 = r_wins * 1000UL / r_count;
			output(0, "Corpus replay: %lu replays  %lu wins (%lu.%lu%%)\n",
			       r_count, r_wins, pct10 / 10, pct10 % 10);
		}

		{
			unsigned long c_iter = __atomic_load_n(
				&minicorpus_shm->chain_iter_count,
				__ATOMIC_RELAXED);
			unsigned long c_subst = __atomic_load_n(
				&minicorpus_shm->chain_substitution_count,
				__ATOMIC_RELAXED);
			unsigned long c_save = chain_corpus_shm ? __atomic_load_n(
				&chain_corpus_shm->save_count,
				__ATOMIC_RELAXED) : 0UL;
			unsigned long c_replay = chain_corpus_shm ? __atomic_load_n(
				&chain_corpus_shm->replay_count,
				__ATOMIC_RELAXED) : 0UL;

			if (c_iter > 0)
				output(0, "Sequence chains: %lu iters  %lu substitutions  %lu corpus saves  %lu replays\n",
				       c_iter, c_subst, c_save, c_replay);
		}
	}

	if (cmp_hints_shm != NULL) {
		unsigned int total_hints = 0, syscalls_with_hints = 0;

		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			if (cmp_hints_shm->pools[i].count > 0) {
				total_hints += cmp_hints_shm->pools[i].count;
				syscalls_with_hints++;
			}
		}
		stat_row("cmp_hints", "values_total",        total_hints);
		stat_row("cmp_hints", "syscalls_with_hints", syscalls_with_hints);
	}

	if (edgepair_shm != NULL) {
		unsigned int top_count = 0;
		unsigned int cold_pairs = 0;
		struct {
			unsigned int prev_nr;
			unsigned int curr_nr;
			unsigned long new_edges;
		} top[10];
		unsigned int j;

		memset(top, 0, sizeof(top));

		stat_row("edgepair_coverage", "unique_pairs",     edgepair_shm->pairs_tracked);
		stat_row("edgepair_coverage", "total_pair_calls", edgepair_shm->total_pair_calls);

		if (edgepair_shm->pairs_dropped > 0)
			stat_row("edgepair_coverage", "inserts_dropped", edgepair_shm->pairs_dropped);

		for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
			struct edgepair_entry *e = &edgepair_shm->table[i];
			unsigned long edges;

			if (e->prev_nr == EDGEPAIR_EMPTY)
				continue;

			edges = e->new_edge_count;
			if (edges == 0)
				continue;

			if (edgepair_is_cold(e->prev_nr, e->curr_nr))
				cold_pairs++;

			for (j = top_count; j > 0 && edges > top[j - 1].new_edges; j--) {
				if (j < 10)
					top[j] = top[j - 1];
			}
			if (j < 10) {
				top[j].prev_nr = e->prev_nr;
				top[j].curr_nr = e->curr_nr;
				top[j].new_edges = edges;
				if (top_count < 10)
					top_count++;
			}
		}

		if (top_count > 0) {
			const struct syscalltable *table = biarch ? syscalls_64bit : syscalls;
			unsigned int nr_max = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;

			output(0, "Top edge-producing syscall pairs:\n");
			for (j = 0; j < top_count; j++) {
				const char *prev_name = "???";
				const char *curr_name = "???";

				if (top[j].prev_nr < nr_max && table[top[j].prev_nr].entry)
					prev_name = table[top[j].prev_nr].entry->name;
				if (top[j].curr_nr < nr_max && table[top[j].curr_nr].entry)
					curr_name = table[top[j].curr_nr].entry->name;

				output(0, "  %-20s -> %-20s %lu\n",
					prev_name, curr_name, top[j].new_edges);
			}
		}

		if (cold_pairs > 0)
			stat_row("edgepair_coverage", "cold_pairs", cold_pairs);

		edgepair_dump_to_file("edgepair.dump");
	}
}
