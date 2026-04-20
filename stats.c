#include <errno.h>
#include <string.h>
#include "arch.h"
#include "cmp_hints.h"
#include "edgepair.h"
#include "kcov.h"
#include "shm.h"
#include "stats.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"

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

	if (shm->stats.fault_injected) {
		output(0, "\nFault injection: %lu syscalls armed via /proc/self/fail-nth, %lu returned -ENOMEM\n",
			shm->stats.fault_injected,
			shm->stats.fault_consumed);
	}

	if (shm->stats.fd_stale_detected || shm->stats.fd_closed_tracked ||
	    shm->stats.fd_regenerated || shm->stats.fd_stale_by_generation ||
	    shm->stats.fd_duped || shm->stats.fd_events_processed) {
		output(0, "\nfd lifecycle: stale:%lu (generation:%lu) closed:%lu regenerated:%lu duped:%lu\n",
			shm->stats.fd_stale_detected,
			shm->stats.fd_stale_by_generation,
			shm->stats.fd_closed_tracked,
			shm->stats.fd_regenerated,
			shm->stats.fd_duped);
		output(0, "fd events: processed:%lu dropped:%lu\n",
			shm->stats.fd_events_processed,
			shm->stats.fd_events_dropped);
	}

	if (shm->stats.fd_oracle_anomalies)
		output(0, "fd oracle anomalies: %lu\n", shm->stats.fd_oracle_anomalies);

	if (shm->stats.mmap_oracle_anomalies)
		output(0, "mmap oracle anomalies: %lu\n", shm->stats.mmap_oracle_anomalies);

	if (shm->stats.cred_oracle_anomalies)
		output(0, "cred oracle anomalies: %lu\n", shm->stats.cred_oracle_anomalies);

	if (shm->stats.procfs_writes || shm->stats.sysfs_writes ||
	    shm->stats.debugfs_writes) {
		output(0, "\nprocfs/sysfs writes: proc:%lu sys:%lu debugfs:%lu\n",
			shm->stats.procfs_writes,
			shm->stats.sysfs_writes,
			shm->stats.debugfs_writes);
	}

	if (shm->stats.memory_pressure_runs)
		output(0, "memory pressure runs (MADV_PAGEOUT+refault): %lu\n",
			shm->stats.memory_pressure_runs);

	if (shm->stats.sched_cycler_runs)
		output(0, "sched_cycler: runs:%lu eperm:%lu\n",
			shm->stats.sched_cycler_runs,
			shm->stats.sched_cycler_eperm);

	if (shm->stats.userns_runs)
		output(0, "userns_fuzzer: runs:%lu inner_crashed:%lu unsupported:%lu\n",
			shm->stats.userns_runs,
			shm->stats.userns_inner_crashed,
			shm->stats.userns_unsupported);

	if (shm->stats.barrier_racer_runs)
		output(0, "barrier racer: %lu runs, %lu inner workers crashed\n",
			shm->stats.barrier_racer_runs,
			shm->stats.barrier_racer_inner_crashed);

	if (shm->stats.genetlink_families_discovered ||
	    shm->stats.genetlink_msgs_sent) {
		output(0, "\ngenetlink fuzzer: families_discovered:%lu (cumulative across children) msgs_sent:%lu eperm:%lu\n",
			shm->stats.genetlink_families_discovered,
			shm->stats.genetlink_msgs_sent,
			shm->stats.genetlink_eperm);
	}

	if (shm->stats.netlink_nested_attrs_emitted)
		output(0, "netlink generator: NLA_F_NESTED containers emitted:%lu\n",
			shm->stats.netlink_nested_attrs_emitted);

	if (shm->stats.perf_chains_runs) {
		output(0, "\nperf event chains: runs:%lu groups_created:%lu ioctl_ops:%lu\n",
			shm->stats.perf_chains_runs,
			shm->stats.perf_chains_groups_created,
			shm->stats.perf_chains_ioctl_ops);
	}

	if (shm->stats.tracefs_kprobe_writes || shm->stats.tracefs_uprobe_writes ||
	    shm->stats.tracefs_filter_writes || shm->stats.tracefs_event_enable_writes ||
	    shm->stats.tracefs_misc_writes) {
		output(0, "\ntracefs fuzzer: kprobe:%lu uprobe:%lu filter:%lu event_enable:%lu misc:%lu\n",
			shm->stats.tracefs_kprobe_writes,
			shm->stats.tracefs_uprobe_writes,
			shm->stats.tracefs_filter_writes,
			shm->stats.tracefs_event_enable_writes,
			shm->stats.tracefs_misc_writes);
	}

	if (shm->stats.bpf_lifecycle_runs) {
		output(0, "\nbpf lifecycle: runs:%lu progs_loaded:%lu attached:%lu triggered:%lu verifier_rejects:%lu attach_failed:%lu eperm:%lu\n",
			shm->stats.bpf_lifecycle_runs,
			shm->stats.bpf_lifecycle_progs_loaded,
			shm->stats.bpf_lifecycle_attached,
			shm->stats.bpf_lifecycle_triggered,
			shm->stats.bpf_lifecycle_verifier_rejects,
			shm->stats.bpf_lifecycle_attach_failed,
			shm->stats.bpf_lifecycle_eperm);
	}

	if (shm->stats.bpf_maps_provided || shm->stats.bpf_progs_provided) {
		output(0, "bpf fd provider: maps_provided:%lu progs_provided:%lu\n",
			shm->stats.bpf_maps_provided,
			shm->stats.bpf_progs_provided);
	}

	if (shm->stats.recipe_runs) {
		output(0, "\nrecipe runner: runs:%lu completed:%lu partial:%lu unsupported:%lu\n",
			shm->stats.recipe_runs,
			shm->stats.recipe_completed,
			shm->stats.recipe_partial,
			shm->stats.recipe_unsupported);
		recipe_runner_dump_stats();
	}

	if (shm->stats.iouring_recipes_runs) {
		output(0, "\nio_uring recipes: runs:%lu completed:%lu partial:%lu enosys:%lu\n",
			shm->stats.iouring_recipes_runs,
			shm->stats.iouring_recipes_completed,
			shm->stats.iouring_recipes_partial,
			shm->stats.iouring_recipes_enosys);
		iouring_recipes_dump_stats();
	}

	if (shm->stats.zombies_reaped || shm->stats.zombies_timed_out ||
	    shm->stats.zombie_slots_pending) {
		output(0, "\nzombie slots: pending:%lu reaped:%lu timed-out:%lu\n",
			shm->stats.zombie_slots_pending,
			shm->stats.zombies_reaped,
			shm->stats.zombies_timed_out);
	}

	if (shm->stats.local_op_count_corrupted) {
		output(0, "\nlocal_op_count corruption events: %lu\n",
			shm->stats.local_op_count_corrupted);
	}

	if (shm->stats.fd_event_ring_corrupted)
		output(0, "\nfd_event_ring non-canonical pointer events: %lu\n",
			shm->stats.fd_event_ring_corrupted);

	if (shm->stats.fd_event_ring_overwritten)
		output(0, "\nfd_event_ring canary mismatch events: %lu\n",
			shm->stats.fd_event_ring_overwritten);

	if (shm->stats.refcount_audit_runs)
		output(0, "\nrefcount audit: runs:%lu fd-anomalies:%lu mmap-anomalies:%lu sock-anomalies:%lu\n",
			shm->stats.refcount_audit_runs,
			shm->stats.refcount_audit_fd_anomalies,
			shm->stats.refcount_audit_mmap_anomalies,
			shm->stats.refcount_audit_sock_anomalies);

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
		output(0, "\nKCOV coverage: %lu unique edges, %lu total PCs, %lu calls (%lu remote)\n",
			kc_edges, kc_pcs, kc_calls, kc_remote);

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

	if (cmp_hints_shm != NULL) {
		unsigned int total_hints = 0, syscalls_with_hints = 0;

		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			if (cmp_hints_shm->pools[i].count > 0) {
				total_hints += cmp_hints_shm->pools[i].count;
				syscalls_with_hints++;
			}
		}
		output(0, "CMP hints: %u values across %u syscalls\n",
			total_hints, syscalls_with_hints);
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

		output(0, "\nEdge-pair coverage: %lu unique pairs, %lu total pair-calls\n",
			edgepair_shm->pairs_tracked,
			edgepair_shm->total_pair_calls);

		if (edgepair_shm->pairs_dropped > 0)
			output(0, "Edge-pair table overflow: %lu inserts dropped (consider growing EDGEPAIR_TABLE_SIZE)\n",
				edgepair_shm->pairs_dropped);

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
			output(0, "Cold pairs (saturated sequences): %u\n", cold_pairs);

		edgepair_dump_to_file("edgepair.dump");
	}
}
